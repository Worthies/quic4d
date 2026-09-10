# dart_quic — design

## Why this exists

`quic4d` (this repo, `main` branch) wraps Quinn (Rust) via
`flutter_rust_bridge` FFI. In production on commander this has shown two
concrete failure modes:

- **HarmonyOS**: cold start with the Rust runtime + FFI bridge init takes
  ~1 minute before the first `connect()` can even be attempted.
- **Ubuntu (Linux desktop)**: the FRB-spawned Tokio driver task pins a CPU
  core at 100% for the connection's entire lifetime, independent of
  traffic volume.

Both look like FFI/runtime-bridging pathology, not a QUIC protocol
problem, and neither is practical to root-cause through three additional
layers (Dart → FRB glue → Tokio → Quinn) we don't own. `dart_quic` avoids
the whole stack: pure Dart, `dart:io` `RawDatagramSocket` for UDP, no
FFI, no bundled native library, no separate build step per platform.

## Scope: what this is (and is not)

This is **not** a general-purpose QUIC v1 stack, and it does not aim for
one. It is scoped tightly to what commander's transport
(`commander/lib/client/quic_client.dart`, `agents/quic_conn.go`,
`server/quic_visitor.go`) actually uses:

In scope:
- QUIC v1 (RFC 9000) client role only. No server role.
- TLS 1.3 handshake per RFC 9001, **client-cert (mTLS) required** —
  commander's whole security model is mutual auth, there is no anonymous
  path.
- ALPN fixed to `"leaf-commander"` (matches `quicNextProto` in
  `agents/quic_conn.go` and `server/quic_visitor.go`).
- Exactly one client-initiated bidirectional stream per connection,
  opened immediately after the handshake completes, held open for the
  connection's lifetime. This is the entire stream model commander uses
  — no unidirectional streams, no server-initiated streams, no more than
  one stream at a time.
- Newline-delimited JSON application framing on that one stream (framing
  itself is application-layer, not this library's concern, but the
  library must not reorder/duplicate/corrupt bytes within the stream).
- The one non-STREAM behavior commander depends on: writing a
  literal `{"type":"_quic_hello"}\n` "handshake frame" as the first bytes
  on the stream so the server's `AcceptStream` unblocks (a QUIC stream
  is only observable to the peer once a STREAM frame carries data) —
  this is application behavior the *caller* does, not something this
  library needs to special-case, but it constrains the library: opening
  a stream and writing to it must work before any data has arrived from
  the peer.
- Idle/keepalive handling compatible with the peer's config
  (`MaxIdleTimeout: 30s`, `KeepAlivePeriod: 10s` in both
  `agents/quic_conn.go` and `server/quic_visitor.go`) — PING frames on a
  timer, idle timeout detection.
- Loss detection and congestion control: a **simplified, correct-but-
  unsophisticated** implementation (RFC 9002's PTO-based loss detection,
  a basic New Reno-style congestion controller). Commander's is a
  low-bandwidth chat/control link (JSON messages, occasional file
  chunks), not a throughput-sensitive bulk transfer — CUBIC-level
  sophistication is explicitly not a goal.

Explicitly out of scope (do not build unless a real commander need
appears):
- QUIC server role.
- 0-RTT / session resumption.
- Connection migration, NAT rebinding, path validation beyond initial
  handshake's implicit validation.
- Multiple concurrent streams, unidirectional streams, stream
  prioritization.
- QUIC datagrams (RFC 9221).
- HTTP/3, WebTransport — this is a raw QUIC transport client, not an H3
  stack.
- Version negotiation / multiple QUIC versions — v1 only, and if the
  server's first flight isn't v1 this library just fails rather than
  negotiating.
- Preferred congestion control tuning, pacing, ECN.
- 0-length connection ID omission edge cases beyond what the handshake
  needs — implement the subset RFC 9000 requires, not every optional
  variant.

If commander's needs grow (e.g. a second stream), extend then — this
document's scope is a snapshot of "what makes commander's QUIC fast-path
work," not a spec-completeness target.

## Interop targets (ground truth for every "does it work" question)

Two independent existing implementations already speak the exact wire
protocol this must interop with — use them as executable specs, not RFC
text alone:

1. **Server**: `server/quic_visitor.go` (leaf repo) — `quic-go` v0.61.0.
   Accepts our connection, requires client cert, expects the ALPN and
   handshake-frame behavior above.
2. **Reference client**: `agents/quic_conn.go` (leaf repo) — also
   `quic-go`, the Go agent's own QUIC fast path. Same wire contract from
   the client side; useful to diff behavior against when something looks
   wrong (if quic-go's client method X does *not* need workaround Y, and
   dart_quic seems to, the bug is probably in dart_quic).

Every milestone below that touches the wire must be verified against a
live `quic-go` server (spin up `server/quic_visitor.go`'s `acceptQUIC`
in a test harness, or a minimal quic-go listener mirroring its TLS/ALPN
config) — unit tests against RFC test vectors alone are necessary but
not sufficient; quic-go's actual behavior (e.g. exact CONNECTION_CLOSE
timing on a rejected client cert, observed empirically per
`quic_conn.go`'s own comments) is the real acceptance bar.

## Architecture

```
lib/
  dart_quic.dart              # public API surface
  src/
    varint.dart                # RFC 9000 §16 variable-length integers
    packet/
      header.dart               # long/short header parsing+encoding
      protection.dart            # RFC 9001 header/packet protection (AEAD)
      number_space.dart          # per-space packet number tracking
    frame/
      frame.dart                  # sealed Frame type + encode/decode
      (one file per frame family: crypto, stream, ack, close, ping, ...)
    tls/
      handshake.dart              # TLS 1.3 client state machine
      transcript.dart             # handshake transcript hash
      key_schedule.dart           # HKDF-Expand-Label / traffic secrets
      transport_parameters.dart   # QUIC TP extension (RFC 9001 §8.2)
      certificate.dart            # mTLS: client cert chain + CertVerify
    recovery/
      loss_detection.dart         # RFC 9002 PTO/loss timers
      congestion.dart              # simplified New-Reno-ish controller
    connection.dart               # top-level state machine, owns socket
    stream.dart                   # QuicStream (send+recv split, like quic4d)
    endpoint.dart                 # QuicEndpoint: owns RawDatagramSocket
```

Concurrency model: a single `Connection` owns one `RawDatagramSocket`
and runs an internal event loop (`async*`/`Stream`-driven, no isolates
initially — revisit only if profiling shows the crypto ops blocking the
event loop matters at commander's message rates). Public API is
`Future`-based, mirroring quic4d's shape so `commander/lib/client/
quic_client.dart` needs minimal changes to switch implementations:

```dart
class QuicEndpoint { static Future<QuicEndpoint> createClientWithCert({...}); }
class QuicConnection { Future<QuicStream> openBidirectionalStream(); }
class QuicStream { Future<void> write(Uint8List); Stream<Uint8List> get incoming; Future<void> finish(); }
```

(Exact shape finalized in milestone 5 — see plan — once the low-level
pieces exist and real usage patterns from `quic_client.dart` are ported
over.)

## Crypto building blocks

No existing pure-Dart QUIC or TLS 1.3 stack was found production-ready
(see the research below) — implement TLS 1.3 client handshake logic
directly on top of primitive crypto libraries rather than a full TLS
library:

- **`package:cryptography`** (2.9.0) — AES-GCM, ChaCha20-Poly1305,
  X25519, Ed25519, HKDF, SHA-256/384. Covers the AEAD + key-derivation
  needs of both TLS 1.3 key schedule and QUIC packet protection.
- **`package:pointycastle`** (4.0.0) — ASN.1/X.509 parsing, RSA/ECDSA
  signature verification, PKCS#8 private key parsing. Needed for: parsing
  the CA root and peer certificate chain, verifying the server's
  CertificateVerify signature, and signing our own CertificateVerify with
  the client's private key (mTLS).
- **`package:basic_utils`** — X.509/PEM helpers on top of pointycastle;
  used for convenience (PEM→DER, extracting SPKI) rather than
  reimplementing ASN.1 parsing by hand.

Header protection and packet protection (RFC 9001 §5) are implemented
directly against `cryptography`'s AEAD ciphers plus a hand-rolled
AES-ECB/ChaCha20-mask step for the header-protection sample (RFC 9001
§5.4 — this part has no standard library shortcut in any Dart crypto
package found).

## Prior art considered

Searched pub.dev and GitHub for existing pure-Dart QUIC implementations
before deciding to build this:

- `jxoesneon/quic_lib` — pub.dev/GitHub, "pure-Dart QUIC, HTTP/3,
  WebTransport, libp2p transport stack." 0 GitHub stars, repo created
  2026-06, still under active early development. Reviewed structure;
  not something to build on top of yet (unclear correctness, no
  significant usage), but referenced for API-shape ideas only, no code
  reused.
- `KellyKinyama/pure-dart-quic` — 7 stars, created 2026-04, appears to
  be a learning/reference project rather than a maintained library.
- `pub.dev` package `quic` — abandoned, `0.1.0-dev.0` from 2020, no API
  surface at all beyond a placeholder.

Conclusion: no viable dependency exists; building from RFC 9000/9001/
9002 plus the two existing quic-go peers (`agents/quic_conn.go`,
`server/quic_visitor.go`) as executable specs is the only realistic
path.

## Testing strategy

- **Unit, RFC test vectors**: RFC 9001 Appendix A gives full worked
  Initial-packet protection test vectors (client Initial, including the
  exact derived keys, header-protected bytes, and final wire bytes) —
  use these directly as golden tests for `packet/protection.dart` and
  `tls/key_schedule.dart` before ever touching a real socket.
- **Unit, frame round-trip**: every frame type gets encode(decode(x)) ==
  x property tests plus known-bad-input tests (truncated varint, etc).
- **Integration, live quic-go server**: a test harness in
  `test/integration/` spins up a minimal quic-go listener (same TLS/ALPN
  config as `server/quic_visitor.go`, using this repo's existing test
  certs generation, e.g. `leaf/generate_all_certs.sh`) and drives a full
  handshake + stream open + write + read cycle from dart_quic. This is
  the real acceptance gate for every milestone from TLS handshake
  onward.
- **Interop smoke test against leaf itself**: once milestone 5 lands,
  wire dart_quic into a throwaway copy of `quic_client.dart` and test
  against a real `server/quic_visitor.go` instance end-to-end (manual,
  not CI, given it needs the full leaf server stack).

## Milestones (see `plan` tool / PR sequence)

1. Varint codec + RFC 9001 Appendix A Initial packet protection
   (encrypt+decrypt a known client Initial packet byte-for-byte).
2. Frame encode/decode for the frame set actually used: PADDING, PING,
   ACK, CRYPTO, STREAM, RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE,
   HANDSHAKE_DONE, NEW_CONNECTION_ID (peer may send it even if unused),
   NEW_TOKEN (may arrive, must be ignored gracefully).
3. TLS 1.3 client handshake state machine: ClientHello → process
   ServerHello/EncryptedExtensions/Certificate/CertificateVerify/
   Finished → send client Certificate+CertificateVerify+Finished (mTLS)
   → derive 1-RTT keys. Includes the QUIC transport parameters
   extension (RFC 9001 §8.2).
4. Connection state machine: UDP send/recv loop, packet number spaces
   (Initial/Handshake/1-RTT), key phase transitions, RFC 9002 loss
   detection (PTO) and a minimal congestion controller, idle timeout +
   PING keepalive.
5. Public API (`QuicEndpoint`/`QuicConnection`/`QuicStream`) shaped to
   match quic4d's surface closely enough that `quic_client.dart` needs
   only an import swap + minor call-site adjustments; live interop test
   against `server/quic_visitor.go`.
