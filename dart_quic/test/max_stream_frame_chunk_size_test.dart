import 'package:dart_quic/src/connection.dart';
import 'package:test/test.dart';

/// Regression coverage for kMaxStreamFrameChunkSize's own safety bound
/// -- see that constant's doc comment for the full incident this
/// guards against: raising it past a value the actual network path
/// tolerates causes every maximally-sized STREAM-frame packet to be
/// silently dropped by a real-world tunneled path (VPN, corporate
/// proxy, nested tunnel) with a smaller MTU than Ethernet's typical
/// 1500 bytes -- observed live as Remote VNC Forwarding's own low-
/// bandwidth mode (which produces the largest, most tightly-packed
/// chunks, since ZRLE hands one whole compressed frame to a single
/// write() call this constant then slices maximally) going from
/// "connects" to "connects, then hangs forever" the moment this
/// constant was raised above what one such real VPN path's own actual
/// MTU allowed.
///
/// This test can't reproduce the network-drop behavior itself (that
/// needs a real constrained-MTU path, which integration tests in this
/// package already exercise against a real quic-go server over
/// loopback -- no MTU constraint there to trigger it), but it DOES
/// pin the specific numeric safety property that incident's root cause
/// violated, so a future change that raises this constant again
/// without re-deriving that safety margin fails loudly here instead of
/// only in a user's own real-world VPN environment.
void main() {
  group('kMaxStreamFrameChunkSize', () {
    test(
        'stays at or below kMinimumInitialDatagramSize minus a safety '
        'margin for packet overhead (short header + STREAM frame '
        'varints + AEAD tag) -- the ONE path-MTU floor RFC 9000 '
        'SS14.1 obligates every compliant QUIC path to support '
        'without any PMTU discovery/negotiation, unlike any larger '
        'value, which this library has no way to confirm a given path '
        'actually tolerates (it implements no Path MTU Discovery)',
        () {
      // Conservative worst-case packet overhead this library's own
      // packet/frame encoding can add on top of a STREAM frame's own
      // chunk payload: ~10 bytes short header (1 first byte + 8-byte
      // DCID + up to 4-byte packet number, though a DCID longer than
      // 8 bytes is possible in principle), ~10 bytes STREAM frame
      // varints (type/streamId/offset/length, worst case once offsets
      // grow past 2^14), 16 bytes AEAD tag.
      const worstCaseOverhead = 10 + 10 + 16;
      expect(
        kMaxStreamFrameChunkSize + worstCaseOverhead,
        lessThanOrEqualTo(kMinimumInitialDatagramSize),
        reason:
            'kMaxStreamFrameChunkSize plus this library\'s own worst-case '
            'per-packet overhead must not exceed kMinimumInitialDatagramSize '
            '(1200 bytes) -- the only datagram size RFC 9000 SS14.1 '
            'guarantees every compliant QUIC path supports without PMTU '
            'discovery. A larger value may work on many paths (Ethernet\'s '
            'typical 1500-byte MTU) but silently fails on others (VPNs, '
            'corporate proxies, nested tunnels commonly sit well under '
            '1400 bytes) with packets simply vanishing into the network, '
            'not a clean error -- see this constant\'s own doc comment for '
            'the real regression this specific bound guards against.',
      );
    });
  });
}
