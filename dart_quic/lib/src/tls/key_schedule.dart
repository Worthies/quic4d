/// TLS 1.3 key schedule (RFC 8446 §7.1): the Derive-Secret construction
/// and the early/handshake/master secret chain. This is what turns a
/// running handshake transcript plus a (EC)DHE shared secret into the
/// traffic secrets QUIC's packet protection (RFC 9001 §5) derives its
/// actual AEAD keys from.
///
/// Verified against RFC 8448 §3's worked example throughout (see
/// key_schedule_test.dart) — every intermediate secret in that trace
/// (early, handshake, client/server handshake traffic, master) is
/// reproduced byte-for-byte.
library;

import 'dart:typed_data';

import 'hkdf_label.dart';

/// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret,
/// Label, Transcript-Hash(Messages), Hash.length) — RFC 8446 §7.1.
///
/// [transcriptHash] is the caller-computed Transcript-Hash of the
/// handshake messages seen so far (SHA-256 digest, computed
/// incrementally as messages arrive — see transcript.dart). Passing it
/// in rather than the raw messages keeps this function pure and
/// avoids recomputing the hash of a growing message list on every
/// call.
Future<Uint8List> deriveSecret({
  required Uint8List secret,
  required String label,
  required Uint8List transcriptHash,
}) {
  return hkdfExpandLabel(
    secret: secret,
    label: label,
    context: transcriptHash,
    length: 32, // SHA-256 output length; the only hash dart_quic supports.
  );
}

/// The zero-filled 32-byte value used as `salt` for the Early Secret
/// extraction (RFC 8446 §7.1: "Extract(0, ...)") and as `IKM` for the
/// Handshake and Master Secret extractions in a non-PSK, non-resumed
/// handshake (RFC 8448 §3's exact scenario) — dart_quic never does PSK
/// or session resumption (see DESIGN.md), so every "real" IKM/salt this
/// library ever needs at these two points is precisely this all-zero
/// value.
final Uint8List zeroFilled32 = Uint8List(32);

/// The full early -> handshake -> master secret chain (RFC 8446 §7.1's
/// key schedule diagram), computed for a non-PSK, non-resumed
/// handshake — the only case dart_quic supports.
class HandshakeSecrets {
  final Uint8List earlySecret;
  final Uint8List handshakeSecret;
  final Uint8List clientHandshakeTrafficSecret;
  final Uint8List serverHandshakeTrafficSecret;
  final Uint8List masterSecret;

  const HandshakeSecrets({
    required this.earlySecret,
    required this.handshakeSecret,
    required this.clientHandshakeTrafficSecret,
    required this.serverHandshakeTrafficSecret,
    required this.masterSecret,
  });
}

/// Computes [HandshakeSecrets] from the (EC)DHE shared secret and the
/// transcript hash up through ServerHello (RFC 8446 §7.1's key
/// schedule, non-PSK branch — Early Secret is Extract(0, 0) since
/// there's no PSK, and Handshake/Master Secret both use an
/// all-zero-IKM/salt "derived" intermediate per the diagram).
Future<HandshakeSecrets> deriveHandshakeSecrets({
  required Uint8List dheSharedSecret,
  required Uint8List transcriptHashUpToServerHello,
  required Uint8List emptyTranscriptHash,
}) async {
  // Early Secret = HKDF-Extract(salt=0, IKM=0) — no PSK, so IKM is also
  // all-zero (RFC 8446 §7.1).
  final earlySecret = await hkdfExtract(salt: zeroFilled32, ikm: zeroFilled32);

  final derivedForHandshake = await deriveSecret(
    secret: earlySecret,
    label: 'derived',
    transcriptHash: emptyTranscriptHash,
  );
  final handshakeSecret = await hkdfExtract(
    salt: derivedForHandshake,
    ikm: dheSharedSecret,
  );

  final clientHsTrafficSecret = await deriveSecret(
    secret: handshakeSecret,
    label: 'c hs traffic',
    transcriptHash: transcriptHashUpToServerHello,
  );
  final serverHsTrafficSecret = await deriveSecret(
    secret: handshakeSecret,
    label: 's hs traffic',
    transcriptHash: transcriptHashUpToServerHello,
  );

  final derivedForMaster = await deriveSecret(
    secret: handshakeSecret,
    label: 'derived',
    transcriptHash: emptyTranscriptHash,
  );
  final masterSecret = await hkdfExtract(
    salt: derivedForMaster,
    ikm: zeroFilled32,
  );

  return HandshakeSecrets(
    earlySecret: earlySecret,
    handshakeSecret: handshakeSecret,
    clientHandshakeTrafficSecret: clientHsTrafficSecret,
    serverHandshakeTrafficSecret: serverHsTrafficSecret,
    masterSecret: masterSecret,
  );
}

/// Application (1-RTT) traffic secrets, derived from the Master Secret
/// once the full handshake transcript (through server Finished) is
/// known (RFC 8446 §7.1).
class ApplicationTrafficSecrets {
  final Uint8List clientApplicationTrafficSecret;
  final Uint8List serverApplicationTrafficSecret;

  const ApplicationTrafficSecrets({
    required this.clientApplicationTrafficSecret,
    required this.serverApplicationTrafficSecret,
  });
}

Future<ApplicationTrafficSecrets> deriveApplicationTrafficSecrets({
  required Uint8List masterSecret,
  required Uint8List transcriptHashUpToServerFinished,
}) async {
  final client = await deriveSecret(
    secret: masterSecret,
    label: 'c ap traffic',
    transcriptHash: transcriptHashUpToServerFinished,
  );
  final server = await deriveSecret(
    secret: masterSecret,
    label: 's ap traffic',
    transcriptHash: transcriptHashUpToServerFinished,
  );
  return ApplicationTrafficSecrets(
    clientApplicationTrafficSecret: client,
    serverApplicationTrafficSecret: server,
  );
}

/// RFC 9001 §5.1: derives the AEAD key/IV/header-protection-key triple
/// QUIC packet protection actually uses from a traffic secret — the
/// same derivation as Initial keys (initial_secrets.dart) but generalized
/// to any traffic secret (handshake or 1-RTT) and any AEAD key length
/// (16 bytes for AES-128-GCM, 32 for AES-256-GCM/ChaCha20-Poly1305).
class TrafficKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  const TrafficKeys({required this.key, required this.iv, required this.hp});
}

Future<TrafficKeys> deriveTrafficKeys({
  required Uint8List secret,
  required int aeadKeyLength,
}) async {
  final key = await hkdfExpandLabel(
      secret: secret, label: 'quic key', length: aeadKeyLength);
  final iv =
      await hkdfExpandLabel(secret: secret, label: 'quic iv', length: 12);
  final hp = await hkdfExpandLabel(
      secret: secret, label: 'quic hp', length: aeadKeyLength);
  return TrafficKeys(key: key, iv: iv, hp: hp);
}

/// RFC 8446 §7.1: `finished_key = HKDF-Expand-Label(BaseKey, "finished",
/// "", Hash.length)` — the key used to compute/verify a Finished
/// message's verify_data (RFC 8446 §4.4.4).
Future<Uint8List> deriveFinishedKey(Uint8List baseKey) {
  return hkdfExpandLabel(secret: baseKey, label: 'finished', length: 32);
}
