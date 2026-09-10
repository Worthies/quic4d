import 'dart:typed_data';

import 'package:dart_quic/src/tls/hkdf_label.dart';
import 'package:dart_quic/src/tls/key_schedule.dart';
import 'package:test/test.dart';

/// Golden tests against RFC 8448 §3's "Simple 1-RTT Handshake" worked
/// example — every secret in the early/handshake/master chain is
/// reproduced byte-for-byte using the RFC's own DHE shared secret and
/// transcript hashes (copied directly from the trace, not derived by
/// this test, so a failure here means the key-schedule code is wrong,
/// not that the fixture is wrong).
void main() {
  // RFC 8448 §3's client + server ephemeral X25519 key exchange result:
  // this exact 32-byte value is what a correct X25519(client_private,
  // server_public) computation produces, and is given directly in the
  // trace as the Handshake Secret's IKM.
  final dheSharedSecret = _hex(
    '8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d '
    '35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d',
  );

  // Transcript-Hash(ClientHello, ServerHello) from the trace: the
  // "hash" field shown alongside the "tls13 c/s hs traffic" derivations.
  final transcriptHashUpToServerHello = _hex(
    '86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed '
    'd6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8',
  );

  // SHA-256("") — the empty transcript hash used for the two "derived"
  // intermediate secrets (Transcript-Hash of zero messages).
  final emptyTranscriptHash = _hex(
    'e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 '
    '27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55',
  );

  test('hkdfExtract(0, 0) reproduces the RFC\'s Early Secret', () async {
    final earlySecret =
        await hkdfExtract(salt: zeroFilled32, ikm: zeroFilled32);
    expect(
      earlySecret,
      _hex(
        '33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 '
        '10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a',
      ),
    );
  });

  test('deriveHandshakeSecrets reproduces every secret in the RFC trace',
      () async {
    final secrets = await deriveHandshakeSecrets(
      dheSharedSecret: dheSharedSecret,
      transcriptHashUpToServerHello: transcriptHashUpToServerHello,
      emptyTranscriptHash: emptyTranscriptHash,
    );

    expect(
      secrets.earlySecret,
      _hex(
        '33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 '
        '10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a',
      ),
      reason: 'early secret',
    );

    expect(
      secrets.handshakeSecret,
      _hex(
        '1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 '
        '04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac',
      ),
      reason: 'handshake secret',
    );

    expect(
      secrets.clientHandshakeTrafficSecret,
      _hex(
        'b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f '
        '3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21',
      ),
      reason: 'client handshake traffic secret',
    );

    expect(
      secrets.serverHandshakeTrafficSecret,
      _hex(
        'b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 '
        'e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38',
      ),
      reason: 'server handshake traffic secret',
    );

    expect(
      secrets.masterSecret,
      _hex(
        '18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a '
        '47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19',
      ),
      reason: 'master secret',
    );
  });

  test('master secret extraction reproduces the RFC\'s "master" secret',
      () async {
    // The RFC labels two different 32-byte values "secret" in quick
    // succession: the "derived" secret used as Extract's salt, and the
    // resulting extracted Master Secret. deriveHandshakeSecrets above
    // already asserts the salt; this asserts the final extracted value
    // by re-deriving it and comparing to the RFC's actual Master Secret
    // line under "{server} extract secret \"master\"".
    final secrets = await deriveHandshakeSecrets(
      dheSharedSecret: dheSharedSecret,
      transcriptHashUpToServerHello: transcriptHashUpToServerHello,
      emptyTranscriptHash: emptyTranscriptHash,
    );
    // RFC 8448 §3 gives the derived-for-master secret separately from
    // the final master secret; recompute Extract(derivedForMaster, 0)
    // here to confirm it equals the documented master secret.
    final derivedForMaster = await deriveSecret(
      secret: secrets.handshakeSecret,
      label: 'derived',
      transcriptHash: emptyTranscriptHash,
    );
    expect(
      derivedForMaster,
      _hex(
        '43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 '
        '31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4',
      ),
    );

    final masterSecret =
        await hkdfExtract(salt: derivedForMaster, ikm: zeroFilled32);
    expect(
      masterSecret,
      _hex(
        '18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a '
        '47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19',
      ),
    );
    expect(secrets.masterSecret, masterSecret);
  });
}

Uint8List _hex(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  final bytes = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}
