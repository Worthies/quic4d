import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dart_quic/src/tls/finished.dart';
import 'package:dart_quic/src/tls/key_schedule.dart';
import 'package:test/test.dart';

/// Golden test against RFC 8448 §3's server Finished computation.
///
/// The RFC's compact trace shows two separate steps under "calculate
/// finished": (1) finished_key = HKDF-Expand-Label(BaseKey, "finished",
/// "", 32) — labeled "hash (0 octets): (empty)" because this step's
/// HKDF context is empty by construction (RFC 8446 §4.4.4: finished_key
/// depends only on the traffic secret, never on the transcript) — and
/// (2) verify_data = HMAC(finished_key, Transcript-Hash(...)), whose
/// result is the "finished" value. Only the finished_key derivation
/// itself is independently checkable against this compact trace (the
/// full HMAC step needs the exact transcript-hash-through-
/// CertificateVerify value, which the trace doesn't print in isolation
/// here); [computeFinishedVerifyData]'s HMAC half is still exercised
/// (with a synthetic transcript hash, checked against a directly
/// computed HMAC-SHA256) to confirm it wires the two pieces together
/// correctly.
void main() {
  test('deriveFinishedKey reproduces the RFC\'s server finished_key', () async {
    final serverHsTrafficSecret = _hex(
      'b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 '
      'e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38',
    );

    final finishedKey = await deriveFinishedKey(serverHsTrafficSecret);

    expect(
      finishedKey,
      _hex(
        '00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f '
        'c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8',
      ),
    );
  });

  test('computeFinishedVerifyData = HMAC(finished_key, transcript hash)',
      () async {
    // Not an RFC-sourced vector (the RFC doesn't isolate this exact
    // intermediate) -- this is a self-consistency test that
    // computeFinishedVerifyData actually calls deriveFinishedKey and
    // then HMACs the given hash, rather than e.g. silently swapping
    // the argument order or forgetting one of the two steps. The
    // expected value is computed directly via HMAC-SHA256, independent
    // of finished.dart's own internals.
    final secret = Uint8List.fromList(List.generate(32, (i) => i));
    final transcriptHash = Uint8List.fromList(List.generate(32, (i) => 31 - i));

    final finishedKey = await deriveFinishedKey(secret);
    final expectedMac = await Hmac.sha256().calculateMac(
      transcriptHash,
      secretKey: SecretKey(finishedKey),
    );

    final actual = await computeFinishedVerifyData(
      handshakeTrafficSecret: secret,
      transcriptHash: transcriptHash,
    );

    expect(actual, Uint8List.fromList(expectedMac.bytes));
  });

  group('verifyDataMatches', () {
    test('returns true for identical byte sequences', () {
      final a = Uint8List.fromList([1, 2, 3, 4]);
      final b = Uint8List.fromList([1, 2, 3, 4]);
      expect(verifyDataMatches(a, b), isTrue);
    });

    test('returns false for a single differing byte', () {
      final a = Uint8List.fromList([1, 2, 3, 4]);
      final b = Uint8List.fromList([1, 2, 3, 5]);
      expect(verifyDataMatches(a, b), isFalse);
    });

    test('returns false for different lengths', () {
      final a = Uint8List.fromList([1, 2, 3]);
      final b = Uint8List.fromList([1, 2, 3, 4]);
      expect(verifyDataMatches(a, b), isFalse);
    });
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
