import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/src/tls/certificate_verify_signature.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Verifies dart_quic's signature verification against real
/// openssl-generated certificates and signatures (test/fixtures/) --
/// an end-to-end check that ASN.1 parsing (extracting SubjectPublic
/// KeyInfo from a real X.509 cert) and each SignatureScheme's verifier
/// actually accept a signature a real-world TLS stack would produce
/// (openssl, and by extension anything using OpenSSL/BoringSSL/rustls
/// under the hood, including the quic-go server this must interop
/// with -- quic-go itself defers to Go's crypto/tls, which is
/// interoperable with the same X.509/PKCS1/PSS/ECDSA encodings).
///
/// Fixtures were generated with (see git history / DESIGN.md for the
/// exact commands):
///   openssl req -new -x509 -key `ec.key`  -out `ec.crt`  -days 30 ...
///   openssl req -new -x509 -key `rsa.key` -out `rsa.crt` -days 30 ...
///   openssl dgst -sha256 -sign KEY -out SIG.der msg.txt
///   openssl dgst -sha256 -sign KEY -sigopt rsa_padding_mode:pss \
///     -sigopt rsa_pss_saltlen:-1 -out rsa_pss_sig.der msg.txt
void main() {
  final fixturesDir = '${Directory.current.path}/test/fixtures';
  final message = File('$fixturesDir/msg.txt').readAsBytesSync();

  group('verifyCertificateSignature against real openssl certs', () {
    test('ECDSA P-256 / SHA-256 signature verifies', () {
      final cert = File('$fixturesDir/ec.der').readAsBytesSync();
      final signature = File('$fixturesDir/ec_sig.der').readAsBytesSync();

      expect(
        () => verifyCertificateSignature(
          leafCertificateDer: cert,
          algorithm: SignatureScheme.ecdsaSecp256r1Sha256,
          signedContent: message,
          signature: signature,
        ),
        returnsNormally,
      );
    });

    test('ECDSA verification rejects a tampered message', () {
      final cert = File('$fixturesDir/ec.der').readAsBytesSync();
      final signature = File('$fixturesDir/ec_sig.der').readAsBytesSync();
      final tampered = Uint8List.fromList([...message, 0x00]);

      expect(
        () => verifyCertificateSignature(
          leafCertificateDer: cert,
          algorithm: SignatureScheme.ecdsaSecp256r1Sha256,
          signedContent: tampered,
          signature: signature,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('RSA PKCS#1 v1.5 / SHA-256 signature verifies', () {
      final cert = File('$fixturesDir/rsa.der').readAsBytesSync();
      final signature =
          File('$fixturesDir/rsa_pkcs1_sig.der').readAsBytesSync();

      expect(
        () => verifyCertificateSignature(
          leafCertificateDer: cert,
          algorithm: SignatureScheme.rsaPkcs1Sha256,
          signedContent: message,
          signature: signature,
        ),
        returnsNormally,
      );
    });

    test('RSA-PSS / SHA-256 signature verifies', () {
      final cert = File('$fixturesDir/rsa.der').readAsBytesSync();
      final signature = File('$fixturesDir/rsa_pss_sig.der').readAsBytesSync();

      expect(
        () => verifyCertificateSignature(
          leafCertificateDer: cert,
          algorithm: SignatureScheme.rsaPssRsaeSha256,
          signedContent: message,
          signature: signature,
        ),
        returnsNormally,
      );
    });

    test('RSA-PSS verification rejects a corrupted signature', () {
      final cert = File('$fixturesDir/rsa.der').readAsBytesSync();
      final signature = Uint8List.fromList(
          File('$fixturesDir/rsa_pss_sig.der').readAsBytesSync());
      signature[0] ^= 0xFF;

      expect(
        () => verifyCertificateSignature(
          leafCertificateDer: cert,
          algorithm: SignatureScheme.rsaPssRsaeSha256,
          signedContent: message,
          signature: signature,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('an unsupported SignatureScheme is rejected explicitly', () {
      final cert = File('$fixturesDir/ec.der').readAsBytesSync();
      expect(
        () => verifyCertificateSignature(
          leafCertificateDer: cert,
          algorithm: 0xDEAD,
          signedContent: message,
          signature: Uint8List(0),
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });
  });

  group('extractSubjectPublicKeyInfo', () {
    test('extracts non-empty SPKI bytes from a v3 EC certificate', () {
      final cert = File('$fixturesDir/ec.der').readAsBytesSync();
      final spki = extractSubjectPublicKeyInfo(cert);
      expect(spki, isNotEmpty);
      // A DER SEQUENCE always starts with tag 0x30.
      expect(spki[0], 0x30);
    });

    test('extracts non-empty SPKI bytes from a v3 RSA certificate', () {
      final cert = File('$fixturesDir/rsa.der').readAsBytesSync();
      final spki = extractSubjectPublicKeyInfo(cert);
      expect(spki, isNotEmpty);
      expect(spki[0], 0x30);
    });
  });
}
