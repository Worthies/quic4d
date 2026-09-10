import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/tls/certificate_verify_signature.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Round-trips dart_quic's own signing (used for the client's mTLS
/// CertificateVerify) through its own verification, and separately
/// through openssl, against the real key fixtures used elsewhere.
/// Confirms signWithEcdsaP256/signWithRsaPss don't just "look right" but
/// produce signatures an independent, real-world implementation (the
/// exact quic-go/OpenSSL stack this must interop with) accepts.
void main() {
  final fixturesDir = '${Directory.current.path}/test/fixtures';
  final message = File('$fixturesDir/msg.txt').readAsBytesSync();

  test('signWithEcdsaP256 output verifies with dart_quic\'s own verifier', () {
    final keyPem = File('$fixturesDir/ec.key').readAsStringSync();
    final certDer = File('$fixturesDir/ec.der').readAsBytesSync();
    final privateKey = CryptoUtils.ecPrivateKeyFromPem(keyPem);

    final signature =
        signWithEcdsaP256(privateKey: privateKey, content: message);

    expect(
      () => verifyCertificateSignature(
        leafCertificateDer: certDer,
        algorithm: SignatureScheme.ecdsaSecp256r1Sha256,
        signedContent: message,
        signature: signature,
      ),
      returnsNormally,
    );
  });

  test('signWithEcdsaP256 output verifies with openssl', () {
    final keyPem = File('$fixturesDir/ec.key').readAsStringSync();
    final privateKey = CryptoUtils.ecPrivateKeyFromPem(keyPem);
    final signature =
        signWithEcdsaP256(privateKey: privateKey, content: message);

    final sigFile = File('${Directory.systemTemp.path}/dart_quic_ec_sig.der')
      ..writeAsBytesSync(signature);
    final pubFile = File('${Directory.systemTemp.path}/dart_quic_ec_pub.pem');
    final extractPub = Process.runSync('openssl', [
      'x509',
      '-in',
      '$fixturesDir/ec.der',
      '-inform',
      'DER',
      '-pubkey',
      '-noout'
    ]);
    pubFile.writeAsStringSync(extractPub.stdout as String);

    final result = Process.runSync('openssl', [
      'dgst',
      '-sha256',
      '-verify',
      pubFile.path,
      '-signature',
      sigFile.path,
      '$fixturesDir/msg.txt',
    ]);

    expect(result.stdout.toString(), contains('Verified OK'));
  }, onPlatform: {'!linux && !mac-os': const Skip('requires openssl CLI')});

  test('signWithRsaPss output verifies with dart_quic\'s own verifier', () {
    final keyPem = File('$fixturesDir/rsa.key').readAsStringSync();
    final certDer = File('$fixturesDir/rsa.der').readAsBytesSync();
    final privateKey = CryptoUtils.rsaPrivateKeyFromPem(keyPem);

    final signature = signWithRsaPss(privateKey: privateKey, content: message);

    expect(
      () => verifyCertificateSignature(
        leafCertificateDer: certDer,
        algorithm: SignatureScheme.rsaPssRsaeSha256,
        signedContent: message,
        signature: signature,
      ),
      returnsNormally,
    );
  });

  test('signWithRsaPss output verifies with openssl', () {
    final keyPem = File('$fixturesDir/rsa.key').readAsStringSync();
    final privateKey = CryptoUtils.rsaPrivateKeyFromPem(keyPem);
    final signature = signWithRsaPss(privateKey: privateKey, content: message);

    final sigFile =
        File('${Directory.systemTemp.path}/dart_quic_rsa_pss_sig.der')
          ..writeAsBytesSync(signature);
    final pubFile = File('${Directory.systemTemp.path}/dart_quic_rsa_pub.pem');
    final extractPub = Process.runSync('openssl', [
      'x509',
      '-in',
      '$fixturesDir/rsa.der',
      '-inform',
      'DER',
      '-pubkey',
      '-noout',
    ]);
    pubFile.writeAsStringSync(extractPub.stdout as String);

    final result = Process.runSync('openssl', [
      'dgst',
      '-sha256',
      '-verify',
      pubFile.path,
      '-sigopt',
      'rsa_padding_mode:pss',
      '-sigopt',
      'rsa_pss_saltlen:-1',
      '-signature',
      sigFile.path,
      '$fixturesDir/msg.txt',
    ]);

    expect(result.stdout.toString(), contains('Verified OK'));
  }, onPlatform: {'!linux && !mac-os': const Skip('requires openssl CLI')});

  test('a signature over the wrong content is rejected', () {
    final keyPem = File('$fixturesDir/ec.key').readAsStringSync();
    final certDer = File('$fixturesDir/ec.der').readAsBytesSync();
    final privateKey = CryptoUtils.ecPrivateKeyFromPem(keyPem);

    final signature =
        signWithEcdsaP256(privateKey: privateKey, content: message);
    final wrongMessage = Uint8List.fromList([...message, 1]);

    expect(
      () => verifyCertificateSignature(
        leafCertificateDer: certDer,
        algorithm: SignatureScheme.ecdsaSecp256r1Sha256,
        signedContent: wrongMessage,
        signature: signature,
      ),
      throwsA(isA<SignatureVerificationException>()),
    );
  });
}
