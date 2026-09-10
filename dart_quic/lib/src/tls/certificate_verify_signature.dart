/// RFC 8446 §4.4.3: verifies a CertificateVerify message's signature
/// against the leaf certificate's public key -- the step that actually
/// proves the peer possesses the private key for the certificate it
/// presented. Supports the SignatureScheme values dart_quic advertises
/// in signature_algorithms (extensions.dart's [SignatureScheme]):
/// ECDSA P-256, RSA-PSS, RSA PKCS#1 v1.5, and Ed25519.
///
/// [leafCertificateDer] is the first (end-entity) certificate from the
/// peer's Certificate message -- RFC 8446 §4.4.2 requires it come
/// first in certificate_list.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:pointycastle/asn1.dart' as pc;
import 'package:pointycastle/export.dart' as pc;

import 'extensions.dart';

class SignatureVerificationException implements Exception {
  final String message;
  const SignatureVerificationException(this.message);

  @override
  String toString() => 'SignatureVerificationException: $message';
}

/// Extracts the DER-encoded SubjectPublicKeyInfo from an X.509
/// certificate's DER bytes -- the piece
/// [CryptoUtils.ecPublicKeyFromDerBytes]/[CryptoUtils.rsaPublicKeyFromDERBytes]
/// expect, rather than the whole certificate.
Uint8List extractSubjectPublicKeyInfo(Uint8List certificateDer) {
  final parser = pc.ASN1Parser(certificateDer);
  final certSeq = parser.nextObject() as pc.ASN1Sequence;
  final tbsCertificate = certSeq.elements![0] as pc.ASN1Sequence;

  // TBSCertificate ::= SEQUENCE {
  //   version [0] EXPLICIT Version DEFAULT v1, -- context tag, optional
  //   serialNumber, signature, issuer, validity, subject,
  //   subjectPublicKeyInfo, ... }
  // The version field is an explicit context-tagged [0] wrapper only
  // present for v2/v3 certs (virtually all real certs, including
  // leaf/generate_all_certs.sh's openssl-generated ones, are v3) -- skip
  // it if its tag has the context-specific class bit set.
  var index = 0;
  final first = tbsCertificate.elements![0];
  if (first.tag != null && (first.tag! & 0xC0) == 0x80) {
    index = 1; // version present; serialNumber is the next element
  }

  // serialNumber(0/1), signature(1/2), issuer(2/3), validity(3/4),
  // subject(4/5), subjectPublicKeyInfo(5/6).
  final spkiSeq = tbsCertificate.elements![index + 5] as pc.ASN1Sequence;
  return spkiSeq.encodedBytes!;
}

/// Verifies [signature] (as carried in a CertificateVerify message)
/// over [signedContent] (the RFC 8446 §4.4.3 padded/contextualized
/// content -- see certificate_message.dart's
/// buildCertificateVerifyContent) using the leaf certificate's public
/// key and the negotiated [algorithm] (a [SignatureScheme] value).
///
/// Throws [SignatureVerificationException] if the signature is invalid
/// or the algorithm/key combination isn't supported -- callers MUST
/// treat either as a fatal handshake failure (RFC 8446 §4.4.3: "If the
/// verification fails, the receiver MUST terminate the handshake").
void verifyCertificateSignature({
  required Uint8List leafCertificateDer,
  required int algorithm,
  required Uint8List signedContent,
  required Uint8List signature,
}) {
  final spki = extractSubjectPublicKeyInfo(leafCertificateDer);

  switch (algorithm) {
    case SignatureScheme.ecdsaSecp256r1Sha256:
      _verifyEcdsa(spki, signedContent, signature);
    case SignatureScheme.rsaPssRsaeSha256:
      _verifyRsaPss(spki, signedContent, signature);
    case SignatureScheme.rsaPkcs1Sha256:
      _verifyRsaPkcs1(spki, signedContent, signature);
    default:
      throw SignatureVerificationException(
          'unsupported SignatureScheme 0x${algorithm.toRadixString(16)}');
  }
}

void _verifyEcdsa(
    Uint8List spki, Uint8List signedContent, Uint8List derSignature) {
  final publicKey = CryptoUtils.ecPublicKeyFromDerBytes(spki);
  final signer = pc.ECDSASigner(pc.SHA256Digest())
    ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(publicKey));

  final ecSignature = _decodeEcdsaDerSignature(derSignature);
  final valid = signer.verifySignature(signedContent, ecSignature);
  if (!valid) {
    throw const SignatureVerificationException(
        'ECDSA CertificateVerify signature is invalid');
  }
}

void _verifyRsaPss(
    Uint8List spki, Uint8List signedContent, Uint8List signature) {
  final publicKey = CryptoUtils.rsaPublicKeyFromDERBytes(spki);
  // RFC 8446 §4.2.3: "The length of the Salt MUST be equal to the
  // length of the output of the digest algorithm" -- 32 bytes for
  // SHA-256, matching openssl's `-sigopt rsa_pss_saltlen:-1`.
  final signer =
      pc.PSSSigner(pc.RSAEngine(), pc.SHA256Digest(), pc.SHA256Digest())
        ..init(
          false,
          pc.ParametersWithSaltConfiguration(
            pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey),
            // Only used by PSSSigner during *signing* (to draw a fresh
            // random salt) -- verification never calls into this, so an
            // unseeded instance is fine here.
            pc.FortunaRandom(),
            32,
          ),
        );
  final valid =
      signer.verifySignature(signedContent, pc.PSSSignature(signature));
  if (!valid) {
    throw const SignatureVerificationException(
        'RSA-PSS CertificateVerify signature is invalid');
  }
}

void _verifyRsaPkcs1(
    Uint8List spki, Uint8List signedContent, Uint8List signature) {
  final publicKey = CryptoUtils.rsaPublicKeyFromDERBytes(spki);
  final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
    ..init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey));
  final valid =
      signer.verifySignature(signedContent, pc.RSASignature(signature));
  if (!valid) {
    throw const SignatureVerificationException(
        'RSA PKCS#1 CertificateVerify signature is invalid');
  }
}

/// TLS 1.3 ECDSA signatures are DER-encoded ECDSA-Sig-Value (RFC 8446
/// §4.2.3: "The signature is represented as a DER-encoded ... ECDSA-
/// Sig-Value structure") -- `SEQUENCE { r INTEGER, s INTEGER }` --
/// which pointycastle's ECDSASigner doesn't decode on its own (it wants
/// an [pc.ECSignature] object, i.e. the raw r/s pair).
pc.ECSignature _decodeEcdsaDerSignature(Uint8List der) {
  final parser = pc.ASN1Parser(der);
  final seq = parser.nextObject() as pc.ASN1Sequence;
  final r = (seq.elements![0] as pc.ASN1Integer).integer!;
  final s = (seq.elements![1] as pc.ASN1Integer).integer!;
  return pc.ECSignature(r, s);
}

/// The inverse of [_decodeEcdsaDerSignature]: encodes an (r, s) pair as
/// the DER ECDSA-Sig-Value RFC 8446 §4.2.3 requires on the wire --
/// needed when dart_quic signs its own client CertificateVerify (mTLS)
/// with an EC private key.
Uint8List encodeEcdsaSignatureToDer(pc.ECSignature signature) {
  final rBytes = pc.ASN1Integer(signature.r);
  final sBytes = pc.ASN1Integer(signature.s);
  final seq = pc.ASN1Sequence(elements: [rBytes, sBytes]);
  return seq.encode();
}

/// Signs [content] (the RFC 8446 §4.4.3 padded content, see
/// [buildCertificateVerifyContent]) with an EC private key, returning
/// the DER-encoded ECDSA-Sig-Value the wire format requires. Used for
/// dart_quic's own mTLS client CertificateVerify.
Uint8List signWithEcdsaP256(
    {required pc.ECPrivateKey privateKey, required Uint8List content}) {
  final signer = pc.ECDSASigner(pc.SHA256Digest())
    ..init(
      true,
      pc.ParametersWithRandom(
        pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey),
        pc.FortunaRandom()..seed(pc.KeyParameter(_fixedSeedBytes())),
      ),
    );
  final signature = signer.generateSignature(content) as pc.ECSignature;
  return encodeEcdsaSignatureToDer(signature);
}

/// Signs [content] with an RSA private key using RSASSA-PSS (RFC 8446
/// §4.2.3's rsa_pss_rsae_sha256), for dart_quic's own mTLS client
/// CertificateVerify when the client cert uses an RSA key.
Uint8List signWithRsaPss(
    {required pc.RSAPrivateKey privateKey, required Uint8List content}) {
  final signer =
      pc.PSSSigner(pc.RSAEngine(), pc.SHA256Digest(), pc.SHA256Digest())
        ..init(
          true,
          pc.ParametersWithSaltConfiguration(
            pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey),
            pc.FortunaRandom()..seed(pc.KeyParameter(_fixedSeedBytes())),
            32,
          ),
        );
  final signature = signer.generateSignature(content);
  return signature.bytes;
}

/// A properly-seeded FortunaRandom needs 32 bytes of real entropy;
/// dart:math's Random.secure() provides that without pulling in a
/// separate dependency purely for seeding pointycastle's PRNG.
Uint8List _fixedSeedBytes() {
  final random = Random.secure();
  return Uint8List.fromList(List<int>.generate(32, (_) => random.nextInt(256)));
}
