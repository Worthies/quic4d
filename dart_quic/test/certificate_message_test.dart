import 'dart:typed_data';

import 'package:dart_quic/src/tls/certificate_message.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:dart_quic/src/tls/handshake_message.dart';
import 'package:test/test.dart';

void main() {
  group('buildCertificateVerifyContent', () {
    test('matches RFC 8446 §4.4.3\'s worked example exactly', () {
      // RFC 8446 §4.4.3: "if the transcript hash was 32 bytes of 01
      // ... the content covered by the digital signature for a server
      // CertificateVerify would be:" followed by the exact hex dump
      // below.
      final transcriptHash = Uint8List.fromList(List.filled(32, 0x01));

      final content = buildCertificateVerifyContent(
        isServer: true,
        transcriptHash: transcriptHash,
      );

      expect(
          content,
          _hex(
            '2020202020202020202020202020202020202020202020202020202020202020'
            '2020202020202020202020202020202020202020202020202020202020202020'
            '544c5320312e332c207365727665722043657274696669636174655665726966'
            '79'
            '00'
            '0101010101010101010101010101010101010101010101010101010101010101',
          ));
    });

    test('uses the client context string when isServer is false', () {
      final transcriptHash = Uint8List.fromList(List.filled(32, 0xAB));
      final content = buildCertificateVerifyContent(
        isServer: false,
        transcriptHash: transcriptHash,
      );
      final contextStringBytes = 'TLS 1.3, client CertificateVerify'.codeUnits;
      final actualContextBytes =
          content.sublist(64, 64 + contextStringBytes.length);
      expect(actualContextBytes, contextStringBytes);
      // Separator byte right after the context string.
      expect(content[64 + contextStringBytes.length], 0x00);
    });

    test('content length is 64 + contextString.length + 1 + hash.length', () {
      final transcriptHash = Uint8List(32);
      final content = buildCertificateVerifyContent(
        isServer: true,
        transcriptHash: transcriptHash,
      );
      final contextLen = 'TLS 1.3, server CertificateVerify'.length;
      expect(content.length, 64 + contextLen + 1 + 32);
    });
  });

  group('CertificateMessage round trip', () {
    test('single-entry chain round-trips through encode/decode', () {
      final cert = Uint8List.fromList(List.generate(300, (i) => i % 256));
      final message = CertificateMessage(
        certificateList: [CertificateEntry(certData: cert)],
      );

      final encoded = message.encode();
      final decodedHeader = tryDecodeHandshakeMessage(encoded, 0)!;
      expect(decodedHeader.type, HandshakeType.certificate);

      final decoded = CertificateMessage.decodeBody(decodedHeader.body);
      expect(decoded.certificateList.length, 1);
      expect(decoded.certificateList.single.certData, cert);
      expect(decoded.certificateRequestContext, isEmpty);
    });

    test('multi-entry chain (leaf + intermediate) round-trips', () {
      final leaf = Uint8List.fromList(List.generate(200, (i) => i));
      final intermediate =
          Uint8List.fromList(List.generate(250, (i) => 255 - i));
      final message = CertificateMessage(
        certificateList: [
          CertificateEntry(certData: leaf),
          CertificateEntry(certData: intermediate),
        ],
      );

      final decoded = CertificateMessage.decodeBody(
        tryDecodeHandshakeMessage(message.encode(), 0)!.body,
      );
      expect(decoded.certificateList.length, 2);
      expect(decoded.certificateList[0].certData, leaf);
      expect(decoded.certificateList[1].certData, intermediate);
    });

    test('an empty certificate_list round-trips (client with no cert)', () {
      final message = CertificateMessage(certificateList: []);
      final decoded = CertificateMessage.decodeBody(
        tryDecodeHandshakeMessage(message.encode(), 0)!.body,
      );
      expect(decoded.certificateList, isEmpty);
    });

    test('per-entry extensions round-trip', () {
      final cert = Uint8List.fromList([1, 2, 3]);
      final message = CertificateMessage(
        certificateList: [
          CertificateEntry(
            certData: cert,
            extensions: [
              RawExtension(type: 0x1234, data: Uint8List.fromList([9, 9]))
            ],
          ),
        ],
      );
      final decoded = CertificateMessage.decodeBody(
        tryDecodeHandshakeMessage(message.encode(), 0)!.body,
      );
      expect(decoded.certificateList.single.extensions.single.type, 0x1234);
    });
  });

  group('CertificateVerifyMessage round trip', () {
    test('encode/decode preserves algorithm and signature', () {
      final message = CertificateVerifyMessage(
        algorithm: SignatureScheme.ecdsaSecp256r1Sha256,
        signature: Uint8List.fromList(List.generate(70, (i) => i)),
      );
      final decodedHeader = tryDecodeHandshakeMessage(message.encode(), 0)!;
      expect(decodedHeader.type, HandshakeType.certificateVerify);

      final decoded = CertificateVerifyMessage.decodeBody(decodedHeader.body);
      expect(decoded.algorithm, SignatureScheme.ecdsaSecp256r1Sha256);
      expect(decoded.signature, message.signature);
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
