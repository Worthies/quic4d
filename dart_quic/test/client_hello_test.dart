import 'dart:typed_data';

import 'package:dart_quic/src/tls/client_hello.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:dart_quic/src/tls/handshake_message.dart';
import 'package:test/test.dart';

void main() {
  group('buildClientHello', () {
    late Uint8List random;
    late Uint8List publicKey;
    late Uint8List transportParams;

    setUp(() {
      random = Uint8List.fromList(List.generate(32, (i) => i));
      publicKey = Uint8List.fromList(List.generate(32, (i) => 255 - i));
      transportParams = Uint8List.fromList([0xAA, 0xBB, 0xCC]);
    });

    test('starts with the ClientHello handshake header', () {
      final hello = buildClientHello(
        random: random,
        x25519PublicKey: publicKey,
        quicTransportParameters: transportParams,
      );

      expect(hello[0], HandshakeType.clientHello);
      // uint24 length = total - 4-byte header.
      final length = (hello[1] << 16) | (hello[2] << 8) | hello[3];
      expect(length, hello.length - 4);
    });

    test('body starts with legacy_version 0x0303 then the random', () {
      final hello = buildClientHello(
        random: random,
        x25519PublicKey: publicKey,
        quicTransportParameters: transportParams,
      );
      final body = Uint8List.sublistView(hello, 4);
      expect(body[0], 0x03);
      expect(body[1], 0x03);
      expect(Uint8List.sublistView(body, 2, 34), random);
    });

    test('includes an empty legacy_session_id', () {
      final hello = buildClientHello(
        random: random,
        x25519PublicKey: publicKey,
        quicTransportParameters: transportParams,
      );
      final body = Uint8List.sublistView(hello, 4);
      // offset 34 (after version+random) is the session ID length byte.
      expect(body[34], 0);
    });

    test('includes exactly the cipher suites requested', () {
      final hello = buildClientHello(
        random: random,
        x25519PublicKey: publicKey,
        quicTransportParameters: transportParams,
        cipherSuites: [CipherSuite.tlsAes128GcmSha256],
      );
      final body = Uint8List.sublistView(hello, 4);
      // offset 35: cipher_suites length (uint16) = 2 (one suite).
      final cipherSuitesLength = (body[35] << 8) | body[36];
      expect(cipherSuitesLength, 2);
      expect(body[37], 0x13);
      expect(body[38], 0x01);
    });

    test('extensions include quic_transport_parameters verbatim', () {
      final hello = buildClientHello(
        random: random,
        x25519PublicKey: publicKey,
        quicTransportParameters: transportParams,
      );
      final message = tryDecodeHandshakeMessage(hello, 0)!;
      // Walk the body manually to the extensions vector: version(2) +
      // random(32) + session_id_len(1) + session_id(0) +
      // cipher_suites_len(2) + cipher_suites(N*2) +
      // compression_len(1) + compression(1).
      var pos = 2 + 32 + 1;
      final cipherSuitesLen = (message.body[pos] << 8) | message.body[pos + 1];
      pos += 2 + cipherSuitesLen;
      pos += 1 + message.body[pos]; // compression methods length + bytes

      final extResult = decodeExtensionList(message.body, pos);
      final quicExt = extResult.extensions
          .firstWhere((e) => e.type == ExtensionType.quicTransportParameters);
      expect(quicExt.data, transportParams);
    });

    test('omits server_name when none is given', () {
      final hello = buildClientHello(
        random: random,
        x25519PublicKey: publicKey,
        quicTransportParameters: transportParams,
      );
      final message = tryDecodeHandshakeMessage(hello, 0)!;
      var pos = 2 + 32 + 1;
      final cipherSuitesLen = (message.body[pos] << 8) | message.body[pos + 1];
      pos += 2 + cipherSuitesLen;
      pos += 1 + message.body[pos];
      final extResult = decodeExtensionList(message.body, pos);
      expect(
        extResult.extensions.any((e) => e.type == ExtensionType.serverName),
        isFalse,
      );
    });

    test('includes server_name when a hostname is given', () {
      final hello = buildClientHello(
        random: random,
        x25519PublicKey: publicKey,
        quicTransportParameters: transportParams,
        serverName: 'example.com',
      );
      final message = tryDecodeHandshakeMessage(hello, 0)!;
      var pos = 2 + 32 + 1;
      final cipherSuitesLen = (message.body[pos] << 8) | message.body[pos + 1];
      pos += 2 + cipherSuitesLen;
      pos += 1 + message.body[pos];
      final extResult = decodeExtensionList(message.body, pos);
      expect(
        extResult.extensions.any((e) => e.type == ExtensionType.serverName),
        isTrue,
      );
    });

    test('rejects a random that is not exactly 32 bytes', () {
      expect(
        () => buildClientHello(
          random: Uint8List(31),
          x25519PublicKey: publicKey,
          quicTransportParameters: transportParams,
        ),
        throwsArgumentError,
      );
    });

    test('rejects a public key that is not exactly 32 bytes', () {
      expect(
        () => buildClientHello(
          random: random,
          x25519PublicKey: Uint8List(31),
          quicTransportParameters: transportParams,
        ),
        throwsArgumentError,
      );
    });
  });
}
