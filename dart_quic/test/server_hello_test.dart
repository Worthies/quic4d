import 'dart:typed_data';

import 'package:dart_quic/src/tls/extensions.dart';
import 'package:dart_quic/src/tls/handshake_message.dart';
import 'package:dart_quic/src/tls/server_hello.dart';
import 'package:test/test.dart';

/// Golden test against RFC 8448 §3's real ServerHello bytes.
void main() {
  group('ServerHello.decodeBody — RFC 8448 §3\'s worked example', () {
    final serverHelloMessage = _hex(
      '02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e '
      '60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e '
      'd3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 '
      '76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 '
      'dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04',
    );

    test('handshake header reports type=server_hello and correct length', () {
      final decoded = tryDecodeHandshakeMessage(serverHelloMessage, 0)!;
      expect(decoded.type, HandshakeType.serverHello);
      expect(decoded.totalLength, serverHelloMessage.length);
    });

    test('parses cipher_suite as TLS_AES_128_GCM_SHA256 (0x1301)', () {
      final body = tryDecodeHandshakeMessage(serverHelloMessage, 0)!.body;
      final hello = ServerHello.decodeBody(body);
      expect(hello.cipherSuite, 0x1301);
    });

    test('is not mistaken for a HelloRetryRequest', () {
      final body = tryDecodeHandshakeMessage(serverHelloMessage, 0)!.body;
      final hello = ServerHello.decodeBody(body);
      expect(hello.isHelloRetryRequest, isFalse);
    });

    test('parses the exact server random from the trace', () {
      final body = tryDecodeHandshakeMessage(serverHelloMessage, 0)!.body;
      final hello = ServerHello.decodeBody(body);
      expect(
        hello.random,
        _hex(
          'a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 '
          '93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28',
        ),
      );
    });

    test('parses the key_share extension with the exact server public key', () {
      final body = tryDecodeHandshakeMessage(serverHelloMessage, 0)!.body;
      final hello = ServerHello.decodeBody(body);
      final keyShare = hello.keyShare!;
      expect(keyShare.group, NamedGroup.x25519);
      expect(
        keyShare.keyExchange,
        _hex(
          'c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 '
          '56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f',
        ),
      );
    });

    test('parses supported_versions selected_version as TLS 1.3 (0x0304)', () {
      final body = tryDecodeHandshakeMessage(serverHelloMessage, 0)!.body;
      final hello = ServerHello.decodeBody(body);
      expect(hello.selectedVersion, 0x0304);
    });

    test('legacy_session_id_echo is empty (client sent none)', () {
      final body = tryDecodeHandshakeMessage(serverHelloMessage, 0)!.body;
      final hello = ServerHello.decodeBody(body);
      expect(hello.legacySessionIdEcho, isEmpty);
    });
  });

  test('isHelloRetryRequest recognizes the fixed magic Random', () {
    final hello = ServerHello(
      random: helloRetryRequestRandom,
      legacySessionIdEcho: Uint8List(0),
      cipherSuite: 0x1301,
      rawExtensions: const [],
    );
    expect(hello.isHelloRetryRequest, isTrue);
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
