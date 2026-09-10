import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/dart_quic.dart';
import 'package:dart_quic/src/api.dart';
import 'package:test/test.dart';

void main() {
  group('QuicEndpoint construction', () {
    test('createClient (no mTLS identity) succeeds', () async {
      final endpoint = await QuicEndpoint.createClient();
      expect(endpoint.caRoots, isEmpty);
    });

    test('createClientWithCert stores the given CA roots', () async {
      final caRoot = Uint8List.fromList([1, 2, 3]);
      // A real cert chain + key are needed for the identity itself to
      // parse -- exercised end-to-end in
      // test/integration/quic_go_interop_test.dart via QuicEndpoint,
      // via QuicEndpoint's actual connect() call. Here we only check
      // the argument-validation surface using a real fixture key/cert.
      final fixturesDir = '${_testDir()}/fixtures';
      final certDer = _readDer('$fixturesDir/ec.der');
      final keyDer = _derFromPem('$fixturesDir/ec.key');

      final endpoint = await QuicEndpoint.createClientWithCert(
        caRoots: [caRoot],
        certChain: [certDer],
        clientKey: keyDer,
      );
      expect(endpoint.caRoots, [caRoot]);
    });

    test('createClientWithCert rejects an empty certChain', () async {
      expect(
        () => QuicEndpoint.createClientWithCert(
          caRoots: const [],
          certChain: const [],
          clientKey: const [1, 2, 3],
        ),
        throwsA(isA<QuicApiException>()),
      );
    });
  });

  group('QuicEndpoint.connect address parsing', () {
    test('rejects an addr with no port', () async {
      final endpoint = await QuicEndpoint.createClient();
      expect(
        () => endpoint.connect(addr: 'localhost', serverName: 'localhost'),
        throwsA(isA<QuicApiException>()),
      );
    });

    test('rejects an addr with a non-numeric port', () async {
      final endpoint = await QuicEndpoint.createClient();
      expect(
        () => endpoint.connect(addr: 'localhost:abc', serverName: 'localhost'),
        throwsA(isA<QuicApiException>()),
      );
    });
  });
}

String _testDir() => 'test';

Uint8List _readDer(String path) => File(path).readAsBytesSync();

/// Strips PEM armor to raw DER bytes -- named generically (not
/// "pkcs8FromPem") since test/fixtures/ec.key is actually SEC1, not
/// PKCS#8; QuicEndpoint's own private-key parsing tries multiple
/// encodings, which is exactly what this fixture exercises.
Uint8List _derFromPem(String path) {
  final pem = File(path).readAsStringSync();
  final match =
      RegExp(r'-----BEGIN (?:EC )?PRIVATE KEY-----([A-Za-z0-9+/=\s]+?)-----END')
          .firstMatch(pem)!;
  final b64 = match.group(1)!.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList(base64Decode(b64));
}
