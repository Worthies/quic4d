import 'dart:typed_data';

import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Golden tests: individual extension encoders reproduce the exact byte
/// patterns RFC 8448 §3's ClientHello trace shows for the extensions
/// dart_quic also sends (key_share, supported_versions) -- a full
/// ClientHello-level comparison isn't meaningful since RFC 8448's
/// example (plain TLS 1.3, no QUIC) includes extensions dart_quic never
/// sends (renegotiation_info, psk_key_exchange_modes,
/// record_size_limit) and omits quic_transport_parameters entirely.
void main() {
  group('encodeKeyShareClientHello matches RFC 8448 §3\'s ClientHello', () {
    test('x25519 key share with the RFC\'s exact public key', () {
      // From the trace: "00 33 00 26 00 24 00 1d 00 20 <32-byte pubkey>"
      // -- extension type 0x0033 is stripped here since
      // encodeKeyShareClientHello only returns extension_data.
      final publicKey = _hex(
        '99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe '
        'b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c',
      );

      final encoded = encodeKeyShareClientHello(
        group: NamedGroup.x25519,
        keyExchange: publicKey,
      );

      expect(
        encoded,
        _hex(
          '00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d '
          '8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 '
          '69 1e 52 9a af 2c',
        ),
      );
    });
  });

  test('encodeSupportedVersionsClientHello matches "02 03 04" from the RFC',
      () {
    expect(encodeSupportedVersionsClientHello(), _hex('02 03 04'));
  });

  group('extension list round trip', () {
    test('encodeExtensionList / decodeExtensionList round-trips', () {
      final extensions = [
        RawExtension(
            type: ExtensionType.supportedVersions,
            data: encodeSupportedVersionsClientHello()),
        RawExtension(
            type: ExtensionType.supportedGroups,
            data: encodeSupportedGroups([NamedGroup.x25519])),
        RawExtension(
            type: ExtensionType.quicTransportParameters,
            data: Uint8List.fromList([1, 2, 3, 4])),
      ];

      final encoded = encodeExtensionList(extensions);
      final decoded = decodeExtensionList(encoded, 0);

      expect(decoded.bytesConsumed, encoded.length);
      expect(decoded.extensions.length, 3);
      expect(decoded.extensions[0].type, ExtensionType.supportedVersions);
      expect(decoded.extensions[0].data, _hex('02 03 04'));
      expect(decoded.extensions[2].type, ExtensionType.quicTransportParameters);
      expect(decoded.extensions[2].data, Uint8List.fromList([1, 2, 3, 4]));
    });

    test('decodeExtensionList handles an empty extension list', () {
      final encoded = encodeExtensionList([]);
      expect(encoded, _hex('00 00'));
      final decoded = decodeExtensionList(encoded, 0);
      expect(decoded.extensions, isEmpty);
      expect(decoded.bytesConsumed, 2);
    });

    test('decodeExtensionList works at a non-zero offset', () {
      final encoded = encodeExtensionList([
        RawExtension(type: 1, data: Uint8List.fromList([9]))
      ]);
      final prefixed = Uint8List.fromList([0xff, 0xff, ...encoded]);
      final decoded = decodeExtensionList(prefixed, 2);
      expect(decoded.extensions.single.type, 1);
      expect(decoded.extensions.single.data, Uint8List.fromList([9]));
    });
  });

  group('encodeSupportedGroups / encodeSignatureAlgorithms', () {
    test('single-group supported_groups has a 2-byte list length', () {
      final encoded = encodeSupportedGroups([NamedGroup.x25519]);
      expect(encoded, _hex('00 02 00 1d'));
    });

    test('signature_algorithms list length matches the entry count', () {
      final encoded = encodeSignatureAlgorithms([
        SignatureScheme.ecdsaSecp256r1Sha256,
        SignatureScheme.ed25519,
      ]);
      expect(encoded, _hex('00 04 04 03 08 07'));
    });
  });

  group('server_name / key_share (server variant)', () {
    test('encodeServerName produces a host_name entry', () {
      final encoded = encodeServerName('example.com');
      // list length (2) + entry: type(1)=0 + len(2)=11 + "example.com"
      final expected = Uint8List.fromList(
          [..._hex('00 0e 00 00 0b'), ...'example.com'.codeUnits]);
      expect(encoded, expected);
    });

    test('decodeKeyShareServerHello parses a single entry (no outer list)', () {
      final data = Uint8List.fromList(
          [..._hex('00 1d 00 20'), ...List<int>.filled(32, 0xAB)]);
      final entry = decodeKeyShareServerHello(data);
      expect(entry.group, NamedGroup.x25519);
      expect(entry.keyExchange, Uint8List.fromList(List.filled(32, 0xAB)));
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
