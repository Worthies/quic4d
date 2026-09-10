/// RFC 8446 §4.1.3: parses a ServerHello handshake message body. Only
/// the fields dart_quic actually needs are surfaced as named getters
/// (cipher suite, key_share, supported_versions' selected version) --
/// [rawExtensions] preserves everything else so a caller can still
/// inspect e.g. a HelloRetryRequest signal (RFC 8446 §4.1.4: detected
/// by [random] equaling a fixed magic constant, not by extension
/// content) without this parser needing to model every possible
/// extension.
library;

import 'dart:typed_data';

import 'extensions.dart';

/// RFC 8446 §4.1.3: the fixed 32-byte Random value a HelloRetryRequest
/// uses in place of a real server random, letting a client distinguish
/// "this is actually a HelloRetryRequest" from an ordinary ServerHello
/// even though both share the same handshake type byte (2).
final Uint8List helloRetryRequestRandom = Uint8List.fromList([
  0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, //
  0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
  0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
  0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
]);

class ServerHelloFormatException implements Exception {
  final String message;
  const ServerHelloFormatException(this.message);

  @override
  String toString() => 'ServerHelloFormatException: $message';
}

class ServerHello {
  final Uint8List random;
  final Uint8List legacySessionIdEcho;
  final int cipherSuite;
  final List<RawExtension> rawExtensions;

  const ServerHello({
    required this.random,
    required this.legacySessionIdEcho,
    required this.cipherSuite,
    required this.rawExtensions,
  });

  bool get isHelloRetryRequest => _bytesEqual(random, helloRetryRequestRandom);

  RawExtension? extension(int type) {
    for (final ext in rawExtensions) {
      if (ext.type == type) return ext;
    }
    return null;
  }

  /// The server's selected key_share entry, or null if the extension is
  /// absent (which would be a protocol violation for a non-PSK
  /// handshake, but parsing itself doesn't enforce that -- the caller's
  /// handshake driver does).
  KeyShareEntry? get keyShare {
    final ext = extension(ExtensionType.keyShare);
    if (ext == null) return null;
    return decodeKeyShareServerHello(ext.data);
  }

  /// The selected TLS version from supported_versions (RFC 8446
  /// §4.2.1's ServerHello variant: a bare 2-byte ProtocolVersion, not a
  /// length-prefixed list like the ClientHello variant). Null if
  /// absent.
  int? get selectedVersion {
    final ext = extension(ExtensionType.supportedVersions);
    if (ext == null || ext.data.length < 2) return null;
    return (ext.data[0] << 8) | ext.data[1];
  }

  /// Decodes a ServerHello's already-unwrapped body (bytes after the
  /// 4-byte handshake header).
  static ServerHello decodeBody(Uint8List body) {
    var pos = 0;
    // legacy_version (2 bytes) -- ignored; supported_versions is
    // authoritative per RFC 8446 §4.1.3.
    pos += 2;

    if (pos + 32 > body.length) {
      throw const ServerHelloFormatException(
          'ServerHello truncated before random');
    }
    final random = Uint8List.sublistView(body, pos, pos + 32);
    pos += 32;

    if (pos >= body.length) {
      throw const ServerHelloFormatException(
          'ServerHello truncated before legacy_session_id_echo length');
    }
    final sessionIdLength = body[pos];
    pos += 1;
    if (pos + sessionIdLength > body.length) {
      throw const ServerHelloFormatException(
          'ServerHello legacy_session_id_echo exceeds available bytes');
    }
    final sessionIdEcho =
        Uint8List.sublistView(body, pos, pos + sessionIdLength);
    pos += sessionIdLength;

    if (pos + 2 > body.length) {
      throw const ServerHelloFormatException(
          'ServerHello truncated before cipher_suite');
    }
    final cipherSuite = (body[pos] << 8) | body[pos + 1];
    pos += 2;

    if (pos >= body.length) {
      throw const ServerHelloFormatException(
          'ServerHello truncated before legacy_compression_method');
    }
    pos += 1; // legacy_compression_method, always 0, ignored

    final extResult = decodeExtensionList(body, pos);

    return ServerHello(
      random: random,
      legacySessionIdEcho: sessionIdEcho,
      cipherSuite: cipherSuite,
      rawExtensions: extResult.extensions,
    );
  }
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
