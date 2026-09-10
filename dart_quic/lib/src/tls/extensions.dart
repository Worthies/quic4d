/// RFC 8446 §4.2: `struct { ExtensionType extension_type; opaque
/// extension_data<0..2^16-1>; } Extension;` plus the specific extension
/// IDs and sub-structures dart_quic's client needs to build or parse
/// (supported_versions, supported_groups, key_share,
/// signature_algorithms, server_name, quic_transport_parameters). This
/// intentionally does not model every TLS 1.3 extension -- unrecognized
/// ones are preserved as raw (type, data) pairs so decoding a real
/// server's EncryptedExtensions/Certificate messages never breaks on an
/// extension this client doesn't otherwise act on.
library;

import 'dart:typed_data';

class ExtensionType {
  static const int serverName = 0x0000;
  static const int supportedGroups = 0x000a;
  static const int signatureAlgorithms = 0x000d;
  static const int alpn = 0x0010;
  static const int supportedVersions = 0x002b;
  static const int keyShare = 0x0033;
  static const int quicTransportParameters = 0x0039;
}

/// NamedGroup values (RFC 8446 §4.2.7) dart_quic sends/recognizes.
/// x25519 is the only key-exchange group this client offers (see
/// DESIGN.md: no reason to support a second group when the whole point
/// is talking to one known quic-go server that accepts x25519).
class NamedGroup {
  static const int x25519 = 0x001d;
  static const int secp256r1 = 0x0017;
}

/// SignatureScheme values (RFC 8446 §4.2.3) dart_quic advertises in
/// signature_algorithms and can verify in a peer's CertificateVerify.
/// Covers the ECDSA P-256 and RSA-PSS/PKCS1 schemes real-world CAs
/// commonly issue leaf certificates for (matching what quic-go/rustls
/// and OpenSSL-generated test certs -- see leaf/generate_all_certs.sh
/// -- typically produce).
class SignatureScheme {
  static const int ecdsaSecp256r1Sha256 = 0x0403;
  static const int rsaPssRsaeSha256 = 0x0804;
  static const int rsaPkcs1Sha256 = 0x0401;
  static const int ed25519 = 0x0807;
}

/// A raw, undifferentiated (type, data) extension -- the wire shape
/// every extension has before a specific parser interprets its
/// `extension_data`.
class RawExtension {
  final int type;
  final Uint8List data;
  const RawExtension({required this.type, required this.data});
}

/// Encodes a list of [RawExtension]s as RFC 8446 §4.2's
/// `Extension extensions<8..2^16-1>` vector -- a 2-byte total-length
/// prefix followed by each extension's own 2-byte type + 2-byte length
/// + data.
Uint8List encodeExtensionList(List<RawExtension> extensions) {
  final body = BytesBuilder();
  for (final ext in extensions) {
    body.add(_uint16(ext.type));
    body.add(_uint16(ext.data.length));
    body.add(ext.data);
  }
  final bodyBytes = body.toBytes();
  final out = BytesBuilder();
  out.add(_uint16(bodyBytes.length));
  out.add(bodyBytes);
  return out.toBytes();
}

/// Decodes an extensions vector (the same shape [encodeExtensionList]
/// produces) starting at [offset] in [bytes]. Returns the parsed list
/// plus how many bytes were consumed (including the 2-byte outer
/// length prefix).
class ExtensionListDecodeResult {
  final List<RawExtension> extensions;
  final int bytesConsumed;
  const ExtensionListDecodeResult(this.extensions, this.bytesConsumed);
}

ExtensionListDecodeResult decodeExtensionList(Uint8List bytes, int offset) {
  final totalLength = _readUint16(bytes, offset);
  var pos = offset + 2;
  final end = pos + totalLength;
  final extensions = <RawExtension>[];
  while (pos < end) {
    final type = _readUint16(bytes, pos);
    pos += 2;
    final length = _readUint16(bytes, pos);
    pos += 2;
    final data = Uint8List.sublistView(bytes, pos, pos + length);
    pos += length;
    extensions.add(RawExtension(type: type, data: data));
  }
  return ExtensionListDecodeResult(extensions, pos - offset);
}

/// Builds the `supported_versions` extension's ClientHello variant
/// (RFC 8446 §4.2.1): a 1-byte length-prefixed list of 2-byte
/// ProtocolVersion values. dart_quic only ever offers TLS 1.3 (0x0304)
/// -- QUIC v1 requires it (RFC 9001 §4.2) and there is no reason to
/// also offer 1.2 when the only peer is a quic-go/rustls server.
Uint8List encodeSupportedVersionsClientHello() {
  return Uint8List.fromList([0x02, 0x03, 0x04]);
}

/// Builds the `supported_groups` extension's NamedGroupList body (RFC
/// 8446 §4.2.7): a 2-byte length-prefixed list of 2-byte NamedGroup
/// values.
Uint8List encodeSupportedGroups(List<int> groups) {
  final sink = BytesBuilder();
  sink.add(_uint16(groups.length * 2));
  for (final g in groups) {
    sink.add(_uint16(g));
  }
  return sink.toBytes();
}

/// Builds the `signature_algorithms` extension's SignatureSchemeList
/// body (RFC 8446 §4.2.3): a 2-byte length-prefixed list of 2-byte
/// SignatureScheme values.
Uint8List encodeSignatureAlgorithms(List<int> schemes) {
  final sink = BytesBuilder();
  sink.add(_uint16(schemes.length * 2));
  for (final s in schemes) {
    sink.add(_uint16(s));
  }
  return sink.toBytes();
}

/// Builds the `key_share` extension's ClientHello variant
/// (KeyShareClientHello, RFC 8446 §4.2.8): a 2-byte length-prefixed
/// list of KeyShareEntry (group + length-prefixed key_exchange bytes).
/// dart_quic always offers exactly one share (x25519), matching
/// DESIGN.md's single-group scope.
Uint8List encodeKeyShareClientHello({
  required int group,
  required Uint8List keyExchange,
}) {
  final entry = BytesBuilder()
    ..add(_uint16(group))
    ..add(_uint16(keyExchange.length))
    ..add(keyExchange);
  final entryBytes = entry.toBytes();

  final sink = BytesBuilder();
  sink.add(_uint16(entryBytes.length));
  sink.add(entryBytes);
  return sink.toBytes();
}

/// Decodes a ServerHello's `key_share` extension_data (a single
/// KeyShareEntry with no outer length-prefixed list, unlike the
/// ClientHello variant -- RFC 8446 §4.2.8 defines this asymmetry
/// explicitly via KeyShareServerHello).
class KeyShareEntry {
  final int group;
  final Uint8List keyExchange;
  const KeyShareEntry({required this.group, required this.keyExchange});
}

KeyShareEntry decodeKeyShareServerHello(Uint8List data) {
  final group = _readUint16(data, 0);
  final length = _readUint16(data, 2);
  final keyExchange = Uint8List.sublistView(data, 4, 4 + length);
  return KeyShareEntry(group: group, keyExchange: keyExchange);
}

/// Builds the `server_name` extension's ClientHello body (RFC 6066
/// §3, referenced by RFC 8446 §4.2): a 2-byte list length, then one
/// ServerNameList entry with NameType host_name(0) and a 2-byte
/// length-prefixed hostname.
Uint8List encodeServerName(String hostname) {
  final nameBytes = Uint8List.fromList(hostname.codeUnits);
  final entry = BytesBuilder()
    ..addByte(0) // NameType.host_name
    ..add(_uint16(nameBytes.length))
    ..add(nameBytes);
  final entryBytes = entry.toBytes();

  final sink = BytesBuilder();
  sink.add(_uint16(entryBytes.length));
  sink.add(entryBytes);
  return sink.toBytes();
}

Uint8List _uint16(int value) {
  final buf = ByteData(2)..setUint16(0, value);
  return buf.buffer.asUint8List();
}

int _readUint16(Uint8List bytes, int offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}
