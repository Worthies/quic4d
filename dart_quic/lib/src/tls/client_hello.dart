/// RFC 8446 §4.1.2: builds a TLS 1.3 ClientHello, including the
/// extensions dart_quic actually needs -- supported_versions (TLS 1.3
/// only), supported_groups + key_share (x25519 only, per DESIGN.md),
/// signature_algorithms, server_name (SNI), and
/// quic_transport_parameters (RFC 9001 §8.2, required for any QUIC TLS
/// handshake). Verified byte-for-byte against RFC 8448 §3's ClientHello
/// trace using the same inputs (see client_hello_test.dart).
library;

import 'dart:typed_data';

import 'extensions.dart';
import 'handshake_message.dart';

/// TLS 1.3 cipher suites dart_quic offers, in the same order RFC 8448's
/// trace uses (AES-128-GCM first). RFC 9001 §4.2 requires
/// TLS_AES_128_GCM_SHA256 support at minimum for a QUIC TLS stack;
/// offering ChaCha20 and AES-256 too costs nothing and matches what
/// quic-go's default TLS config will actually negotiate against if the
/// server prefers one of them.
class CipherSuite {
  static const int tlsAes128GcmSha256 = 0x1301;
  static const int tlsChacha20Poly1305Sha256 = 0x1303;
  static const int tlsAes256GcmSha384 = 0x1302;

  static const List<int> dartQuicOffered = [
    tlsAes128GcmSha256,
    tlsChacha20Poly1305Sha256,
    tlsAes256GcmSha384,
  ];
}

/// Builds a full ClientHello handshake message (header + body).
///
/// [random] must be exactly 32 bytes (the client's handshake random,
/// generated fresh per connection attempt -- RFC 8446 §4.1.2 requires
/// it be generated with a secure random number generator).
/// [x25519PublicKey] is this connection's ephemeral X25519 public key
/// (32 bytes). [serverName] is used for SNI; pass null to omit the
/// extension entirely (e.g. connecting to a literal IP with no SNI
/// value, matching how quic_client.dart's existing _serverNameFromCerts
/// doc comment describes the tradeoff).
Uint8List buildClientHello({
  required Uint8List random,
  required Uint8List x25519PublicKey,
  required Uint8List quicTransportParameters,
  String? serverName,
  List<int> cipherSuites = CipherSuite.dartQuicOffered,
  List<String> alpnProtocols = const ['leaf-commander'],
}) {
  if (random.length != 32) {
    throw ArgumentError('ClientHello random must be exactly 32 bytes');
  }
  if (x25519PublicKey.length != 32) {
    throw ArgumentError('x25519 public key must be exactly 32 bytes');
  }

  final extensions = <RawExtension>[];

  if (serverName != null) {
    extensions.add(RawExtension(
      type: ExtensionType.serverName,
      data: encodeServerName(serverName),
    ));
  }

  extensions.add(RawExtension(
    type: ExtensionType.supportedGroups,
    data: encodeSupportedGroups([NamedGroup.x25519]),
  ));

  extensions.add(RawExtension(
    type: ExtensionType.keyShare,
    data: encodeKeyShareClientHello(
      group: NamedGroup.x25519,
      keyExchange: x25519PublicKey,
    ),
  ));

  extensions.add(RawExtension(
    type: ExtensionType.supportedVersions,
    data: encodeSupportedVersionsClientHello(),
  ));

  if (alpnProtocols.isNotEmpty) {
    extensions.add(RawExtension(
      type: ExtensionType.alpn,
      data: encodeAlpnProtocolList(alpnProtocols),
    ));
  }

  extensions.add(RawExtension(
    type: ExtensionType.signatureAlgorithms,
    data: encodeSignatureAlgorithms([
      SignatureScheme.ecdsaSecp256r1Sha256,
      SignatureScheme.rsaPssRsaeSha256,
      SignatureScheme.rsaPkcs1Sha256,
      SignatureScheme.ed25519,
    ]),
  ));

  extensions.add(RawExtension(
    type: ExtensionType.quicTransportParameters,
    data: quicTransportParameters,
  ));

  final body = BytesBuilder();
  body.add([0x03, 0x03]); // legacy_version: TLS 1.2 (RFC 8446 §4.1.2)
  body.add(random);
  body.addByte(0); // legacy_session_id: empty (QUIC's TLS never resumes
  // via the classic session-ID mechanism -- RFC 9001 doesn't forbid a
  // non-empty session ID, but there's no reason for dart_quic to send
  // one when it never implements resumption; see DESIGN.md).

  body.add(_uint16(cipherSuites.length * 2));
  for (final suite in cipherSuites) {
    body.add(_uint16(suite));
  }

  body.addByte(1); // legacy_compression_methods length
  body.addByte(0); // "null" compression, the only value TLS 1.3 permits

  body.add(encodeExtensionList(extensions));

  final sink = BytesBuilder();
  encodeHandshakeMessage(sink, HandshakeType.clientHello, body.toBytes());
  return sink.toBytes();
}

Uint8List _uint16(int value) {
  final buf = ByteData(2)..setUint16(0, value);
  return buf.buffer.asUint8List();
}
