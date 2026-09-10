/// RFC 8446 §4.4.2 (Certificate) and §4.4.3 (CertificateVerify): the
/// two handshake messages that carry X.509 certificate chains and the
/// signature proving possession of the corresponding private key.
/// dart_quic only ever sends/parses X.509 certificate entries (RFC
/// 7250 RawPublicKey is not needed -- see DESIGN.md's mTLS
/// requirement, which assumes standard X.509 client/server certs like
/// the ones leaf/generate_all_certs.sh produces).
library;

import 'dart:typed_data';

import 'extensions.dart';
import 'handshake_message.dart';

/// One entry in a Certificate message's certificate_list: a DER-encoded
/// X.509 certificate plus its (usually empty, for a client cert)
/// per-entry extensions.
class CertificateEntry {
  final Uint8List certData;
  final List<RawExtension> extensions;
  const CertificateEntry({required this.certData, this.extensions = const []});
}

final Uint8List _emptyBytes = Uint8List(0);

class CertificateMessage {
  final Uint8List certificateRequestContext;
  final List<CertificateEntry> certificateList;
  CertificateMessage({
    Uint8List? certificateRequestContext,
    required this.certificateList,
  }) : certificateRequestContext = certificateRequestContext ?? _emptyBytes;

  Uint8List encode() {
    final body = BytesBuilder();
    body.addByte(certificateRequestContext.length);
    body.add(certificateRequestContext);

    final listBody = BytesBuilder();
    for (final entry in certificateList) {
      _writeUint24(listBody, entry.certData.length);
      listBody.add(entry.certData);
      listBody.add(encodeExtensionList(entry.extensions));
    }
    final listBytes = listBody.toBytes();
    _writeUint24(body, listBytes.length);
    body.add(listBytes);

    final sink = BytesBuilder();
    encodeHandshakeMessage(sink, HandshakeType.certificate, body.toBytes());
    return sink.toBytes();
  }

  /// Decodes a Certificate message's already-unwrapped body (i.e. the
  /// bytes after the 4-byte handshake header -- see
  /// [tryDecodeHandshakeMessage]).
  static CertificateMessage decodeBody(Uint8List body) {
    var pos = 0;
    final contextLength = body[pos];
    pos += 1;
    final context = Uint8List.sublistView(body, pos, pos + contextLength);
    pos += contextLength;

    final listLength = _readUint24(body, pos);
    pos += 3;
    final listEnd = pos + listLength;

    final entries = <CertificateEntry>[];
    while (pos < listEnd) {
      final certLength = _readUint24(body, pos);
      pos += 3;
      final certData = Uint8List.sublistView(body, pos, pos + certLength);
      pos += certLength;

      final extResult = decodeExtensionList(body, pos);
      pos += extResult.bytesConsumed;

      entries.add(CertificateEntry(
          certData: certData, extensions: extResult.extensions));
    }

    return CertificateMessage(
        certificateRequestContext: context, certificateList: entries);
  }
}

class CertificateVerifyMessage {
  final int algorithm;
  final Uint8List signature;
  const CertificateVerifyMessage(
      {required this.algorithm, required this.signature});

  Uint8List encode() {
    final body = BytesBuilder();
    body.add(_uint16(algorithm));
    body.add(_uint16(signature.length));
    body.add(signature);

    final sink = BytesBuilder();
    encodeHandshakeMessage(
        sink, HandshakeType.certificateVerify, body.toBytes());
    return sink.toBytes();
  }

  static CertificateVerifyMessage decodeBody(Uint8List body) {
    final algorithm = (body[0] << 8) | body[1];
    final sigLength = (body[2] << 8) | body[3];
    final signature = Uint8List.sublistView(body, 4, 4 + sigLength);
    return CertificateVerifyMessage(algorithm: algorithm, signature: signature);
  }
}

/// RFC 8446 §4.4.3: builds the exact byte sequence that gets signed
/// (server) or verified (client checking the server's signature) --
/// 64 bytes of 0x20, the context string, a 0x00 separator, then the
/// transcript hash. [isServer] selects between "TLS 1.3, server
/// CertificateVerify" and "TLS 1.3, client CertificateVerify" (RFC
/// 8446 §4.4.3's two context strings) -- dart_quic needs the server
/// variant to verify the peer's CertificateVerify, and the client
/// variant to build its own (mTLS).
Uint8List buildCertificateVerifyContent({
  required bool isServer,
  required Uint8List transcriptHash,
}) {
  final contextString = isServer
      ? 'TLS 1.3, server CertificateVerify'
      : 'TLS 1.3, client CertificateVerify';

  final sink = BytesBuilder();
  sink.add(List.filled(64, 0x20));
  sink.add(contextString.codeUnits);
  sink.addByte(0x00);
  sink.add(transcriptHash);
  return sink.toBytes();
}

void _writeUint24(BytesBuilder sink, int value) {
  sink.addByte((value >> 16) & 0xFF);
  sink.addByte((value >> 8) & 0xFF);
  sink.addByte(value & 0xFF);
}

int _readUint24(Uint8List bytes, int offset) {
  return (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
}

Uint8List _uint16(int value) {
  final buf = ByteData(2)..setUint16(0, value);
  return buf.buffer.asUint8List();
}
