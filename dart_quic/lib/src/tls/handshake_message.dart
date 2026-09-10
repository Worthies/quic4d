/// RFC 8446 §4: the common TLS handshake message envelope --
/// `struct { HandshakeType msg_type; uint24 length; opaque body[length]; }`.
/// Every handshake message (ClientHello, ServerHello, Certificate, ...)
/// is this 4-byte header plus a type-specific body. This is the one
/// place that header is read/written so every message parser below can
/// assume it's already been stripped.
library;

import 'dart:typed_data';

/// RFC 8446 §4: HandshakeType values dart_quic needs to recognize.
/// Values not listed (e.g. hello_retry_request re-uses server_hello's
/// type byte and is distinguished by a magic Random value -- see RFC
/// 8446 §4.1.3) are handled at the call site, not here.
class HandshakeType {
  static const int clientHello = 1;
  static const int serverHello = 2;
  static const int newSessionTicket = 4;
  static const int endOfEarlyData = 5;
  static const int encryptedExtensions = 8;
  static const int certificate = 11;
  static const int certificateRequest = 13;
  static const int certificateVerify = 15;
  static const int finished = 20;
  static const int keyUpdate = 24;
}

class HandshakeFormatException implements Exception {
  final String message;
  const HandshakeFormatException(this.message);

  @override
  String toString() => 'HandshakeFormatException: $message';
}

/// A decoded handshake message: its [type] byte and [body] (the bytes
/// after the 4-byte type+length header, i.e. what a message-specific
/// parser consumes), plus [totalLength] (header + body) so the caller
/// can advance a CRYPTO-stream cursor.
class HandshakeMessage {
  final int type;
  final Uint8List body;
  final int totalLength;

  const HandshakeMessage(
      {required this.type, required this.body, required this.totalLength});
}

/// Wraps [body] in the 4-byte handshake header for [type] and appends
/// the whole thing to [sink].
void encodeHandshakeMessage(BytesBuilder sink, int type, Uint8List body) {
  sink.addByte(type);
  _writeUint24(sink, body.length);
  sink.add(body);
}

/// Attempts to decode one complete handshake message starting at
/// [offset] in [bytes]. Returns null (rather than throwing) if fewer
/// than a full message's worth of bytes are available yet -- CRYPTO
/// frames can arrive in arbitrary chunks relative to handshake message
/// boundaries (RFC 9000 §19.6), so the caller (the handshake driver
/// buffering incoming CRYPTO data) needs to distinguish "wait for
/// more" from "this is malformed" without an exception on the hot
/// path of ordinary partial delivery.
HandshakeMessage? tryDecodeHandshakeMessage(Uint8List bytes, int offset) {
  const headerLength = 4;
  if (offset + headerLength > bytes.length) return null;

  final type = bytes[offset];
  final length = _readUint24(bytes, offset + 1);
  final totalLength = headerLength + length;
  if (offset + totalLength > bytes.length) return null;

  final body =
      Uint8List.sublistView(bytes, offset + headerLength, offset + totalLength);
  return HandshakeMessage(type: type, body: body, totalLength: totalLength);
}

void _writeUint24(BytesBuilder sink, int value) {
  if (value < 0 || value > 0xFFFFFF) {
    throw HandshakeFormatException(
        'handshake message body length $value out of uint24 range');
  }
  sink.addByte((value >> 16) & 0xFF);
  sink.addByte((value >> 8) & 0xFF);
  sink.addByte(value & 0xFF);
}

int _readUint24(Uint8List bytes, int offset) {
  return (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
}
