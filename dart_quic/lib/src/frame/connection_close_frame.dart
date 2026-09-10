import 'dart:convert';
import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// CONNECTION_CLOSE (type=0x1c or 0x1d, RFC 9000 §19.19): notifies the
/// peer the connection is closing. Type 0x1c is a QUIC-layer error (or
/// no error); 0x1d is an application-layer error and omits the
/// triggering [frameType] field entirely (not just zeroes it).
class ConnectionCloseFrame extends Frame {
  static const int wireTypeTransport = 0x1c;
  static const int wireTypeApplication = 0x1d;

  final bool isApplicationError;
  final int errorCode;

  /// The frame type that triggered the error — only meaningful (and
  /// only encoded/decoded) when [isApplicationError] is false.
  final int? frameType;
  final String reasonPhrase;

  const ConnectionCloseFrame({
    required this.isApplicationError,
    required this.errorCode,
    this.frameType,
    this.reasonPhrase = '',
  });

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(isApplicationError ? wireTypeApplication : wireTypeTransport);
    writeVarInt(sink, errorCode);
    if (!isApplicationError) {
      writeVarInt(sink, frameType ?? 0);
    }
    final reasonBytes = utf8.encode(reasonPhrase);
    writeVarInt(sink, reasonBytes.length);
    sink.add(reasonBytes);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length) {
      throw const FrameFormatException(
          'no bytes for CONNECTION_CLOSE frame type');
    }
    final type = bytes[pos];
    if (type != wireTypeTransport && type != wireTypeApplication) {
      throw const FrameFormatException('not a CONNECTION_CLOSE frame');
    }
    pos += 1;
    final isApplication = type == wireTypeApplication;

    final errorCode =
        readFrameVarInt(bytes, pos, 'CONNECTION_CLOSE error code');
    pos += errorCode.bytesConsumed;

    int? frameType;
    if (!isApplication) {
      final ft = readFrameVarInt(bytes, pos, 'CONNECTION_CLOSE frame type');
      frameType = ft.value;
      pos += ft.bytesConsumed;
    }

    final reasonLength =
        readFrameVarInt(bytes, pos, 'CONNECTION_CLOSE reason length');
    pos += reasonLength.bytesConsumed;

    if (pos + reasonLength.value > bytes.length) {
      throw const FrameFormatException(
          'CONNECTION_CLOSE reason phrase exceeds available bytes');
    }
    final reasonBytes =
        Uint8List.sublistView(bytes, pos, pos + reasonLength.value);
    pos += reasonLength.value;

    String reason;
    try {
      reason = utf8.decode(reasonBytes, allowMalformed: false);
    } on FormatException {
      // RFC 9000 §19.19 recommends but does not require valid UTF-8;
      // don't let an ill-behaved peer's malformed reason string crash
      // parsing of an otherwise-valid CONNECTION_CLOSE frame.
      reason = utf8.decode(reasonBytes, allowMalformed: true);
    }

    return FrameDecodeResult(
      ConnectionCloseFrame(
        isApplicationError: isApplication,
        errorCode: errorCode.value,
        frameType: frameType,
        reasonPhrase: reason,
      ),
      pos - offset,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is ConnectionCloseFrame &&
      other.isApplicationError == isApplicationError &&
      other.errorCode == errorCode &&
      other.frameType == frameType &&
      other.reasonPhrase == reasonPhrase;

  @override
  int get hashCode =>
      Object.hash(isApplicationError, errorCode, frameType, reasonPhrase);

  @override
  String toString() =>
      'ConnectionCloseFrame(application: $isApplicationError, errorCode: '
      '$errorCode, frameType: $frameType, reason: "$reasonPhrase")';
}
