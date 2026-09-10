import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// STOP_SENDING (type=0x05, RFC 9000 §19.5): asks the peer to stop
/// sending on a stream. Decode-only in dart_quic's scope (see
/// [ResetStreamFrame]'s doc comment — same rationale).
class StopSendingFrame extends Frame {
  static const int wireType = 0x05;

  final int streamId;
  final int applicationErrorCode;

  const StopSendingFrame({
    required this.streamId,
    required this.applicationErrorCode,
  });

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, streamId);
    writeVarInt(sink, applicationErrorCode);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a STOP_SENDING frame');
    }
    pos += 1;

    final streamId = readFrameVarInt(bytes, pos, 'STOP_SENDING stream ID');
    pos += streamId.bytesConsumed;
    final errorCode = readFrameVarInt(bytes, pos, 'STOP_SENDING error code');
    pos += errorCode.bytesConsumed;

    return FrameDecodeResult(
      StopSendingFrame(
        streamId: streamId.value,
        applicationErrorCode: errorCode.value,
      ),
      pos - offset,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is StopSendingFrame &&
      other.streamId == streamId &&
      other.applicationErrorCode == applicationErrorCode;

  @override
  int get hashCode => Object.hash(streamId, applicationErrorCode);

  @override
  String toString() => 'StopSendingFrame(streamId: $streamId, errorCode: '
      '$applicationErrorCode)';
}
