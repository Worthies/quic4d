import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// RESET_STREAM (type=0x04, RFC 9000 §19.4): abruptly terminates the
/// sending side of a stream. DESIGN.md's single-stream model doesn't
/// use this to originate a reset, but must be able to decode one if
/// the peer ever sends it (e.g. server-side error abandoning the
/// stream) so the connection can react instead of failing to parse.
class ResetStreamFrame extends Frame {
  static const int wireType = 0x04;

  final int streamId;
  final int applicationErrorCode;
  final int finalSize;

  const ResetStreamFrame({
    required this.streamId,
    required this.applicationErrorCode,
    required this.finalSize,
  });

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, streamId);
    writeVarInt(sink, applicationErrorCode);
    writeVarInt(sink, finalSize);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a RESET_STREAM frame');
    }
    pos += 1;

    final streamId = readFrameVarInt(bytes, pos, 'RESET_STREAM stream ID');
    pos += streamId.bytesConsumed;
    final errorCode = readFrameVarInt(bytes, pos, 'RESET_STREAM error code');
    pos += errorCode.bytesConsumed;
    final finalSize = readFrameVarInt(bytes, pos, 'RESET_STREAM final size');
    pos += finalSize.bytesConsumed;

    return FrameDecodeResult(
      ResetStreamFrame(
        streamId: streamId.value,
        applicationErrorCode: errorCode.value,
        finalSize: finalSize.value,
      ),
      pos - offset,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is ResetStreamFrame &&
      other.streamId == streamId &&
      other.applicationErrorCode == applicationErrorCode &&
      other.finalSize == finalSize;

  @override
  int get hashCode => Object.hash(streamId, applicationErrorCode, finalSize);

  @override
  String toString() => 'ResetStreamFrame(streamId: $streamId, errorCode: '
      '$applicationErrorCode, finalSize: $finalSize)';
}
