import 'dart:typed_data';

import 'ack_frame.dart';
import 'connection_close_frame.dart';
import 'crypto_frame.dart';
import 'flow_control_frames.dart';
import 'frame.dart';
import 'new_connection_id_frame.dart';
import 'new_token_frame.dart';
import 'reset_stream_frame.dart';
import 'stop_sending_frame.dart';
import 'stream_frame.dart';

export 'ack_frame.dart';
export 'connection_close_frame.dart';
export 'crypto_frame.dart';
export 'flow_control_frames.dart';
export 'frame.dart';
export 'new_connection_id_frame.dart';
export 'new_token_frame.dart';
export 'reset_stream_frame.dart';
export 'stop_sending_frame.dart';
export 'stream_frame.dart';

/// Decodes a single frame starting at [offset] in [bytes] (a packet's
/// decrypted payload), dispatching on the type byte per RFC 9000 §19's
/// Table 3. This is dart_quic's one central point of frame-type
/// knowledge — every frame family the library understands (including
/// ones it never sends, like NEW_TOKEN or HANDSHAKE_DONE) is wired in
/// here so decoding a real quic-go packet's payload never desyncs on
/// an unrecognized-but-valid frame type.
///
/// Throws [FrameFormatException] for a type byte with no known frame
/// mapping, or if the specific frame's decoder finds malformed/
/// truncated data.
FrameDecodeResult decodeFrame(Uint8List bytes, int offset) {
  if (offset >= bytes.length) {
    throw const FrameFormatException('no bytes remaining to decode a frame');
  }
  final type = bytes[offset];

  if (type == 0x00) {
    return FrameDecodeResult(const PaddingFrame(), 1);
  }
  if (type == 0x01) {
    return FrameDecodeResult(const PingFrame(), 1);
  }
  if (type == AckFrame.wireTypeNoEcn || type == AckFrame.wireTypeWithEcn) {
    return AckFrame.decode(bytes, offset);
  }
  if (type == ResetStreamFrame.wireType) {
    return ResetStreamFrame.decode(bytes, offset);
  }
  if (type == StopSendingFrame.wireType) {
    return StopSendingFrame.decode(bytes, offset);
  }
  if (type == CryptoFrame.wireType) {
    return CryptoFrame.decode(bytes, offset);
  }
  if (type == NewTokenFrame.wireType) {
    return NewTokenFrame.decode(bytes, offset);
  }
  if (type >= 0x08 && type <= 0x0f) {
    return StreamFrame.decode(bytes, offset);
  }
  if (type == MaxDataFrame.wireType) {
    return MaxDataFrame.decode(bytes, offset);
  }
  if (type == MaxStreamDataFrame.wireType) {
    return MaxStreamDataFrame.decode(bytes, offset);
  }
  if (type == MaxStreamsFrame.wireTypeBidi ||
      type == MaxStreamsFrame.wireTypeUni) {
    return MaxStreamsFrame.decode(bytes, offset);
  }
  if (type == DataBlockedFrame.wireType) {
    return DataBlockedFrame.decode(bytes, offset);
  }
  if (type == StreamDataBlockedFrame.wireType) {
    return StreamDataBlockedFrame.decode(bytes, offset);
  }
  if (type == StreamsBlockedFrame.wireTypeBidi ||
      type == StreamsBlockedFrame.wireTypeUni) {
    return StreamsBlockedFrame.decode(bytes, offset);
  }
  if (type == NewConnectionIdFrame.wireType) {
    return NewConnectionIdFrame.decode(bytes, offset);
  }
  if (type == RetireConnectionIdFrame.wireType) {
    return RetireConnectionIdFrame.decode(bytes, offset);
  }
  if (type == PathChallengeFrame.wireType) {
    return PathChallengeFrame.decode(bytes, offset);
  }
  if (type == PathResponseFrame.wireType) {
    return PathResponseFrame.decode(bytes, offset);
  }
  if (type == ConnectionCloseFrame.wireTypeTransport ||
      type == ConnectionCloseFrame.wireTypeApplication) {
    return ConnectionCloseFrame.decode(bytes, offset);
  }
  if (type == 0x1e) {
    return FrameDecodeResult(const HandshakeDoneFrame(), 1);
  }

  throw FrameFormatException(
      'unknown frame type 0x${type.toRadixString(16)} at offset $offset');
}

/// Decodes every frame in a packet's full payload, in order. A QUIC
/// packet payload is exactly a sequence of frames with no outer
/// length/count prefix (RFC 9000 §12.4), so this simply keeps calling
/// [decodeFrame] until the payload is exhausted.
List<Frame> decodeAllFrames(Uint8List payload) {
  final frames = <Frame>[];
  var pos = 0;
  while (pos < payload.length) {
    final result = decodeFrame(payload, pos);
    frames.add(result.frame);
    pos += result.bytesConsumed;
  }
  return frames;
}
