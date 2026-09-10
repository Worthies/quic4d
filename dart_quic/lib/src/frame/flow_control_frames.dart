/// Flow-control and stream-limit frames (RFC 9000 §19.9-19.14): all
/// decode-only in dart_quic's scope. DESIGN.md's single-stream,
/// low-bandwidth commander link doesn't implement flow-control-aware
/// sending (it relies on the peer's generous default limits rather
/// than negotiating them), but a real quic-go peer sends these
/// unconditionally during normal operation, so they must still parse
/// correctly to avoid desyncing frame decoding for whatever follows.
library;

import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// MAX_DATA (type=0x10, RFC 9000 §19.9).
class MaxDataFrame extends Frame {
  static const int wireType = 0x10;
  final int maximumData;
  const MaxDataFrame({required this.maximumData});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, maximumData);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a MAX_DATA frame');
    }
    pos += 1;
    final value = readFrameVarInt(bytes, pos, 'MAX_DATA maximum data');
    pos += value.bytesConsumed;
    return FrameDecodeResult(
        MaxDataFrame(maximumData: value.value), pos - offset);
  }

  @override
  String toString() => 'MaxDataFrame(maximumData: $maximumData)';
}

/// MAX_STREAM_DATA (type=0x11, RFC 9000 §19.10).
class MaxStreamDataFrame extends Frame {
  static const int wireType = 0x11;
  final int streamId;
  final int maximumStreamData;
  const MaxStreamDataFrame(
      {required this.streamId, required this.maximumStreamData});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, streamId);
    writeVarInt(sink, maximumStreamData);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a MAX_STREAM_DATA frame');
    }
    pos += 1;
    final streamId = readFrameVarInt(bytes, pos, 'MAX_STREAM_DATA stream ID');
    pos += streamId.bytesConsumed;
    final max =
        readFrameVarInt(bytes, pos, 'MAX_STREAM_DATA maximum stream data');
    pos += max.bytesConsumed;
    return FrameDecodeResult(
      MaxStreamDataFrame(
          streamId: streamId.value, maximumStreamData: max.value),
      pos - offset,
    );
  }

  @override
  String toString() =>
      'MaxStreamDataFrame(streamId: $streamId, maximumStreamData: '
      '$maximumStreamData)';
}

/// MAX_STREAMS (type=0x12 bidi or 0x13 uni, RFC 9000 §19.11).
class MaxStreamsFrame extends Frame {
  static const int wireTypeBidi = 0x12;
  static const int wireTypeUni = 0x13;
  final bool bidirectional;
  final int maximumStreams;
  const MaxStreamsFrame(
      {required this.bidirectional, required this.maximumStreams});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(bidirectional ? wireTypeBidi : wireTypeUni);
    writeVarInt(sink, maximumStreams);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length) {
      throw const FrameFormatException('no bytes for MAX_STREAMS frame type');
    }
    final type = bytes[pos];
    if (type != wireTypeBidi && type != wireTypeUni) {
      throw const FrameFormatException('not a MAX_STREAMS frame');
    }
    pos += 1;
    final max = readFrameVarInt(bytes, pos, 'MAX_STREAMS maximum streams');
    pos += max.bytesConsumed;
    return FrameDecodeResult(
      MaxStreamsFrame(
          bidirectional: type == wireTypeBidi, maximumStreams: max.value),
      pos - offset,
    );
  }

  @override
  String toString() =>
      'MaxStreamsFrame(bidirectional: $bidirectional, maximumStreams: '
      '$maximumStreams)';
}

/// DATA_BLOCKED (type=0x14, RFC 9000 §19.12).
class DataBlockedFrame extends Frame {
  static const int wireType = 0x14;
  final int maximumData;
  const DataBlockedFrame({required this.maximumData});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, maximumData);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a DATA_BLOCKED frame');
    }
    pos += 1;
    final value = readFrameVarInt(bytes, pos, 'DATA_BLOCKED maximum data');
    pos += value.bytesConsumed;
    return FrameDecodeResult(
        DataBlockedFrame(maximumData: value.value), pos - offset);
  }

  @override
  String toString() => 'DataBlockedFrame(maximumData: $maximumData)';
}

/// STREAM_DATA_BLOCKED (type=0x15, RFC 9000 §19.13).
class StreamDataBlockedFrame extends Frame {
  static const int wireType = 0x15;
  final int streamId;
  final int maximumStreamData;
  const StreamDataBlockedFrame(
      {required this.streamId, required this.maximumStreamData});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, streamId);
    writeVarInt(sink, maximumStreamData);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a STREAM_DATA_BLOCKED frame');
    }
    pos += 1;
    final streamId =
        readFrameVarInt(bytes, pos, 'STREAM_DATA_BLOCKED stream ID');
    pos += streamId.bytesConsumed;
    final max =
        readFrameVarInt(bytes, pos, 'STREAM_DATA_BLOCKED maximum stream data');
    pos += max.bytesConsumed;
    return FrameDecodeResult(
      StreamDataBlockedFrame(
          streamId: streamId.value, maximumStreamData: max.value),
      pos - offset,
    );
  }

  @override
  String toString() =>
      'StreamDataBlockedFrame(streamId: $streamId, maximumStreamData: '
      '$maximumStreamData)';
}

/// STREAMS_BLOCKED (type=0x16 bidi or 0x17 uni, RFC 9000 §19.14).
class StreamsBlockedFrame extends Frame {
  static const int wireTypeBidi = 0x16;
  static const int wireTypeUni = 0x17;
  final bool bidirectional;
  final int maximumStreams;
  const StreamsBlockedFrame(
      {required this.bidirectional, required this.maximumStreams});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(bidirectional ? wireTypeBidi : wireTypeUni);
    writeVarInt(sink, maximumStreams);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length) {
      throw const FrameFormatException(
          'no bytes for STREAMS_BLOCKED frame type');
    }
    final type = bytes[pos];
    if (type != wireTypeBidi && type != wireTypeUni) {
      throw const FrameFormatException('not a STREAMS_BLOCKED frame');
    }
    pos += 1;
    final max = readFrameVarInt(bytes, pos, 'STREAMS_BLOCKED maximum streams');
    pos += max.bytesConsumed;
    return FrameDecodeResult(
      StreamsBlockedFrame(
          bidirectional: type == wireTypeBidi, maximumStreams: max.value),
      pos - offset,
    );
  }

  @override
  String toString() =>
      'StreamsBlockedFrame(bidirectional: $bidirectional, maximumStreams: '
      '$maximumStreams)';
}

/// RETIRE_CONNECTION_ID (type=0x19, RFC 9000 §19.16).
class RetireConnectionIdFrame extends Frame {
  static const int wireType = 0x19;
  final int sequenceNumber;
  const RetireConnectionIdFrame({required this.sequenceNumber});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, sequenceNumber);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a RETIRE_CONNECTION_ID frame');
    }
    pos += 1;
    final seq =
        readFrameVarInt(bytes, pos, 'RETIRE_CONNECTION_ID sequence number');
    pos += seq.bytesConsumed;
    return FrameDecodeResult(
        RetireConnectionIdFrame(sequenceNumber: seq.value), pos - offset);
  }

  @override
  String toString() =>
      'RetireConnectionIdFrame(sequenceNumber: $sequenceNumber)';
}

/// PATH_CHALLENGE (type=0x1a, RFC 9000 §19.17): fixed 8-byte payload.
class PathChallengeFrame extends Frame {
  static const int wireType = 0x1a;
  final Uint8List data;
  const PathChallengeFrame({required this.data});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    sink.add(data);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a PATH_CHALLENGE frame');
    }
    pos += 1;
    if (pos + 8 > bytes.length) {
      throw const FrameFormatException('PATH_CHALLENGE frame truncated');
    }
    final data = Uint8List.sublistView(bytes, pos, pos + 8);
    pos += 8;
    return FrameDecodeResult(PathChallengeFrame(data: data), pos - offset);
  }

  @override
  String toString() => 'PathChallengeFrame()';
}

/// PATH_RESPONSE (type=0x1b, RFC 9000 §19.18): fixed 8-byte payload,
/// same wire shape as PATH_CHALLENGE.
class PathResponseFrame extends Frame {
  static const int wireType = 0x1b;
  final Uint8List data;
  const PathResponseFrame({required this.data});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    sink.add(data);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a PATH_RESPONSE frame');
    }
    pos += 1;
    if (pos + 8 > bytes.length) {
      throw const FrameFormatException('PATH_RESPONSE frame truncated');
    }
    final data = Uint8List.sublistView(bytes, pos, pos + 8);
    pos += 8;
    return FrameDecodeResult(PathResponseFrame(data: data), pos - offset);
  }

  @override
  String toString() => 'PathResponseFrame()';
}
