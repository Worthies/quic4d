import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// STREAM (type=0x08..0x0f, RFC 9000 §19.8): the frame that carries the
/// single bidirectional stream's data in DESIGN.md's scope. The low 3
/// bits of the type byte are flags (OFF/LEN/FIN), not a separate field
/// — [StreamFrame] always encodes with OFF and LEN set (offset and
/// explicit length are always included) since dart_quic never needs
/// the "extends to end of packet" length omission this milestone's
/// scope doesn't require optimizing for.
class StreamFrame extends Frame {
  static const int _baseType = 0x08;
  static const int _finBit = 0x01;
  static const int _lenBit = 0x02;
  static const int _offBit = 0x04;

  final int streamId;
  final int offset;
  final Uint8List data;
  final bool fin;

  const StreamFrame({
    required this.streamId,
    required this.offset,
    required this.data,
    this.fin = false,
  });

  @override
  void encode(BytesBuilder sink) {
    var type = _baseType | _lenBit;
    if (offset != 0) type |= _offBit;
    if (fin) type |= _finBit;

    sink.addByte(type);
    writeVarInt(sink, streamId);
    if (offset != 0) writeVarInt(sink, offset);
    writeVarInt(sink, data.length);
    sink.add(data);
  }

  /// Decodes a STREAM frame starting at [offset] in [bytes]. `offset`
  /// here is the byte-buffer position parameter (shadowing the field
  /// name in this static context is fine — no instance to confuse it
  /// with).
  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length) {
      throw const FrameFormatException('no bytes for STREAM frame type');
    }
    final type = bytes[pos];
    if (type < _baseType || type > _baseType + 0x07) {
      throw const FrameFormatException('not a STREAM frame');
    }
    pos += 1;

    final hasOffset = (type & _offBit) != 0;
    final hasLength = (type & _lenBit) != 0;
    final fin = (type & _finBit) != 0;

    final streamId = readFrameVarInt(bytes, pos, 'STREAM stream ID');
    pos += streamId.bytesConsumed;

    var streamOffset = 0;
    if (hasOffset) {
      final result = readFrameVarInt(bytes, pos, 'STREAM offset');
      streamOffset = result.value;
      pos += result.bytesConsumed;
    }

    int dataLength;
    if (hasLength) {
      final result = readFrameVarInt(bytes, pos, 'STREAM length');
      dataLength = result.value;
      pos += result.bytesConsumed;
    } else {
      // No explicit length: Stream Data extends to the end of the
      // packet payload (`bytes`, which callers pass as exactly the
      // packet's remaining payload for this reason).
      dataLength = bytes.length - pos;
    }

    if (pos + dataLength > bytes.length) {
      throw const FrameFormatException(
          'STREAM frame data length exceeds available bytes');
    }
    final data = Uint8List.sublistView(bytes, pos, pos + dataLength);
    pos += dataLength;

    return FrameDecodeResult(
      StreamFrame(
        streamId: streamId.value,
        offset: streamOffset,
        data: data,
        fin: fin,
      ),
      pos - offset,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is StreamFrame &&
      other.streamId == streamId &&
      other.offset == offset &&
      other.fin == fin &&
      _bytesEqual(other.data, data);

  @override
  int get hashCode => Object.hash(streamId, offset, fin, data.length);

  @override
  String toString() =>
      'StreamFrame(streamId: $streamId, offset: $offset, length: '
      '${data.length}, fin: $fin)';
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
