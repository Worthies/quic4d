/// RFC 9000 §16 variable-length integer encoding.
///
/// The two most significant bits of the first byte encode the length
/// (1/2/4/8 bytes), leaving 6/14/30/62 usable bits. This is QUIC's only
/// integer encoding for packet numbers' length hints, frame type/length
/// fields, stream IDs, offsets, etc — every higher-level piece of this
/// library depends on it being correct before anything else can work.
library;

import 'dart:typed_data';

/// Maximum value representable in a QUIC varint (2^62 - 1).
const int maxVarInt = 0x3FFFFFFFFFFFFFFF;

/// Thrown when encoding a value that doesn't fit in a QUIC varint, or
/// when decoding malformed/truncated varint bytes.
class VarIntFormatException implements Exception {
  final String message;
  const VarIntFormatException(this.message);

  @override
  String toString() => 'VarIntFormatException: $message';
}

/// Returns the number of bytes [value] will occupy when varint-encoded.
int varIntLength(int value) {
  if (value < 0 || value > maxVarInt) {
    throw VarIntFormatException(
        'value $value out of range for a QUIC varint (0..$maxVarInt)');
  }
  if (value <= 0x3F) return 1;
  if (value <= 0x3FFF) return 2;
  if (value <= 0x3FFFFFFF) return 4;
  return 8;
}

/// Encodes [value] as a QUIC variable-length integer and appends it to
/// [sink].
void writeVarInt(BytesBuilder sink, int value) {
  final len = varIntLength(value);
  switch (len) {
    case 1:
      sink.addByte(value);
      return;
    case 2:
      final buf = ByteData(2)..setUint16(0, value | 0x4000);
      sink.add(buf.buffer.asUint8List());
      return;
    case 4:
      final buf = ByteData(4)..setUint32(0, value | 0x80000000);
      sink.add(buf.buffer.asUint8List());
      return;
    default:
      // 8-byte case: the top two bits (0xC0) go into the MSB of a 64-bit
      // field. `value` here is always < 2^62, so it never collides with
      // those bits.
      final buf = ByteData(8)..setUint64(0, value | 0xC000000000000000);
      sink.add(buf.buffer.asUint8List());
  }
}

/// Convenience wrapper: returns the varint encoding of [value] as its own
/// [Uint8List] instead of writing into a caller-supplied sink.
Uint8List encodeVarInt(int value) {
  final sink = BytesBuilder();
  writeVarInt(sink, value);
  return sink.toBytes();
}

/// The result of decoding a single varint out of a byte buffer: the
/// decoded [value] and the [bytesConsumed] so the caller can advance its
/// read cursor.
class VarIntResult {
  final int value;
  final int bytesConsumed;
  const VarIntResult(this.value, this.bytesConsumed);
}

/// Decodes a QUIC varint starting at [offset] in [data].
///
/// Throws [VarIntFormatException] if [data] is too short to contain the
/// full encoded value (the length is determined by the first byte's top
/// two bits, per RFC 9000 §16 Table 4).
VarIntResult readVarInt(Uint8List data, int offset) {
  if (offset >= data.length) {
    throw const VarIntFormatException('no bytes remaining to decode a varint');
  }
  final first = data[offset];
  final lengthBits = first >> 6;
  final length = 1 << lengthBits; // 0b00->1, 0b01->2, 0b10->4, 0b11->8

  if (offset + length > data.length) {
    throw VarIntFormatException(
        'truncated varint: need $length bytes at offset $offset, only '
        '${data.length - offset} available');
  }

  final view = ByteData.sublistView(data, offset, offset + length);
  int value;
  switch (length) {
    case 1:
      value = first & 0x3F;
      break;
    case 2:
      value = view.getUint16(0) & 0x3FFF;
      break;
    case 4:
      value = view.getUint32(0) & 0x3FFFFFFF;
      break;
    default:
      value = view.getUint64(0) & 0x3FFFFFFFFFFFFFFF;
  }
  return VarIntResult(value, length);
}
