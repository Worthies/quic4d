import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// CRYPTO (type=0x06, RFC 9000 §19.6): carries TLS handshake bytes.
/// Functionally identical to a STREAM frame but implicit (no stream ID,
/// one independent byte-stream per encryption level) and always
/// present when there's handshake data to send — this is the frame
/// dart_quic's TLS handshake milestone builds directly on top of.
class CryptoFrame extends Frame {
  static const int wireType = 0x06;

  final int offset;
  final Uint8List data;

  const CryptoFrame({required this.offset, required this.data});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, offset);
    writeVarInt(sink, data.length);
    sink.add(data);
  }

  /// Decodes a CRYPTO frame starting at [offset] in [bytes], where
  /// `bytes[offset]` is expected to already be the 0x06 type byte.
  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a CRYPTO frame');
    }
    pos += 1;

    final streamOffset = readFrameVarInt(bytes, pos, 'CRYPTO offset');
    pos += streamOffset.bytesConsumed;

    final length = readFrameVarInt(bytes, pos, 'CRYPTO length');
    pos += length.bytesConsumed;

    if (pos + length.value > bytes.length) {
      throw const FrameFormatException(
          'CRYPTO frame data length exceeds available bytes');
    }
    final data = Uint8List.sublistView(bytes, pos, pos + length.value);
    pos += length.value;

    return FrameDecodeResult(
      CryptoFrame(offset: streamOffset.value, data: data),
      pos - offset,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is CryptoFrame &&
      other.offset == offset &&
      _bytesEqual(other.data, data);

  @override
  int get hashCode => Object.hash(offset, data.length);

  @override
  String toString() => 'CryptoFrame(offset: $offset, length: ${data.length})';
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
