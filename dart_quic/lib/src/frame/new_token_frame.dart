import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// NEW_TOKEN (type=0x07, RFC 9000 §19.7): server-only, provides a token
/// for a future 0-RTT-capable connection. dart_quic doesn't implement
/// 0-RTT (see DESIGN.md), so this is decode-only — the token itself is
/// kept but never used or persisted; parsing it correctly still matters
/// so a real server's NEW_TOKEN frame doesn't break decoding of
/// whatever frame follows it in the same packet.
class NewTokenFrame extends Frame {
  static const int wireType = 0x07;

  final Uint8List token;

  const NewTokenFrame({required this.token});

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, token.length);
    sink.add(token);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a NEW_TOKEN frame');
    }
    pos += 1;

    final length = readFrameVarInt(bytes, pos, 'NEW_TOKEN length');
    pos += length.bytesConsumed;

    if (pos + length.value > bytes.length) {
      throw const FrameFormatException(
          'NEW_TOKEN token length exceeds available bytes');
    }
    final token = Uint8List.sublistView(bytes, pos, pos + length.value);
    pos += length.value;

    return FrameDecodeResult(NewTokenFrame(token: token), pos - offset);
  }

  @override
  bool operator ==(Object other) =>
      other is NewTokenFrame && _bytesEqual(other.token, token);

  @override
  int get hashCode => token.length;

  @override
  String toString() => 'NewTokenFrame(length: ${token.length})';
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
