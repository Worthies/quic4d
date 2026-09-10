/// RFC 9000 §19: the base [Frame] type plus the three frames with no
/// fields at all (PADDING, PING, HANDSHAKE_DONE) — every other frame
/// family lives in its own file (ack_frame.dart, stream_frame.dart,
/// etc.) alongside this one, all re-exported from frame_codec.dart's
/// central [decodeFrame] dispatcher.
library;

import 'dart:typed_data';

import '../varint.dart';

/// Thrown when frame bytes are malformed or truncated in a way that
/// can't be attributed to a more specific cause — callers that need to
/// distinguish "not enough bytes yet" (wait for more data) from "this
/// is simply invalid" (drop the packet / close the connection) should
/// catch this and inspect [message].
class FrameFormatException implements Exception {
  final String message;
  const FrameFormatException(this.message);

  @override
  String toString() => 'FrameFormatException: $message';
}

/// Common interface for every QUIC frame this library understands.
/// Subclasses each own their wire type constant and encode/decode logic
/// (decode is a static factory per subclass, dispatched centrally by
/// frame_codec.dart's [decodeFrame] once the type byte is read).
abstract class Frame {
  const Frame();

  /// Appends this frame's wire encoding (including its type byte) to
  /// [sink].
  void encode(BytesBuilder sink);
}

/// The result of decoding one frame out of a byte buffer: the decoded
/// [frame] and the [bytesConsumed] (including the type byte) so the
/// caller can advance to the next frame in the same packet payload.
class FrameDecodeResult {
  final Frame frame;
  final int bytesConsumed;
  const FrameDecodeResult(this.frame, this.bytesConsumed);
}

/// PADDING (type=0x00, RFC 9000 §19.1): a single zero byte, no fields.
/// Used to pad Initial packets to their minimum size and, on protected
/// packets, to obscure length-based traffic analysis.
class PaddingFrame extends Frame {
  const PaddingFrame();

  @override
  void encode(BytesBuilder sink) => sink.addByte(0x00);

  @override
  bool operator ==(Object other) => other is PaddingFrame;
  @override
  int get hashCode => (PaddingFrame).hashCode;
  @override
  String toString() => 'PaddingFrame()';
}

/// PING (type=0x01, RFC 9000 §19.2): no fields; only exists so its
/// containing packet elicits an ACK. dart_quic sends this on a timer to
/// hold the connection open against the peer's idle timeout — see
/// DESIGN.md's keepalive requirement.
class PingFrame extends Frame {
  const PingFrame();

  @override
  void encode(BytesBuilder sink) => sink.addByte(0x01);

  @override
  bool operator ==(Object other) => other is PingFrame;
  @override
  int get hashCode => (PingFrame).hashCode;
  @override
  String toString() => 'PingFrame()';
}

/// HANDSHAKE_DONE (type=0x1e, RFC 9000 §19.20): server-only, signals
/// handshake confirmation to the client. dart_quic (client-only, per
/// DESIGN.md) only ever decodes this, never sends it.
class HandshakeDoneFrame extends Frame {
  const HandshakeDoneFrame();

  @override
  void encode(BytesBuilder sink) => sink.addByte(0x1e);

  @override
  bool operator ==(Object other) => other is HandshakeDoneFrame;
  @override
  int get hashCode => (HandshakeDoneFrame).hashCode;
  @override
  String toString() => 'HandshakeDoneFrame()';
}

/// Reads a QUIC varint field out of [data] at [offset], wrapping
/// [VarIntFormatException] in the frame-decoding vocabulary so callers
/// only need to catch [FrameFormatException].
VarIntResult readFrameVarInt(Uint8List data, int offset, String fieldName) {
  try {
    return readVarInt(data, offset);
  } on VarIntFormatException catch (e) {
    throw FrameFormatException('$fieldName: ${e.message}');
  }
}
