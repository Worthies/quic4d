import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// NEW_CONNECTION_ID (type=0x18, RFC 9000 §19.15): offers an
/// alternative connection ID for migration. dart_quic doesn't implement
/// connection migration (DESIGN.md), so this is decode-only — a real
/// quic-go peer sends one during the handshake regardless, and it must
/// parse cleanly so it doesn't desync frame decoding for whatever
/// follows it in the same packet.
class NewConnectionIdFrame extends Frame {
  static const int wireType = 0x18;

  final int sequenceNumber;
  final int retirePriorTo;
  final Uint8List connectionId;
  final Uint8List statelessResetToken;

  const NewConnectionIdFrame({
    required this.sequenceNumber,
    required this.retirePriorTo,
    required this.connectionId,
    required this.statelessResetToken,
  });

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(wireType);
    writeVarInt(sink, sequenceNumber);
    writeVarInt(sink, retirePriorTo);
    sink.addByte(connectionId.length);
    sink.add(connectionId);
    sink.add(statelessResetToken);
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length || bytes[pos] != wireType) {
      throw const FrameFormatException('not a NEW_CONNECTION_ID frame');
    }
    pos += 1;

    final seq =
        readFrameVarInt(bytes, pos, 'NEW_CONNECTION_ID sequence number');
    pos += seq.bytesConsumed;
    final retirePriorTo =
        readFrameVarInt(bytes, pos, 'NEW_CONNECTION_ID retire prior to');
    pos += retirePriorTo.bytesConsumed;

    if (pos >= bytes.length) {
      throw const FrameFormatException(
          'NEW_CONNECTION_ID missing connection ID length');
    }
    final cidLength = bytes[pos];
    pos += 1;
    if (cidLength < 1 || cidLength > 20) {
      throw const FrameFormatException(
          'NEW_CONNECTION_ID connection ID length out of range (1..20)');
    }

    const tokenLength = 16; // 128-bit stateless reset token
    if (pos + cidLength + tokenLength > bytes.length) {
      throw const FrameFormatException(
          'NEW_CONNECTION_ID frame truncated before connection ID/token');
    }
    final cid = Uint8List.sublistView(bytes, pos, pos + cidLength);
    pos += cidLength;
    final token = Uint8List.sublistView(bytes, pos, pos + tokenLength);
    pos += tokenLength;

    return FrameDecodeResult(
      NewConnectionIdFrame(
        sequenceNumber: seq.value,
        retirePriorTo: retirePriorTo.value,
        connectionId: cid,
        statelessResetToken: token,
      ),
      pos - offset,
    );
  }

  @override
  String toString() =>
      'NewConnectionIdFrame(seq: $sequenceNumber, retirePriorTo: '
      '$retirePriorTo, cidLength: ${connectionId.length})';
}
