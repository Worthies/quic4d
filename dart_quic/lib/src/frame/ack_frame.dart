import 'dart:typed_data';

import '../varint.dart';
import 'frame.dart';

/// A single ACK Range as it appears on the wire (RFC 9000 §19.3.1):
/// [gap] contiguous unacknowledged packets, then [ackRangeLength]
/// contiguous acknowledged packets, both counting down from the
/// previous range's smallest acknowledged packet number.
class AckRange {
  final int gap;
  final int ackRangeLength;
  const AckRange({required this.gap, required this.ackRangeLength});

  @override
  bool operator ==(Object other) =>
      other is AckRange &&
      other.gap == gap &&
      other.ackRangeLength == ackRangeLength;
  @override
  int get hashCode => Object.hash(gap, ackRangeLength);
  @override
  String toString() => 'AckRange(gap: $gap, ackRangeLength: $ackRangeLength)';
}

/// The three ECN counts (RFC 9000 §19.3.2), present only on ACK frames
/// of wire type 0x03.
class EcnCounts {
  final int ect0;
  final int ect1;
  final int ecnCe;
  const EcnCounts(
      {required this.ect0, required this.ect1, required this.ecnCe});

  @override
  bool operator ==(Object other) =>
      other is EcnCounts &&
      other.ect0 == ect0 &&
      other.ect1 == ect1 &&
      other.ecnCe == ecnCe;
  @override
  int get hashCode => Object.hash(ect0, ect1, ecnCe);
}

/// ACK (type=0x02 or 0x03, RFC 9000 §19.3): acknowledges received
/// packets. dart_quic's simplified loss-detection milestone consumes
/// this to learn which of its own sent packets the peer has seen;
/// [ecnCounts] is decoded (so a 0x03 frame parses correctly) but not
/// acted on, per DESIGN.md's explicit exclusion of ECN.
class AckFrame extends Frame {
  static const int wireTypeNoEcn = 0x02;
  static const int wireTypeWithEcn = 0x03;

  final int largestAcknowledged;
  final int ackDelay;
  final int firstAckRange;
  final List<AckRange> ackRanges;
  final EcnCounts? ecnCounts;

  const AckFrame({
    required this.largestAcknowledged,
    required this.ackDelay,
    required this.firstAckRange,
    this.ackRanges = const [],
    this.ecnCounts,
  });

  @override
  void encode(BytesBuilder sink) {
    sink.addByte(ecnCounts != null ? wireTypeWithEcn : wireTypeNoEcn);
    writeVarInt(sink, largestAcknowledged);
    writeVarInt(sink, ackDelay);
    writeVarInt(sink, ackRanges.length);
    writeVarInt(sink, firstAckRange);
    for (final range in ackRanges) {
      writeVarInt(sink, range.gap);
      writeVarInt(sink, range.ackRangeLength);
    }
    final ecn = ecnCounts;
    if (ecn != null) {
      writeVarInt(sink, ecn.ect0);
      writeVarInt(sink, ecn.ect1);
      writeVarInt(sink, ecn.ecnCe);
    }
  }

  static FrameDecodeResult decode(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length) {
      throw const FrameFormatException('no bytes for ACK frame type');
    }
    final type = bytes[pos];
    if (type != wireTypeNoEcn && type != wireTypeWithEcn) {
      throw const FrameFormatException('not an ACK frame');
    }
    pos += 1;

    final largest = readFrameVarInt(bytes, pos, 'ACK largest acknowledged');
    pos += largest.bytesConsumed;

    final delay = readFrameVarInt(bytes, pos, 'ACK delay');
    pos += delay.bytesConsumed;

    final rangeCount = readFrameVarInt(bytes, pos, 'ACK range count');
    pos += rangeCount.bytesConsumed;

    final firstRange = readFrameVarInt(bytes, pos, 'ACK first ack range');
    pos += firstRange.bytesConsumed;

    final ranges = <AckRange>[];
    for (var i = 0; i < rangeCount.value; i++) {
      final gap = readFrameVarInt(bytes, pos, 'ACK gap');
      pos += gap.bytesConsumed;
      final length = readFrameVarInt(bytes, pos, 'ACK range length');
      pos += length.bytesConsumed;
      ranges.add(AckRange(gap: gap.value, ackRangeLength: length.value));
    }

    EcnCounts? ecn;
    if (type == wireTypeWithEcn) {
      final ect0 = readFrameVarInt(bytes, pos, 'ACK ECT0 count');
      pos += ect0.bytesConsumed;
      final ect1 = readFrameVarInt(bytes, pos, 'ACK ECT1 count');
      pos += ect1.bytesConsumed;
      final ecnCe = readFrameVarInt(bytes, pos, 'ACK ECN-CE count');
      pos += ecnCe.bytesConsumed;
      ecn = EcnCounts(ect0: ect0.value, ect1: ect1.value, ecnCe: ecnCe.value);
    }

    return FrameDecodeResult(
      AckFrame(
        largestAcknowledged: largest.value,
        ackDelay: delay.value,
        firstAckRange: firstRange.value,
        ackRanges: ranges,
        ecnCounts: ecn,
      ),
      pos - offset,
    );
  }

  /// Every packet number this ACK frame covers, largest first — a
  /// convenience for loss-detection code rather than something encoded
  /// directly on the wire (which uses the more compact gap/range-length
  /// scheme instead).
  List<int> acknowledgedPacketNumbers() {
    final result = <int>[];
    var largest = largestAcknowledged;
    var rangeLength = firstAckRange;
    result.addAll(_range(largest, rangeLength));

    var smallest = largest - rangeLength;
    for (final range in ackRanges) {
      largest = smallest - range.gap - 2;
      rangeLength = range.ackRangeLength;
      result.addAll(_range(largest, rangeLength));
      smallest = largest - rangeLength;
    }
    return result;
  }

  static List<int> _range(int largest, int rangeLength) {
    final smallest = largest - rangeLength;
    return [for (var pn = largest; pn >= smallest; pn--) pn];
  }

  @override
  bool operator ==(Object other) =>
      other is AckFrame &&
      other.largestAcknowledged == largestAcknowledged &&
      other.ackDelay == ackDelay &&
      other.firstAckRange == firstAckRange &&
      _listEqual(other.ackRanges, ackRanges) &&
      other.ecnCounts == ecnCounts;

  @override
  int get hashCode =>
      Object.hash(largestAcknowledged, ackDelay, firstAckRange, ecnCounts);

  @override
  String toString() =>
      'AckFrame(largest: $largestAcknowledged, delay: $ackDelay, '
      'firstRange: $firstAckRange, ranges: $ackRanges)';
}

bool _listEqual(List<AckRange> a, List<AckRange> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
