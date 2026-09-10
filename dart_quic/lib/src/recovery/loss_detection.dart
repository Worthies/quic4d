/// RFC 9002 §6 / Appendix A: per-packet-number-space loss detection
/// (packet-threshold + time-threshold) and PTO scheduling. This is a
/// deliberately simplified implementation per DESIGN.md's scope
/// ("correct-but-unsophisticated" -- commander is a low-bandwidth
/// chat/control link, not a throughput-sensitive bulk transfer): it
/// implements the RFC's core algorithm faithfully but skips ECN
/// handling and persistent-congestion detection (both explicitly out
/// of scope).
library;

import 'rtt_estimator.dart';
import 'sent_packet.dart';

/// RFC 9002 Appendix A.2: reordering tolerance before packet-threshold
/// loss kicks in.
const int kPacketThreshold = 3;

/// RFC 9002 §6.1.2: time-threshold multiplier on the larger of
/// latest_rtt/smoothed_rtt.
const double kTimeThresholdMultiplier = 9 / 8;

class LostPacket {
  final SentPacket packet;
  const LostPacket(this.packet);
}

class AckResult {
  final List<SentPacket> newlyAcked;
  final List<LostPacket> newlyLost;
  const AckResult({required this.newlyAcked, required this.newlyLost});
}

/// Tracks in-flight packets and detects loss for exactly one QUIC
/// packet number space (Initial, Handshake, or ApplicationData -- RFC
/// 9002 §6: "Loss detection is separate per packet number space").
class LossDetector {
  final Map<int, SentPacket> _sentPackets = {};
  int? largestAckedPacket;
  DateTime? lossTime;
  DateTime? timeOfLastAckElicitingPacket;

  final RttEstimator rtt;
  int ptoCount = 0;

  LossDetector(this.rtt);

  bool get hasAckElicitingInFlight =>
      _sentPackets.values.any((p) => p.ackEliciting && p.inFlight);

  int get bytesInFlight => _sentPackets.values
      .where((p) => p.inFlight)
      .fold(0, (sum, p) => sum + p.sentBytes);

  /// RFC 9002 Appendix A.5: records that a packet was just sent.
  void onPacketSent(SentPacket packet) {
    _sentPackets[packet.packetNumber] = packet;
    if (packet.inFlight && packet.ackEliciting) {
      timeOfLastAckElicitingPacket = packet.timeSent;
    }
  }

  /// RFC 9002 Appendix A.7/A.10: processes a received ACK's
  /// acknowledged packet-number list, updating RTT (via [rtt]) when
  /// applicable, then runs time-threshold loss detection. [now] is
  /// injectable for deterministic tests.
  AckResult onAckReceived({
    required List<int> acknowledgedPacketNumbers,
    required Duration ackDelay,
    required bool handshakeConfirmed,
    required Duration maxAckDelay,
    required DateTime now,
  }) {
    if (acknowledgedPacketNumbers.isEmpty) {
      return const AckResult(newlyAcked: [], newlyLost: []);
    }
    final largestInThisAck =
        acknowledgedPacketNumbers.reduce((a, b) => a > b ? a : b);
    largestAckedPacket = largestAckedPacket == null
        ? largestInThisAck
        : (largestAckedPacket! > largestInThisAck
            ? largestAckedPacket!
            : largestInThisAck);

    final newlyAcked = <SentPacket>[];
    for (final pn in acknowledgedPacketNumbers) {
      final packet = _sentPackets.remove(pn);
      if (packet != null) {
        newlyAcked.add(packet);
      }
    }
    if (newlyAcked.isEmpty) {
      return const AckResult(newlyAcked: [], newlyLost: []);
    }

    final largestAckedInFlight =
        newlyAcked.where((p) => p.packetNumber == largestInThisAck).toList();
    if (largestAckedInFlight.isNotEmpty &&
        newlyAcked.any((p) => p.ackEliciting)) {
      final sample = largestAckedInFlight.first;
      rtt.updateRtt(
        rtt: now.difference(sample.timeSent),
        ackDelay: ackDelay,
        handshakeConfirmed: handshakeConfirmed,
        maxAckDelay: maxAckDelay,
      );
    }

    final newlyLost = _detectAndRemoveLostPackets(now);
    return AckResult(newlyAcked: newlyAcked, newlyLost: newlyLost);
  }

  /// RFC 9002 Appendix A.10.
  List<LostPacket> _detectAndRemoveLostPackets(DateTime now) {
    if (largestAckedPacket == null) return const [];
    lossTime = null;
    final lostPackets = <LostPacket>[];

    final rttForThreshold =
        rtt.latestRtt > rtt.smoothedRtt ? rtt.latestRtt : rtt.smoothedRtt;
    var lossDelayUs =
        (rttForThreshold.inMicroseconds * kTimeThresholdMultiplier).round();
    final granularityUs = kGranularity.inMicroseconds;
    if (lossDelayUs < granularityUs) lossDelayUs = granularityUs;
    final lossDelay = Duration(microseconds: lossDelayUs);
    final lostSendTime = now.subtract(lossDelay);

    final toRemove = <int>[];
    for (final unacked in _sentPackets.values) {
      if (unacked.packetNumber > largestAckedPacket!) continue;

      final byTime = !unacked.timeSent.isAfter(lostSendTime);
      final byCount =
          largestAckedPacket! >= unacked.packetNumber + kPacketThreshold;
      if (byTime || byCount) {
        toRemove.add(unacked.packetNumber);
        lostPackets.add(LostPacket(unacked));
      } else {
        final candidateLossTime = unacked.timeSent.add(lossDelay);
        if (lossTime == null || candidateLossTime.isBefore(lossTime!)) {
          lossTime = candidateLossTime;
        }
      }
    }
    for (final pn in toRemove) {
      _sentPackets.remove(pn);
    }
    return lostPackets;
  }

  /// RFC 9002 Appendix A.9: forces a time-threshold loss check (used
  /// when the loss detection timer itself fires, rather than in
  /// response to a new ACK).
  List<LostPacket> detectLossOnTimeout(DateTime now) =>
      _detectAndRemoveLostPackets(now);

  /// RFC 9002 Appendix A.11: drops all tracked state for this space
  /// (Initial/Handshake key discard).
  void discard() {
    _sentPackets.clear();
    timeOfLastAckElicitingPacket = null;
    lossTime = null;
    ptoCount = 0;
  }
}
