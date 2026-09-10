/// RFC 9002 §5: RTT estimation (smoothed_rtt / rttvar / min_rtt), the
/// input every other piece of loss detection (PTO, time-threshold loss)
/// depends on.
library;

/// RFC 9002 Appendix A.2: 333ms, used before any real RTT sample
/// exists.
const Duration kInitialRtt = Duration(milliseconds: 333);

/// RFC 9002 §6.1.2: minimum timer granularity assumed for threshold
/// calculations.
const Duration kGranularity = Duration(milliseconds: 1);

class RttEstimator {
  Duration latestRtt = Duration.zero;
  Duration smoothedRtt = kInitialRtt;
  Duration rttvar = Duration(microseconds: kInitialRtt.inMicroseconds ~/ 2);
  Duration? minRtt;
  bool _hasSample = false;

  /// RFC 9002 §5.3: updates the estimator with a new RTT sample
  /// ([rtt], the raw send-to-ack-receipt latency) and the peer-reported
  /// [ackDelay] from the ACK frame that produced it. [handshakeConfirmed]
  /// and [maxAckDelay] gate whether ackDelay is clamped, per RFC 9002
  /// §5.3's handshake-confirmed rule.
  void updateRtt({
    required Duration rtt,
    required Duration ackDelay,
    required bool handshakeConfirmed,
    required Duration maxAckDelay,
  }) {
    latestRtt = rtt;

    if (minRtt == null || rtt < minRtt!) {
      minRtt = rtt;
    }

    var effectiveAckDelay = ackDelay;
    if (handshakeConfirmed && effectiveAckDelay > maxAckDelay) {
      effectiveAckDelay = maxAckDelay;
    }

    var adjustedRtt = rtt;
    final min = minRtt!;
    if (rtt >= min + effectiveAckDelay) {
      adjustedRtt = rtt - effectiveAckDelay;
    }

    if (!_hasSample) {
      smoothedRtt = adjustedRtt;
      rttvar = Duration(microseconds: adjustedRtt.inMicroseconds ~/ 2);
      _hasSample = true;
      return;
    }

    final smoothedUs = smoothedRtt.inMicroseconds;
    final adjustedUs = adjustedRtt.inMicroseconds;
    final newSmoothedUs = ((7 * smoothedUs) + adjustedUs) ~/ 8;
    final rttvarSampleUs = (newSmoothedUs - adjustedUs).abs();
    final newRttvarUs = ((3 * rttvar.inMicroseconds) + rttvarSampleUs) ~/ 4;

    smoothedRtt = Duration(microseconds: newSmoothedUs);
    rttvar = Duration(microseconds: newRttvarUs);
  }

  /// RFC 9002 §6.2.1: `PTO = smoothed_rtt + max(4*rttvar, kGranularity)
  /// + max_ack_delay`. [maxAckDelay] must be [Duration.zero] for the
  /// Initial/Handshake packet number spaces (RFC 9002 §6.2.1: "the peer
  /// is expected to not delay these packets intentionally").
  Duration computePto(Duration maxAckDelay) {
    final fourRttvar = Duration(microseconds: rttvar.inMicroseconds * 4);
    final variationTerm = fourRttvar > kGranularity ? fourRttvar : kGranularity;
    return smoothedRtt + variationTerm + maxAckDelay;
  }
}
