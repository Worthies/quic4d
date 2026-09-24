/// RFC 9002 §7 / Appendix B: a simplified NewReno congestion
/// controller. Per DESIGN.md's scope, this implements slow start,
/// recovery, and congestion avoidance faithfully but skips ECN-driven
/// congestion events and persistent-congestion window reset (both
/// explicitly out of scope for commander's low-bandwidth link).
library;

import 'sent_packet.dart';

/// Minimum UDP payload dart_quic targets (RFC 9000 §14: the minimum
/// datagram size a QUIC endpoint must support during the handshake).
const int kMinimumMaxDatagramSize = 1200;

/// RFC 9002 §7.2: initial window is 10x the max datagram size, capped
/// to the larger of 14,720 bytes or 2x the max datagram size.
///
/// RFC 9002 §7.2 itself notes this is a *conservative default*: "a
/// sender MAY use a larger initial window ... if there is knowledge
/// that a path likely supports the higher rate" -- see
/// [CongestionController]'s own `initialWindowOverride` parameter for
/// where this library takes that option up, specifically for a link
/// where that knowledge already exists (see that parameter's own doc
/// comment for the full rationale).
int initialWindow(int maxDatagramSize) {
  final tenX = 10 * maxDatagramSize;
  final cap = 14720 > (2 * maxDatagramSize) ? 14720 : (2 * maxDatagramSize);
  return tenX < cap ? tenX : cap;
}

/// RFC 9002 §7.2: minimum congestion window, 2x the max datagram size.
int minimumWindow(int maxDatagramSize) => 2 * maxDatagramSize;

/// RFC 9002 §7: the loss-window reduction factor.
const double kLossReductionFactor = 0.5;

class CongestionController {
  final int maxDatagramSize;
  late int congestionWindow;
  int bytesInFlight = 0;
  DateTime? congestionRecoveryStartTime;
  double ssthresh = double.infinity;

  /// Whether the application/flow control currently limits how much
  /// data could be sent -- RFC 9002 §7.8: don't grow the window off
  /// acks that didn't actually reflect available capacity. dart_quic's
  /// single-stream, low-bandwidth use (DESIGN.md) means this is often
  /// true; callers (connection.dart) set it based on whether they
  /// actually had more data queued to send when the window allowed it.
  bool isApplicationLimited = false;

  /// Overrides RFC 9002 §7.2's own conservative default initial window
  /// (see [initialWindow]'s own doc comment on why RFC 9002 explicitly
  /// permits this for a path the sender already has reason to trust).
  /// dart_quic's own usage is exactly that case: commander only ever
  /// speaks QUIC to server/'s own quic-go listener over a link the
  /// operator already controls end to end (see DESIGN.md's own scope
  /// note), not an arbitrary Internet path shared with untrusted
  /// traffic congestion control's slow-start conservatism primarily
  /// protects against. RFC 9002's own 14,720-byte default (~10-15
  /// packets at this library's chunk size) forces a large payload --
  /// e.g. Remote VNC Forwarding's own FramebufferUpdate frames, which
  /// can be hundreds of KB to several MB (see PLAN.md's "Remote VNC
  /// Forwarding" section) -- through dozens of "send a small window,
  /// then WAIT a full round-trip for ACKs before sending more" cycles;
  /// on a path with non-trivial RTT (routing through server's own
  /// relay, not a same-LAN hop), that RTT-per-window cost compounds
  /// into many seconds to tens of seconds of pure waiting for a single
  /// large frame -- independent of, and additive with, any actual
  /// encode/decode or encryption cost. A generous fixed override sized
  /// for "the whole frame fits in the window from the very first RTT"
  /// removes that wait entirely for the traffic this library actually
  /// carries, at the accepted cost of behaving less conservatively than
  /// RFC 9002's own default would on a genuinely congested/lossy path --
  /// loss detection and the ordinary congestion-avoidance additive-
  /// increase/multiplicative-decrease behavor (RFC 9002 Appendix B.5/
  /// B.6, both still fully implemented and untouched by this override)
  /// still apply and shrink the window the normal way the first time a
  /// real loss is actually detected.
  final int? initialWindowOverride;

  CongestionController({
    this.maxDatagramSize = kMinimumMaxDatagramSize,
    this.initialWindowOverride,
  }) {
    congestionWindow = initialWindowOverride ?? initialWindow(maxDatagramSize);
  }

  bool get isInSlowStart => congestionWindow < ssthresh;

  bool _inCongestionRecovery(DateTime sentTime) {
    final start = congestionRecoveryStartTime;
    if (start == null) return false;
    return !sentTime.isAfter(start);
  }

  /// RFC 9002 Appendix B.4: called when a packet carrying non-ACK-only
  /// content is sent.
  void onPacketSent(int sentBytes) {
    bytesInFlight += sentBytes;
  }

  /// RFC 9002 Appendix B.5: called once per newly-acknowledged packet.
  void onPacketAcked(SentPacket packet) {
    if (!packet.inFlight) return;
    bytesInFlight -= packet.sentBytes;
    if (bytesInFlight < 0) bytesInFlight = 0;

    if (isApplicationLimited) return;
    if (_inCongestionRecovery(packet.timeSent)) return;

    if (isInSlowStart) {
      congestionWindow += packet.sentBytes;
    } else {
      congestionWindow +=
          (maxDatagramSize * packet.sentBytes) ~/ congestionWindow;
    }
  }

  /// RFC 9002 Appendix B.6: enters (or stays in) a recovery period in
  /// response to a newly-detected loss.
  void onCongestionEvent(DateTime sentTime, DateTime now) {
    if (_inCongestionRecovery(sentTime)) return;
    congestionRecoveryStartTime = now;
    final newSsthresh = congestionWindow * kLossReductionFactor;
    ssthresh = newSsthresh;
    final minWindow = minimumWindow(maxDatagramSize);
    congestionWindow =
        newSsthresh > minWindow ? newSsthresh.round() : minWindow;
  }

  /// RFC 9002 Appendix B.8 (persistent-congestion handling omitted per
  /// DESIGN.md's scope): removes lost packets from bytes_in_flight and
  /// raises a congestion event for the most recent loss.
  void onPacketsLost(List<SentPacket> lostPackets, DateTime now) {
    DateTime? lastLossTime;
    for (final packet in lostPackets) {
      if (packet.inFlight) {
        bytesInFlight -= packet.sentBytes;
        if (bytesInFlight < 0) bytesInFlight = 0;
        if (lastLossTime == null || packet.timeSent.isAfter(lastLossTime)) {
          lastLossTime = packet.timeSent;
        }
      }
    }
    if (lastLossTime != null) {
      onCongestionEvent(lastLossTime, now);
    }
  }

  /// RFC 9002 Appendix B.9: removes packets from bytes_in_flight when
  /// their packet number space's keys are discarded (Initial/Handshake).
  void removeFromBytesInFlight(List<SentPacket> discardedPackets) {
    for (final packet in discardedPackets) {
      if (packet.inFlight) {
        bytesInFlight -= packet.sentBytes;
        if (bytesInFlight < 0) bytesInFlight = 0;
      }
    }
  }

  /// Whether [bytesToSend] more bytes can currently be sent without
  /// exceeding the congestion window -- the gate connection.dart's send
  /// path checks before transmitting a new (non-probe) packet.
  bool canSend(int bytesToSend) =>
      bytesInFlight + bytesToSend <= congestionWindow;
}
