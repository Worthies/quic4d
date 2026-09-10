/// RFC 9002 Appendix A.1.1: the per-sent-packet bookkeeping loss
/// detection and congestion control both need.
library;

import '../frame/frame_codec.dart';

class SentPacket {
  final int packetNumber;
  final bool ackEliciting;
  final bool inFlight;
  final int sentBytes;
  final DateTime timeSent;

  /// The CRYPTO/STREAM frames this packet carried, if any -- kept
  /// verbatim (same offset/data) so that if this packet is declared
  /// lost, connection.dart can resend the exact same frames in a new
  /// packet (RFC 9000 §13.3: lost data is retransmitted, never the
  /// original packet itself, since packet numbers are never reused).
  /// Null for packets that carry nothing worth retransmitting on their
  /// own (bare ACK/PING) -- losing those has no retransmission action
  /// beyond what PTO probing already covers.
  final List<Frame>? retransmittableFrames;

  const SentPacket({
    required this.packetNumber,
    required this.ackEliciting,
    required this.inFlight,
    required this.sentBytes,
    required this.timeSent,
    this.retransmittableFrames,
  });
}
