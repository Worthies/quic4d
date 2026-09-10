/// RFC 9002 Appendix A.1.1: the per-sent-packet bookkeeping loss
/// detection and congestion control both need.
library;

class SentPacket {
  final int packetNumber;
  final bool ackEliciting;
  final bool inFlight;
  final int sentBytes;
  final DateTime timeSent;

  const SentPacket({
    required this.packetNumber,
    required this.ackEliciting,
    required this.inFlight,
    required this.sentBytes,
    required this.timeSent,
  });
}
