/// Per-packet-number-space tracking of received packet numbers, so ACK
/// frames can honestly acknowledge every packet actually received --
/// as one or more contiguous ranges -- instead of only the single
/// largest packet number.
///
/// Why this matters (the bug this replaces): an ACK frame with
/// firstAckRange=0 acknowledges exactly ONE packet. Sending only that
/// for every received packet made the peer's loss detection declare
/// every other packet lost and retransmit it, roughly doubling inbound
/// traffic, AEAD-decrypt work, and duplicate-frame allocation churn --
/// observed against a real quic-go server as high memory/CPU and
/// flow-control windows burning twice as fast as they should.
///
/// Memory shape: a contiguous frontier (every packet number <= frontier
/// has been received) plus a set of above-frontier packets. The set
/// only ever holds reordered stragglers; once the gap below them fills,
/// the frontier advances and they're removed. Duplicate notifications
/// below the frontier are O(1) rejections.
library;

import '../frame/ack_frame.dart';

/// How many ACK ranges an encoded ACK frame carries at most. RFC 9000
/// §19.3 imposes no limit; a cap keeps ACK packets bounded under
/// pathological reordering. Ranges beyond the cap are simply not
/// acknowledged yet (the peer retransmits them, same as if they had
/// been lost -- always safe, never dishonest).
const int kMaxAckRanges = 8;

/// Cap on out-of-order packets tracked above the contiguous frontier.
/// A peer may legally send packet numbers far above the frontier (4-byte
/// truncated numbers jump up to 2^31), so state growth must be bounded;
/// untracked packets simply go un-ACKed and are retransmitted by the
/// peer's loss detection, which is always safe.
const int kMaxTrackedStragglers = 256;

/// Cap on how far below a run we scan for the next received packet while
/// building ACK ranges. Bounds buildAckFrame to
/// O(kMaxAckRanges * (kMaxTrackedStragglers + kMaxGapScan)) steps so a
/// huge packet-number jump cannot stall the event loop. Gaps beyond the
/// cap end the ACK early; the skipped packets get retransmitted.
const int kMaxGapScan = 64;

class ReceivedPacketTracker {
  /// Highest packet number such that EVERY pn in 0..frontier has been
  /// received. -1 = nothing received yet.
  int _frontier = -1;

  /// Received packet numbers above [_frontier] awaiting the gap below
  /// them to fill.
  final Set<int> _above = {};

  /// Largest packet number ever received (>= frontier whenever
  /// anything has been received).
  int? largestReceived;

  /// Records a received packet number. Returns false if it was a
  /// duplicate (already known), true if newly recorded.
  bool onReceived(int pn) {
    if (pn <= _frontier) return false;
    if (_above.length >= kMaxTrackedStragglers && !_above.contains(pn)) {
      // Untracked (not ACKed): the peer retransmits it later.
      largestReceived = largestReceived == null || pn > largestReceived!
          ? pn
          : largestReceived;
      return true;
    }
    if (!_above.add(pn)) return false;
    largestReceived =
        largestReceived == null || pn > largestReceived! ? pn : largestReceived;
    while (_above.contains(_frontier + 1)) {
      _above.remove(_frontier + 1);
      _frontier++;
    }
    return true;
  }

  /// Whether [pn] has been recorded as received.
  bool contains(int pn) => pn <= _frontier || _above.contains(pn);

  /// Builds an honest ACK frame for everything received so far, with
  /// up to [kMaxAckRanges] additional ranges. Returns null when
  /// nothing has been received yet.
  AckFrame? buildAckFrame(int ackDelayMicros) {
    final largest = largestReceived;
    if (largest == null) return null;

    // Walk DOWN from largest, alternating received-runs (ranges) and
    // unreceived-runs (gaps), exactly mirroring RFC 9000 §19.3.1's
    // encoding: firstAckRange counts packets below largestAcknowledged
    // in the first contiguous received run; each AckRange then encodes
    // a gap (unreceived count minus one) followed by the next
    // received-run length minus one.
    final ranges = <AckRange>[];
    var firstAckRange = _contiguousRunBelow(largest) - 1;
    var lowestInRun = largest - (firstAckRange + 1);
    while (lowestInRun > _frontier && ranges.length < kMaxAckRanges) {
      // Gap down to the next received packet, bounded by kMaxGapScan so
      // a huge packet-number jump cannot turn this into a billions-step
      // scan that stalls the event loop.
      var gapPn = lowestInRun - 1;
      var scanned = 0;
      while (gapPn >= 0 && !contains(gapPn) && scanned < kMaxGapScan) {
        gapPn--;
        scanned++;
      }
      if (gapPn < 0 || !contains(gapPn)) break;
      // RFC 9000 §19.3.1 + ack_frame.dart's own decoder: the next
      // range's largest = previous range's smallest - gap - 2, i.e.
      // gap = unackedCount - 1 between the two runs (verified by
      // concrete round-trip: received {0..5, 8} must encode as
      // largest=8, firstAckRange=0, one AckRange(gap:1, len:5)).
      final gap = lowestInRun - gapPn - 1;
      final runLength = _contiguousRunBelow(gapPn);
      ranges.add(AckRange(gap: gap, ackRangeLength: runLength - 1));
      lowestInRun = gapPn - runLength;
    }
    return AckFrame(
      largestAcknowledged: largest,
      ackDelay: ackDelayMicros,
      firstAckRange: firstAckRange < 0 ? 0 : firstAckRange,
      ackRanges: ranges,
    );
  }

  /// Length of the contiguous received run ENDING at [pn] (inclusive).
  /// Uses the frontier directly for everything below it (all received
  /// by definition) so the common in-order case is O(1) instead of
  /// walking the whole history -- an ACK build must not be O(packets
  /// received so far), or a long session degenerates to O(n^2) total.
  int _contiguousRunBelow(int pn) {
    var run = 1;
    var p = pn - 1;
    while (p > _frontier && _above.contains(p)) {
      run++;
      p--;
    }
    if (p <= _frontier) run += p + 1; // everything 0..p is received
    return run;
  }
}
