import 'package:dart_quic/src/recovery/received_packet_tracker.dart';
import 'package:test/test.dart';

void main() {
  test('in-order packets produce a single all-received range', () {
    final t = ReceivedPacketTracker();
    for (var pn = 0; pn < 100; pn++) {
      expect(t.onReceived(pn), isTrue);
    }
    final ack = t.buildAckFrame(0)!;
    expect(ack.largestAcknowledged, 99);
    expect(ack.firstAckRange, 99); // everything 0..98 too
    expect(ack.ackRanges, isEmpty);
    // Round-trips through our own decoder's expansion.
    expect(ack.acknowledgedPacketNumbers().toSet(),
        {for (var i = 0; i < 100; i++) i});
  });

  test('one reordered straggler produces an honest two-range ack', () {
    final t = ReceivedPacketTracker();
    // Received {0..5, 8}: 6 and 7 missing.
    for (var pn = 0; pn <= 5; pn++) {
      t.onReceived(pn);
    }
    t.onReceived(8);
    final ack = t.buildAckFrame(0)!;
    expect(ack.largestAcknowledged, 8);
    expect(ack.firstAckRange, 0); // only 8 in the top run
    expect(ack.ackRanges.length, 1);
    expect(ack.ackRanges[0].gap, 1); // two missing (6,7) minus one
    expect(ack.ackRanges[0].ackRangeLength, 5); // 5..0
    expect(ack.acknowledgedPacketNumbers().toSet(), {
      for (var i = 0; i <= 5; i++) i,
      8,
    });
  });

  test('duplicate notifications are rejected and never widen the ack', () {
    final t = ReceivedPacketTracker();
    t.onReceived(0);
    t.onReceived(1);
    expect(t.onReceived(1), isFalse);
    expect(t.onReceived(0), isFalse);
    final ack = t.buildAckFrame(0)!;
    expect(ack.largestAcknowledged, 1);
    expect(ack.firstAckRange, 1);
  });

  test('frontier advances when the gap fills, collapsing ranges', () {
    final t = ReceivedPacketTracker();
    t.onReceived(0);
    t.onReceived(2);
    t.onReceived(4);
    var ack = t.buildAckFrame(0)!;
    expect(ack.ackRanges.length, 2);
    // The missing 1 and 3 arrive (e.g. retransmitted).
    expect(t.onReceived(1), isTrue);
    expect(t.onReceived(3), isTrue);
    ack = t.buildAckFrame(0)!;
    expect(ack.firstAckRange, 4); // everything 0..4 now
    expect(ack.ackRanges, isEmpty);
  });

  test('ranges are capped, never dishonest', () {
    final t = ReceivedPacketTracker();
    // Received every even packet: 0,2,4,...,2N -- N+1 singleton runs,
    // more than kMaxAckRanges.
    for (var pn = 0; pn <= 2 * (kMaxAckRanges + 5); pn += 2) {
      t.onReceived(pn);
    }
    final ack = t.buildAckFrame(0)!;
    expect(ack.ackRanges.length, kMaxAckRanges);
    // Every acknowledged pn must be one actually received (even).
    for (final pn in ack.acknowledgedPacketNumbers()) {
      expect(pn.isEven, isTrue, reason: 'acked pn $pn was never received');
    }
  });

  test('buildAckFrame returns null before anything is received', () {
    final t = ReceivedPacketTracker();
    expect(t.buildAckFrame(0), isNull);
  });

  test('huge packet-number jump cannot stall ack building', () {
    final t = ReceivedPacketTracker();
    for (var pn = 0; pn <= 5; pn++) {
      t.onReceived(pn);
    }
    // 4-byte truncated packet numbers legally jump to ~2^31. The old
    // gap walk scanned every pn between frontier and the straggler --
    // billions of iterations freezing the event loop; now it must
    // return immediately with an honest single-packet ack.
    const hugePn = 0x7FFFFFFF;
    t.onReceived(hugePn);
    final ack = t.buildAckFrame(0)!;
    expect(ack.largestAcknowledged, hugePn);
    expect(ack.firstAckRange, 0); // nothing else near the straggler
    expect(ack.ackRanges, isEmpty);
    // The straggler is acked as largestAcknowledged itself; the gap
    // below is skipped (those pns were never received, so acking only
    // the top run stays honest).
    final acked = ack.acknowledgedPacketNumbers().toSet();
    expect(acked.contains(hugePn), isTrue);
    for (final pn in acked.where((p) => p != hugePn)) {
      expect(pn <= 5, isTrue, reason: 'acked pn $pn was never received');
    }
  });

  test('straggler tracking is bounded under adversarial injection', () {
    final t = ReceivedPacketTracker();
    t.onReceived(0);
    // Far more stragglers than the cap: state must stay bounded and
    // building an ack must terminate, never claiming unreceived pns.
    for (var pn = 10; pn < 10 + kMaxTrackedStragglers * 4; pn += 2) {
      t.onReceived(pn);
    }
    final ack = t.buildAckFrame(0)!;
    expect(ack.largestAcknowledged, 10 + kMaxTrackedStragglers * 4 - 2);
    for (final pn in ack.acknowledgedPacketNumbers()) {
      expect(pn.isEven || pn == 0, isTrue,
          reason: 'acked pn $pn was never received');
    }
  });
}
