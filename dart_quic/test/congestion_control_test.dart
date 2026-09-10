import 'package:dart_quic/src/recovery/congestion_control.dart';
import 'package:dart_quic/src/recovery/sent_packet.dart';
import 'package:test/test.dart';

void main() {
  group('initial/minimum window (RFC 9002 SS7.2)', () {
    test(
        'initialWindow is 10x datagram size, capped at 14720 for the '
        'default 1200-byte size', () {
      // 10 * 1200 = 12000, which is below the 14720 cap.
      expect(initialWindow(1200), 12000);
    });

    test('initialWindow caps at 14720 for a larger datagram size', () {
      // 10 * 1500 = 15000, capped to max(14720, 2*1500=3000) = 14720.
      expect(initialWindow(1500), 14720);
    });

    test('minimumWindow is 2x the max datagram size', () {
      expect(minimumWindow(1200), 2400);
    });
  });

  group('CongestionController construction', () {
    test('starts in slow start with congestionWindow = initialWindow', () {
      final cc = CongestionController();
      expect(cc.congestionWindow, initialWindow(kMinimumMaxDatagramSize));
      expect(cc.isInSlowStart, isTrue);
      expect(cc.bytesInFlight, 0);
    });
  });

  group('slow start growth (RFC 9002 SS7.3.1)', () {
    test('congestion window grows by acked bytes while in slow start', () {
      final cc = CongestionController();
      final initial = cc.congestionWindow;
      cc.onPacketSent(500);

      final packet = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: DateTime(2024, 1, 1),
      );
      cc.onPacketAcked(packet);

      expect(cc.congestionWindow, initial + 500);
      expect(cc.bytesInFlight, 0);
    });

    test('does not grow the window when application-limited', () {
      final cc = CongestionController()..isApplicationLimited = true;
      final initial = cc.congestionWindow;
      final packet = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: DateTime(2024, 1, 1),
      );
      cc.onPacketAcked(packet);
      expect(cc.congestionWindow, initial);
    });
  });

  group('congestion event / recovery (RFC 9002 SS7.3.2)', () {
    test('a loss halves the congestion window (kLossReductionFactor)', () {
      final cc = CongestionController();
      final initial = cc.congestionWindow;
      final lostPacket = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: DateTime(2024, 1, 1),
      );
      cc.onPacketSent(500);
      cc.onPacketsLost([lostPacket], DateTime(2024, 1, 1, 0, 0, 1));

      expect(cc.congestionWindow, (initial * 0.5).round());
      expect(cc.ssthresh, initial * 0.5);
      expect(cc.bytesInFlight, 0);
    });

    test('congestion window never drops below minimumWindow', () {
      final cc = CongestionController(maxDatagramSize: 1200);
      // Force a very small window before the loss, to exercise the
      // minimumWindow floor.
      cc.congestionWindow = 100;
      final lostPacket = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: DateTime(2024, 1, 1),
      );
      cc.onPacketsLost([lostPacket], DateTime(2024, 1, 1, 0, 0, 1));
      expect(cc.congestionWindow, minimumWindow(1200));
    });

    test(
        'a second loss within the same recovery period is a no-op '
        '(RFC 9002 SS7.3.2: recovery limits reduction to once per RTT)', () {
      final cc = CongestionController();
      final t0 = DateTime(2024, 1, 1);
      final firstLoss = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: t0,
      );
      cc.onPacketsLost([firstLoss], t0.add(const Duration(milliseconds: 10)));
      final windowAfterFirstLoss = cc.congestionWindow;

      // Second lost packet was sent *before* the recovery period
      // started, so RFC 9002's InCongestionRecovery(sent_time) check
      // (sent_time <= congestion_recovery_start_time) correctly treats
      // it as part of the same recovery event, not a new one.
      final secondLoss = SentPacket(
        packetNumber: 2,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: t0.add(const Duration(milliseconds: 5)),
      );
      cc.onPacketsLost([secondLoss], t0.add(const Duration(milliseconds: 20)));

      expect(cc.congestionWindow, windowAfterFirstLoss);
    });

    test(
        'an ack for a packet sent during recovery exits recovery and '
        'resumes growth', () {
      final cc = CongestionController();
      final t0 = DateTime(2024, 1, 1);
      final lostPacket = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: t0,
      );
      cc.onPacketsLost([lostPacket], t0.add(const Duration(seconds: 1)));
      final windowInRecovery = cc.congestionWindow;

      // A packet sent *after* recovery started, once acked, should
      // grow the window again (no longer "in recovery" per
      // InCongestionRecovery's sent_time <= start_time check).
      final packetAfterRecovery = SentPacket(
        packetNumber: 2,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: t0.add(const Duration(seconds: 2)),
      );
      cc.onPacketAcked(packetAfterRecovery);
      expect(cc.congestionWindow, greaterThan(windowInRecovery));
    });
  });

  group('congestion avoidance (RFC 9002 SS7.3.3)', () {
    test(
        'once above ssthresh, window grows by at most one datagram '
        'per RTT (AIMD)', () {
      final cc = CongestionController(maxDatagramSize: 1200);
      cc.ssthresh = 1000; // force congestion avoidance immediately
      cc.congestionWindow = 10000;
      final before = cc.congestionWindow;

      final packet = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 1200,
        timeSent: DateTime(2024, 1, 1),
      );
      cc.onPacketAcked(packet);

      // congestion_window += max_datagram_size * sent_bytes / cwnd
      final expectedGrowth = (1200 * 1200) ~/ before;
      expect(cc.congestionWindow, before + expectedGrowth);
    });
  });

  group('canSend / bytesInFlight', () {
    test('canSend is false once bytesInFlight would exceed the window', () {
      final cc = CongestionController(maxDatagramSize: 1200)
        ..congestionWindow = 1000;
      cc.onPacketSent(900);
      expect(cc.canSend(50), isTrue);
      expect(cc.canSend(200), isFalse);
    });

    test('removeFromBytesInFlight subtracts discarded in-flight bytes', () {
      final cc = CongestionController();
      cc.onPacketSent(500);
      final discarded = SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 500,
        timeSent: DateTime(2024, 1, 1),
      );
      cc.removeFromBytesInFlight([discarded]);
      expect(cc.bytesInFlight, 0);
    });

    test('onPacketAcked ignores packets that were never in flight', () {
      final cc = CongestionController();
      final before = cc.congestionWindow;
      final notInFlight = SentPacket(
        packetNumber: 1,
        ackEliciting: false,
        inFlight: false,
        sentBytes: 500,
        timeSent: DateTime(2024, 1, 1),
      );
      cc.onPacketAcked(notInFlight);
      expect(cc.congestionWindow, before);
      expect(cc.bytesInFlight, 0);
    });
  });
}
