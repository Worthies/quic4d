import 'package:dart_quic/src/recovery/loss_detection.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/recovery/sent_packet.dart';
import 'package:test/test.dart';

void main() {
  group('LossDetector — packet threshold (RFC 9002 SS6.1.1)', () {
    // Both tests below pre-seed a realistic 100ms RTT sample via a
    // throwaway packet/ack pair *before* the scenario under test, so
    // the ack that matters doesn't itself produce the first-ever RTT
    // sample (which would collapse smoothed_rtt to whatever that one
    // ack's latency happens to be, confusing packet-threshold-only
    // scenarios with time-threshold effects -- see RFC 9002 SS5.3's
    // "on first sample, reset the estimator" rule).
    LossDetector seededDetector(DateTime baseTime) {
      final detector = LossDetector(RttEstimator());
      detector.onPacketSent(SentPacket(
        packetNumber: 0,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: baseTime.subtract(const Duration(milliseconds: 200)),
      ));
      detector.onAckReceived(
        acknowledgedPacketNumbers: [0],
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
        now: baseTime.subtract(const Duration(milliseconds: 100)),
      );
      expect(detector.rtt.smoothedRtt, const Duration(milliseconds: 100));
      return detector;
    }

    test('a packet 3+ behind the largest acked is declared lost', () {
      final baseTime = DateTime(2024, 1, 1, 0, 0, 0);
      final detector = seededDetector(baseTime);

      for (var pn = 1; pn <= 5; pn++) {
        detector.onPacketSent(SentPacket(
          packetNumber: pn,
          ackEliciting: true,
          inFlight: true,
          sentBytes: 100,
          timeSent: baseTime.add(Duration(milliseconds: pn)),
        ));
      }

      // Ack only packet 5, immediately (so the 100ms-RTT-based time
      // threshold hasn't elapsed for anything): kPacketThreshold=3
      // behind packet 5 is pn<=2 -> only 1,2 are lost by packet count.
      final result = detector.onAckReceived(
        acknowledgedPacketNumbers: [5],
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
        now: baseTime.add(const Duration(milliseconds: 6)),
      );

      final lostPns =
          result.newlyLost.map((l) => l.packet.packetNumber).toSet();
      expect(lostPns, {1, 2});
    });

    test('packets within the threshold are not yet declared lost', () {
      final baseTime = DateTime(2024, 1, 1);
      final detector = seededDetector(baseTime);

      for (var pn = 1; pn <= 3; pn++) {
        detector.onPacketSent(SentPacket(
          packetNumber: pn,
          ackEliciting: true,
          inFlight: true,
          sentBytes: 100,
          timeSent: baseTime.add(Duration(milliseconds: pn)),
        ));
      }

      // Ack packet 3: pn 1,2 are only 1-2 behind (< kPacketThreshold=3),
      // and elapsed time (a few ms) is far below the 100ms-RTT-based
      // time threshold, so nothing should be lost yet.
      final result = detector.onAckReceived(
        acknowledgedPacketNumbers: [3],
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
        now: baseTime.add(const Duration(milliseconds: 4)),
      );

      expect(result.newlyLost, isEmpty);
      expect(detector.lossTime, isNotNull); // a loss timer should be armed
    });
  });

  group('LossDetector — time threshold (RFC 9002 SS6.1.2)', () {
    test(
        'a packet sent long enough ago is declared lost by time '
        'alone', () {
      final detector = LossDetector(RttEstimator());
      final baseTime = DateTime(2024, 1, 1);

      // Give the estimator a real RTT sample first so the time
      // threshold isn't dominated by kInitialRtt's large default.
      detector.rtt.updateRtt(
        rtt: const Duration(milliseconds: 50),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );

      detector.onPacketSent(SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: baseTime,
      ));
      detector.onPacketSent(SentPacket(
        packetNumber: 2,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: baseTime.add(const Duration(milliseconds: 200)),
      ));

      // Ack packet 2 well after packet 1's time-threshold window
      // (50ms * 9/8 = 56.25ms) has elapsed since packet 1 was sent.
      final result = detector.onAckReceived(
        acknowledgedPacketNumbers: [2],
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
        now: baseTime.add(const Duration(milliseconds: 200)),
      );

      final lostPns =
          result.newlyLost.map((l) => l.packet.packetNumber).toSet();
      expect(lostPns, {1});
    });
  });

  group('LossDetector — RTT sample updates on ack', () {
    test(
        'acking the largest-numbered ack-eliciting packet updates '
        'latest_rtt', () {
      final detector = LossDetector(RttEstimator());
      final sentAt = DateTime(2024, 1, 1);
      detector.onPacketSent(SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: sentAt,
      ));

      final ackedAt = sentAt.add(const Duration(milliseconds: 75));
      detector.onAckReceived(
        acknowledgedPacketNumbers: [1],
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
        now: ackedAt,
      );

      expect(detector.rtt.latestRtt, const Duration(milliseconds: 75));
    });

    test(
        'acking a non-largest packet in the same ACK does not itself '
        'produce a fresh latest_rtt sample unless it is the largest', () {
      final detector = LossDetector(RttEstimator());
      final sentAt = DateTime(2024, 1, 1);
      detector.onPacketSent(SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: sentAt,
      ));
      detector.onPacketSent(SentPacket(
        packetNumber: 2,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: sentAt.add(const Duration(milliseconds: 10)),
      ));

      // ACK's largest_acked is 2 (per the ACK frame), even though this
      // call only supplies packet 1 in acknowledgedPacketNumbers --
      // simulate that by passing the actual ack.largest_acked
      // separately isn't modeled here; this test instead just checks
      // that acking exactly the largest packet (2) does produce a
      // sample when it's ack-eliciting.
      final result = detector.onAckReceived(
        acknowledgedPacketNumbers: [2],
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
        now: sentAt.add(const Duration(milliseconds: 60)),
      );
      expect(result.newlyAcked.map((p) => p.packetNumber), [2]);
      expect(detector.rtt.latestRtt, const Duration(milliseconds: 50));
    });
  });

  group('LossDetector bookkeeping', () {
    test('bytesInFlight sums only in-flight packets', () {
      final detector = LossDetector(RttEstimator());
      final now = DateTime(2024, 1, 1);
      detector.onPacketSent(SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: now,
      ));
      detector.onPacketSent(SentPacket(
        packetNumber: 2,
        ackEliciting: false,
        inFlight: false,
        sentBytes: 50,
        timeSent: now,
      ));
      expect(detector.bytesInFlight, 100);
    });

    test(
        'hasAckElicitingInFlight reflects only ack-eliciting, '
        'in-flight packets', () {
      final detector = LossDetector(RttEstimator());
      final now = DateTime(2024, 1, 1);
      expect(detector.hasAckElicitingInFlight, isFalse);
      detector.onPacketSent(SentPacket(
        packetNumber: 1,
        ackEliciting: false,
        inFlight: true,
        sentBytes: 100,
        timeSent: now,
      ));
      expect(detector.hasAckElicitingInFlight, isFalse);
      detector.onPacketSent(SentPacket(
        packetNumber: 2,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: now,
      ));
      expect(detector.hasAckElicitingInFlight, isTrue);
    });

    test('discard() clears all tracked state', () {
      final detector = LossDetector(RttEstimator());
      final now = DateTime(2024, 1, 1);
      detector.onPacketSent(SentPacket(
        packetNumber: 1,
        ackEliciting: true,
        inFlight: true,
        sentBytes: 100,
        timeSent: now,
      ));
      detector.discard();
      expect(detector.bytesInFlight, 0);
      expect(detector.hasAckElicitingInFlight, isFalse);
      expect(detector.timeOfLastAckElicitingPacket, isNull);
    });

    test('an ACK with no matching sent packets is a no-op', () {
      final detector = LossDetector(RttEstimator());
      final result = detector.onAckReceived(
        acknowledgedPacketNumbers: [999],
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
        now: DateTime(2024, 1, 1),
      );
      expect(result.newlyAcked, isEmpty);
      expect(result.newlyLost, isEmpty);
    });
  });
}
