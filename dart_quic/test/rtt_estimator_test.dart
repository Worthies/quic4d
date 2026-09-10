import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:test/test.dart';

void main() {
  group('RttEstimator', () {
    test('starts at kInitialRtt with rttvar = kInitialRtt / 2', () {
      final estimator = RttEstimator();
      expect(estimator.smoothedRtt, kInitialRtt);
      expect(estimator.rttvar,
          Duration(microseconds: kInitialRtt.inMicroseconds ~/ 2));
    });

    test(
        'first sample resets smoothed_rtt and rttvar to that sample '
        '(RFC 9002 SS5.3)', () {
      final estimator = RttEstimator();
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      expect(estimator.smoothedRtt, const Duration(milliseconds: 100));
      expect(estimator.rttvar, const Duration(milliseconds: 50));
      expect(estimator.minRtt, const Duration(milliseconds: 100));
    });

    test('subsequent samples follow the 7/8, 1/8 EWMA formula', () {
      final estimator = RttEstimator();
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      // Second sample of 200ms: adjusted_rtt = 200ms (ack_delay=0).
      // smoothed_rtt = 7/8*100 + 1/8*200 = 112.5ms
      // rttvar_sample = |112.5 - 200| = 87.5ms
      // rttvar = 3/4*50 + 1/4*87.5 = 59.375ms
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 200),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      expect(estimator.smoothedRtt.inMicroseconds, 112500);
      expect(estimator.rttvar.inMicroseconds, 59375);
    });

    test('min_rtt tracks the smallest RTT sample seen', () {
      final estimator = RttEstimator();
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 50),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      expect(estimator.minRtt, const Duration(milliseconds: 50));
    });

    test('ack_delay is subtracted from the RTT sample when plausible', () {
      final estimator = RttEstimator();
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      // latest_rtt(150) >= min_rtt(100) + ack_delay(20) -> subtract.
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 150),
        ackDelay: const Duration(milliseconds: 20),
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      // adjusted_rtt = 130ms; smoothed = 7/8*100 + 1/8*130 = 103.75ms
      expect(estimator.smoothedRtt.inMicroseconds, 103750);
    });

    test(
        'ack_delay is clamped to max_ack_delay once handshake is '
        'confirmed', () {
      final estimator = RttEstimator();
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        handshakeConfirmed: true,
        maxAckDelay: const Duration(milliseconds: 10),
      );
      // ack_delay(50ms) clamped to max_ack_delay(10ms) since
      // handshakeConfirmed=true.
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 150),
        ackDelay: const Duration(milliseconds: 50),
        handshakeConfirmed: true,
        maxAckDelay: const Duration(milliseconds: 10),
      );
      // adjusted_rtt = 150 - 10 = 140ms; smoothed = 7/8*100+1/8*140=105ms
      expect(estimator.smoothedRtt.inMicroseconds, 105000);
    });

    test(
        'computePto = smoothed_rtt + max(4*rttvar, kGranularity) + '
        'max_ack_delay', () {
      final estimator = RttEstimator();
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 100),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      // smoothed=100ms, rttvar=50ms -> 4*rttvar=200ms
      final pto = estimator.computePto(const Duration(milliseconds: 25));
      expect(pto, const Duration(milliseconds: 100 + 200 + 25));
    });

    test('computePto with maxAckDelay=0 for Initial/Handshake spaces', () {
      final estimator = RttEstimator();
      estimator.updateRtt(
        rtt: const Duration(milliseconds: 50),
        ackDelay: Duration.zero,
        handshakeConfirmed: false,
        maxAckDelay: const Duration(milliseconds: 25),
      );
      final pto = estimator.computePto(Duration.zero);
      // smoothed=50ms, rttvar=25ms -> 4*rttvar=100ms
      expect(pto, const Duration(milliseconds: 50 + 100));
    });
  });
}
