import 'package:dart_quic/src/recovery/mtu_discovery.dart';
import 'package:test/test.dart';

void main() {
  group('MtuDiscoverer', () {
    test('currentMtu starts at kBaseMtu (RFC 9000\'s own guaranteed '
        'floor) before any probe is ever confirmed', () {
      final finder = MtuDiscoverer();
      expect(finder.currentMtu, equals(kBaseMtu));
    });

    test('shouldProbe is false before start() is called', () {
      final finder = MtuDiscoverer();
      expect(finder.shouldProbe, isFalse);
    });

    test('shouldProbe is true after start(), before any probe is in '
        'flight and before the search is done', () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      expect(finder.shouldProbe, isTrue);
    });

    test('nextProbeSize returns the midpoint of the search interval', () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      expect(finder.nextProbeSize(), equals((1200 + 1452) ~/ 2));
    });

    test('shouldProbe is false while a probe is already in flight', () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      finder.nextProbeSize();
      expect(finder.shouldProbe, isFalse);
    });

    test(
        'an ACKed probe raises currentMtu to that size and narrows the '
        'search interval upward, allowing the next probe further up',
        () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      final probeSize = finder.nextProbeSize(); // 1326
      finder.onProbeAcked(probeSize);

      expect(finder.currentMtu, equals(probeSize));
      expect(finder.shouldProbe, isTrue);
      final nextProbe = finder.nextProbeSize();
      expect(nextProbe, greaterThan(probeSize));
    });

    test(
        'a single lost probe does NOT immediately narrow the interval '
        'down -- ordinary packet loss must not be mistaken for an MTU '
        'ceiling from just one data point', () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      final probeSize = finder.nextProbeSize();
      finder.onProbeLost(probeSize);

      expect(finder.shouldProbe, isTrue);
      // Retries the exact same midpoint -- the interval itself hasn't
      // moved yet.
      expect(finder.nextProbeSize(), equals(probeSize));
    });

    test(
        'kMaxProbeAttempts consecutive losses at the same candidate '
        'size conclusively narrows the search interval\'s own max down '
        'below that size, so a real hard MTU ceiling is eventually '
        'respected rather than retried forever', () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      final probeSize = finder.nextProbeSize();

      for (var i = 0; i < kMaxProbeAttempts; i++) {
        // Re-fetch the (unchanged, per the single-loss test above)
        // in-flight size each iteration -- nextProbeSize marks a new
        // probe in flight, so it must be called again after each
        // onProbeLost clears the previous one.
        finder.onProbeLost(probeSize);
        if (i < kMaxProbeAttempts - 1) {
          expect(finder.nextProbeSize(), equals(probeSize));
        }
      }

      // currentMtu (still the base floor -- this size never actually
      // succeeded) stays safe, and the search interval's own upper
      // bound must now sit at or below the failed candidate.
      expect(finder.currentMtu, equals(1200));
      final nextProbe = finder.shouldProbe ? finder.nextProbeSize() : null;
      if (nextProbe != null) {
        expect(nextProbe, lessThan(probeSize));
      }
    });

    test(
        'isDone becomes true once the search interval narrows to '
        'kMtuSearchGranularity or less, and shouldProbe stops '
        'requesting further probes', () {
      // A tight interval that's already effectively converged.
      final finder =
          MtuDiscoverer(min: 1200, max: 1200 + kMtuSearchGranularity);
      finder.start();
      expect(finder.isDone, isTrue);
      expect(finder.shouldProbe, isFalse);
    });

    test(
        'a stale/mismatched onProbeAcked report (wrong size, e.g. from '
        'a probe sent before a reset) is ignored rather than corrupting '
        'the search state', () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      final probeSize = finder.nextProbeSize();
      finder.onProbeAcked(probeSize + 999); // mismatched size

      // The real in-flight probe's own state is untouched -- still in
      // flight, currentMtu unchanged.
      expect(finder.currentMtu, equals(1200));
      expect(finder.shouldProbe, isFalse);
    });

    test('reset() restores a fresh search interval and clears in-'
        'flight/loss-count state', () {
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();
      final probeSize = finder.nextProbeSize();
      finder.onProbeAcked(probeSize);
      expect(finder.currentMtu, greaterThan(1200));

      finder.reset(min: 1200, max: 1452);
      expect(finder.currentMtu, equals(1200));
      expect(finder.shouldProbe, isTrue);
    });

    test(
        'realistic end-to-end search: repeatedly probing and always '
        'acking converges to a value close to the true ceiling and '
        'never exceeds it', () {
      const trueCeiling = 1420; // e.g. a realistic WireGuard MTU
      final finder = MtuDiscoverer(min: 1200, max: 1452);
      finder.start();

      var iterations = 0;
      while (!finder.isDone && iterations < 50) {
        iterations++;
        if (!finder.shouldProbe) break;
        final size = finder.nextProbeSize();
        if (size <= trueCeiling) {
          finder.onProbeAcked(size);
        } else {
          // Simulate the real failure mode this class exists to
          // handle: a probe above the true ceiling is silently
          // dropped every single time (a hard limit, not flaky loss),
          // so kMaxProbeAttempts consecutive losses always follow.
          for (var i = 0; i < kMaxProbeAttempts; i++) {
            finder.onProbeLost(size);
          }
        }
      }

      expect(finder.currentMtu, lessThanOrEqualTo(trueCeiling));
      expect(finder.currentMtu,
          greaterThan(trueCeiling - kMtuSearchGranularity - 1));
      expect(iterations, lessThan(50),
          reason: 'search must actually converge, not loop forever');
    });
  });
}
