import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/diagnostics.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

import 'lossy_udp_proxy.dart';

/// Quantifies the false-positive rate of the 1-RTT path probe
/// (_noteProbeSent/_noteProbeAcked in connection.dart) under ordinary,
/// self-healing packet loss -- the question that has to be answered
/// BEFORE wiring the probe into any reconnect decision (the "N3"
/// optimization under consideration for commander): does "uplink NOT
/// acked within 3s" reliably mean the path is dead, or can a
/// perfectly healthy connection under realistic mobile-network loss
/// also trigger it?
///
/// The probe watches exactly ONE packet number -- the very first
/// 1-RTT ping sent synchronously as Connection.connect() returns --
/// and never re-arms if that specific packet or its ACK is lost, even
/// though dart_quic's own loss detection would retransmit it and the
/// connection would prove itself alive moments later. This runs many
/// independent connect() trials against a real quic-go server behind
/// a lossy proxy (20% constant client->server loss -- realistic for a
/// degraded-but-not-dead mobile link, and already proven survivable
/// up to 30% for full handshake completion by the existing
/// reliability test) and tallies how often the probe reports
/// NOT-acked on a connection that is, moments later, proven fully
/// alive by completing a real application round-trip.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  // The single-Accept()-lifetime server (test/integration/server) only
  // ever handles one connection; this test needs many (one per
  // trial), so it uses the multi-accept server built for
  // reconnect_after_abrupt_death_test.dart instead.
  final serverDir = '$testDir/multi_accept_server';
  final fixturesDir = '$testDir/fixtures';

  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_probe_fp_test_server';
    final build = await Process.run(
      'go',
      ['build', '-o', serverBinaryPath!, '.'],
      workingDirectory: serverDir,
    );
    if (build.exitCode != 0) {
      throw StateError('failed to build Go test server:\n${build.stderr}');
    }
  });

  test(
      'false-positive rate of the path probe under 20% client->server '
      'loss, across repeated trials against a real quic-go server',
      () async {
    if (serverBinaryPath == null) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const serverPort = 48470;
    const trials = 12;

    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$serverPort'],
    );
    addTearDown(() => serverProcess.kill());

    final serverStderr = <String>[];
    serverProcess.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(serverStderr.add);

    final readyCompleter = Completer<void>();
    serverProcess.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.trim() == 'READY' && !readyCompleter.isCompleted) {
        readyCompleter.complete();
      }
    });
    await readyCompleter.future.timeout(const Duration(seconds: 10));

    final clientCertDer =
        _pemCertToDer(File('$fixturesDir/client.crt').readAsStringSync());
    final clientKeyPem = File('$fixturesDir/client.key').readAsStringSync();
    final clientIdentity = ClientIdentity(
      certificateChainDer: [clientCertDer],
      privateKey: CryptoUtils.rsaPrivateKeyFromPem(clientKeyPem),
      signatureScheme: SignatureScheme.rsaPssRsaeSha256,
    );

    var notAckedCount = 0;
    var ackedCount = 0;
    var neitherCount = 0;
    var falsePositiveCount = 0;

    for (var trial = 0; trial < trials; trial++) {
      final diagnosticLog = <String>[];
      final unsubscribe = QuicDiagnostics.listen(diagnosticLog.add);

      // A fresh proxy per trial: LossyUdpProxy tracks only a single
      // client address/port globally (by design, for its original
      // one-connection-per-run use in quic_go_reliability_test.dart),
      // so reusing one proxy across sequential trials risks routing a
      // straggling previous trial's retransmission/ACK to the wrong
      // client port during the handover window -- a real bug this
      // test tripped over empirically (a trial's real application
      // traffic never arrived at all, not merely a slow probe).
      final proxyPort = 48472 + trial;
      final proxy = LossyUdpProxy(
        listenPort: proxyPort,
        targetPort: serverPort,
        dropProbability: 0.2,
      );
      await proxy.start();

      Connection? connection;
      try {
        connection = await Connection.connect(
          host: '127.0.0.1',
          port: proxyPort,
          serverName: 'localhost',
          clientIdentity: clientIdentity,
          handshakeTimeout: const Duration(seconds: 20),
        );

        final replies = <String>[];
        connection.stream.incoming.listen((c) => replies.add(utf8.decode(c)));

        // Prove the connection is genuinely alive regardless of what
        // the probe reported: a real application round-trip, which
        // must survive the same 20% loss via dart_quic's own
        // retransmission (unrelated to and independent of the
        // one-shot probe).
        final marker = 'trial-$trial-alive';
        await connection.stream.write(Uint8List.fromList(utf8.encode(
            '{"type":"marker","content":"$marker"}\n')));
        await _waitUntil(
          () => replies.any((r) => r.contains(marker)),
          timeout: const Duration(seconds: 25),
          onTimeout: () => 'trial $trial: marker never echoed back. '
              'connection.state=${connection?.state}; '
              'replies so far: $replies; diagnostic log: $diagnosticLog; '
              'proxy: forwarded=${proxy.forwardedCount} '
              'dropped=${proxy.droppedCount}; '
              'proxy server->client forwarded='
              '${proxy.serverToClientForwardedCount}; '
              'server stderr: ${serverStderr.join(' | ')}',
        );

        // Give the probe's 3s timer a chance to fire if it hasn't
        // resolved yet.
        await Future<void>.delayed(const Duration(milliseconds: 500));

        final notAcked = diagnosticLog.any((l) => l.contains('NOT acked'));
        final acked = diagnosticLog.any((l) => l.contains('server ACKed'));
        if (notAcked) {
          notAckedCount++;
          // The connection JUST completed real traffic above -- any
          // NOT-acked report is, by definition, a false positive.
          falsePositiveCount++;
        } else if (acked) {
          ackedCount++;
        } else {
          neitherCount++;
        }
      } finally {
        unsubscribe();
        await connection?.close();
        await proxy.stop();
      }
    }

    // ignore: avoid_print
    print('path probe under 20% loss, $trials trials: '
        '$ackedCount ACKed, $notAckedCount NOT-acked '
        '($falsePositiveCount of those were false positives -- the '
        'connection was proven alive moments later), $neitherCount '
        'neither (probe still pending when checked)');

    if (falsePositiveCount > 0) {
      // ignore: avoid_print
      print('CONCLUSION: the probe has a non-zero false-positive rate '
          '(~${(falsePositiveCount / trials * 100).toStringAsFixed(0)}% '
          'in this sample) under realistic lossy-but-alive conditions. '
          'Wiring it directly into a reconnect decision (N3) would '
          'force unnecessary reconnects on connections that were about '
          'to recover on their own -- it needs corroborating evidence '
          '(e.g. ALL pulls also timing out, not just the probe alone) '
          'before triggering a reconnect, not standalone trust.');
    } else {
      // ignore: avoid_print
      print('CONCLUSION: no false positives observed in this sample '
          '($trials trials at 20% loss) -- inconclusive either way '
          'without a much larger sample; the single-packet, no-retry '
          'design is still a structural risk even at a low observed '
          'rate here.');
    }
  }, timeout: const Timeout(Duration(seconds: 400)));
}

Future<void> _waitUntil(
  bool Function() condition, {
  required Duration timeout,
  String Function()? onTimeout,
}) async {
  final deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail(onTimeout != null ? onTimeout() : 'condition not met within $timeout');
    }
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
}

Future<bool> _commandExists(String command) async {
  try {
    final result = await Process.run('which', [command]);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Uint8List _pemCertToDer(String pem) {
  final match = RegExp(
          r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----')
      .firstMatch(pem)!;
  final b64 = match.group(1)!.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList(base64Decode(b64));
}
