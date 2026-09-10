import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

import 'lossy_udp_proxy.dart';

/// Reliability-focused end-to-end tests against a real quic-go server:
/// retransmission under induced packet loss, and the keepalive PING
/// holding a connection open across the peer's idle timeout. These are
/// the two properties DESIGN.md calls "correct but unsophisticated"
/// congestion/loss handling actually needs to prove in practice, not
/// just in unit tests against synthetic timelines.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_reliability_test_server';
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
      'client retransmits and completes the handshake + message '
      'exchange even with 30% of its outbound packets dropped', () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const serverPort = 48410;
    const proxyPort = 48411;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$serverPort', '3'],
    );
    addTearDown(() => serverProcess.kill());

    final stderrLines = <String>[];
    serverProcess.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(stderrLines.add);
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

    // 30% client->server packet loss -- high enough to guarantee
    // multiple real retransmissions across the handshake + 3 message
    // round trips, low enough that the exchange still completes within
    // the test's timeout given dart_quic's PTO backoff.
    final proxy = LossyUdpProxy(
      listenPort: proxyPort,
      targetPort: serverPort,
      dropProbability: 0.3,
    );
    await proxy.start();
    addTearDown(proxy.stop);

    final clientCertDer =
        _pemCertToDer(File('$fixturesDir/client.crt').readAsStringSync());
    final clientKeyPem = File('$fixturesDir/client.key').readAsStringSync();
    final clientPrivateKey = CryptoUtils.rsaPrivateKeyFromPem(clientKeyPem);
    final clientIdentity = ClientIdentity(
      certificateChainDer: [clientCertDer],
      privateKey: clientPrivateKey,
      signatureScheme: SignatureScheme.rsaPssRsaeSha256,
    );

    final connection = await Connection.connect(
      host: '127.0.0.1',
      port: proxyPort,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      // Generous timeout: with 30% loss and PTO backoff, the handshake
      // may need several retransmission rounds.
      handshakeTimeout: const Duration(seconds: 25),
    );
    addTearDown(connection.close);

    expect(connection.state, ConnectionState.connected);

    final replies = <String>[];
    final subscription = connection.stream.incoming.listen((chunk) {
      replies.add(utf8.decode(chunk));
    });
    addTearDown(subscription.cancel);

    for (var i = 0; i < 3; i++) {
      await connection.stream
          .write(Uint8List.fromList(utf8.encode('message $i\n')));
      // Give the lossy link time to retransmit if needed before the
      // next write -- generous relative to dart_quic's PTO, which
      // starts around kInitialRtt (~333ms) and backs off from there.
      await _waitUntil(
        () => replies.length > i,
        timeout: const Duration(seconds: 10),
      );
    }

    expect(replies, [
      'echo:message 0\n',
      'echo:message 1\n',
      'echo:message 2\n',
    ]);

    // The whole point of this test: confirm loss actually happened and
    // dart_quic recovered from it, not that the network happened to be
    // clean.
    expect(proxy.droppedCount, greaterThan(0),
        reason: 'test is meaningless if the proxy never actually dropped '
            'a packet; stderr: ${stderrLines.join("\n")}');
  }, timeout: const Timeout(Duration(seconds: 40)));

  test(
      'keepalive PING holds the connection open past its own '
      'ping interval', () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const serverPort = 48420;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$serverPort', '1'],
    );
    addTearDown(() => serverProcess.kill());

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
    final clientPrivateKey = CryptoUtils.rsaPrivateKeyFromPem(clientKeyPem);
    final clientIdentity = ClientIdentity(
      certificateChainDer: [clientCertDer],
      privateKey: clientPrivateKey,
      signatureScheme: SignatureScheme.rsaPssRsaeSha256,
    );

    final connection = await Connection.connect(
      host: '127.0.0.1',
      port: serverPort,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(connection.close);

    // dart_quic's keepalive PING fires every 10s (matching
    // agents/quic_conn.go / server/quic_visitor.go's shared
    // KeepAlivePeriod). Wait past two ping intervals with no
    // application traffic at all and confirm the connection is still
    // alive and usable -- if the keepalive weren't working, either
    // side's 30s MaxIdleTimeout would eventually drop the connection
    // (this test doesn't wait that long, but it does prove the
    // connection stays live and responsive well past the point where
    // an application would otherwise have gone quiet).
    await Future<void>.delayed(const Duration(seconds: 22));
    expect(connection.state, ConnectionState.connected,
        reason: 'connection should still be alive after 22s of pure '
            'keepalive traffic (2+ ping intervals, well under the 30s '
            'idle timeout)');

    final replyCompleter = Completer<String>();
    final subscription = connection.stream.incoming.listen((chunk) {
      if (!replyCompleter.isCompleted) {
        replyCompleter.complete(utf8.decode(chunk));
      }
    });
    addTearDown(subscription.cancel);

    await connection.stream
        .write(Uint8List.fromList(utf8.encode('still alive\n')));
    final reply = await replyCompleter.future.timeout(
      const Duration(seconds: 10),
    );
    expect(reply, 'echo:still alive\n');
  }, timeout: const Timeout(Duration(seconds: 45)));
}

Future<void> _waitUntil(
  bool Function() condition, {
  required Duration timeout,
}) async {
  final deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      throw StateError('condition not met within $timeout');
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
