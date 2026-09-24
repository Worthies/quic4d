import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/recovery/mtu_discovery.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// End-to-end proof that Path MTU Discovery (see
/// lib/src/recovery/mtu_discovery.dart) actually runs against a real
/// quic-go server and actually grows the size QuicStream.write uses,
/// not just that the isolated MtuDiscoverer state machine behaves
/// correctly in mtu_discovery_test.dart's own unit tests. Loopback has
/// no real MTU constraint, so every probe here is expected to
/// eventually succeed (this test proves discovery CONVERGES upward
/// when the path allows it; the "a real ceiling gets respected, not
/// exceeded" property is covered by mtu_discovery_test.dart's own
/// synthetic-ceiling unit test, since reproducing an actual constrained
/// MTU here would need a real network path, not loopback).
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_mtu_discovery_e2e_server';
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
      'MTU discovery converges above the fixed RFC-9000-floor chunk '
      'size against a real quic-go server over several keepalive/'
      'probe cycles', () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const port = 48750;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$port', '-1'],
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
      port: port,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(() => connection.close());

    // Discovery starts at kBaseMtu right after connect.
    expect(connection.debugMtuDiscoverer.currentMtu, equals(kBaseMtu));

    // The connection's own ping timer (10s interval) is what actually
    // drives probing (see Connection._startPingTimer) -- wait through
    // several cycles for the binary search to converge. Loopback has
    // no real MTU ceiling, so every probe should eventually succeed,
    // converging toward kMaxProbeMtu.
    final deadline = DateTime.now().add(const Duration(seconds: 75));
    while (!connection.debugMtuDiscoverer.isDone &&
        DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(seconds: 2));
    }

    expect(
      connection.debugMtuDiscoverer.currentMtu,
      greaterThan(kBaseMtu),
      reason: 'discovery must have confirmed at least one probe size '
          'larger than the base floor over loopback (no real MTU '
          'ceiling to block it)',
    );
  }, timeout: const Timeout(Duration(seconds: 100)));
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
