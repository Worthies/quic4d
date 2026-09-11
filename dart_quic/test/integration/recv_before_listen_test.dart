import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Regression test for the first-entry data-loss bug: the incoming
/// stream used to be a bare broadcast controller, which DROPS events
/// added before any listener exists. Bytes the peer sends in the
/// window between openBi()/write() and the app's listen() vanished --
/// commander saw this as "empty visitor panel, nothing received until
/// the stale watchdog forced a reconnect" because the server's
/// welcome message landed exactly in that window. Received chunks must
/// instead be parked and replayed in order once the first listener
/// attaches.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';
  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_recv_before_listen_server';
    final build = await Process.run(
      'go',
      ['build', '-o', serverBinaryPath!, '.'],
      workingDirectory: serverDir,
    );
    if (build.exitCode != 0) {
      throw StateError('failed to build Go test server:\n${build.stderr}');
    }
  });

  test('data delivered before the first listen() is parked and replayed',
      () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const serverPort = 48431;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$serverPort'],
    );
    addTearDown(() => serverProcess.kill());

    final readyCompleter = Completer<void>();
    // "READY" goes to the server's stdout (fmt.Println); stderr only
    // carries its logs.
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

    final connection = await Connection.connect(
      host: '127.0.0.1',
      port: serverPort,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(connection.close);

    await connection.stream
        .write(Uint8List.fromList(utf8.encode('parked reply\n')));
    await Future<void>.delayed(const Duration(milliseconds: 800));

    // Now attach the (first) listener: everything parked above must
    // be replayed in order, not silently dropped.
    final replayed = Completer<String>();
    final subscription = connection.stream.incoming.listen((chunk) {
      if (!replayed.isCompleted) {
        replayed.complete(utf8.decode(chunk));
      }
    });
    addTearDown(subscription.cancel);

    final reply =
        await replayed.future.timeout(const Duration(seconds: 10));
    expect(reply, 'echo:parked reply\n');
  }, timeout: const Timeout(Duration(seconds: 45)));
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
