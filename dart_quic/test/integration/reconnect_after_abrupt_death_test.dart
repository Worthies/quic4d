import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

// NOTE: test/integration/server/main.go's shared test server only
// accepts ONE connection for its whole process lifetime (a single
// `listener.Accept()` call, no loop) -- it is not reusable for a
// two-connection scenario. A tiny dedicated multi-accept echo server
// lives in reconnect_after_abrupt_death_server/main.go instead.

/// Reproduces the field report: "every reconnect after an abrupt local
/// network death (errno 103 / ECONNABORTED) has its application-layer
/// pulls (get_visitors etc.) go completely unanswered afterward, every
/// single time" -- to find out whether that is a client-side bug
/// (stale state bleeding into the new connection) or purely a
/// server-side one (as the transport-layer probe already suggests).
///
/// Simulates "the OS yanked the network out from under us" by closing
/// the client's raw UDP socket without going through Connection.close()
/// -- the old connection is abandoned mid-flight exactly like
/// commander's _handleDisconnect does (fire-and-forget,
/// unawaited(close())), not gracefully torn down -- then immediately
/// (no delay) opens a brand new Connection to the same server and
/// sends a real application-layer message on it, asserting the server
/// actually receives and echoes it back.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/multi_accept_server';
  final fixturesDir = '$testDir/fixtures';
  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_reconnect_after_death_server';
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
      'a fresh connection opened right after an abrupt prior-connection '
      'death still gets real application-layer replies', () async {
    if (serverBinaryPath == null) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const serverPort = 48440;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$serverPort'],
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
    final clientIdentity = ClientIdentity(
      certificateChainDer: [clientCertDer],
      privateKey: CryptoUtils.rsaPrivateKeyFromPem(clientKeyPem),
      signatureScheme: SignatureScheme.rsaPssRsaeSha256,
    );

    // --- Connection 1: establish, then kill it abruptly -------------
    final conn1 = await Connection.connect(
      host: '127.0.0.1',
      port: serverPort,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      handshakeTimeout: const Duration(seconds: 10),
    );
    expect(conn1.state, ConnectionState.connected);

    // Abrupt death: abandon it without a graceful close, mirroring
    // commander's _handleDisconnect (unawaited(_connection.close())) --
    // the important part is NOT waiting for teardown to finish before
    // the next connect() begins, since that's the real-world race.
    unawaited(conn1.close());

    // --- Connection 2: open immediately, no delay --------------------
    final conn2 = await Connection.connect(
      host: '127.0.0.1',
      port: serverPort,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(conn2.close);
    expect(conn2.state, ConnectionState.connected);

    // Prove the SECOND connection's application layer actually works:
    // send a real message and require the real echo server's reply.
    final replyCompleter = Completer<String>();
    final sub = conn2.stream.incoming.listen((chunk) {
      if (!replyCompleter.isCompleted) {
        replyCompleter.complete(utf8.decode(chunk));
      }
    });
    addTearDown(sub.cancel);

    await conn2.stream
        .write(Uint8List.fromList(utf8.encode('are you there\n')));
    final reply = await replyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw TimeoutException(
          'connection 2 got NO reply from the server after an abrupt '
          'connection 1 death -- reproduces the field report'),
    );
    expect(reply, 'echo:are you there\n');
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
