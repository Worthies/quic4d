import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Integration coverage for [Connection.connect]'s own
/// `initialCongestionWindow` parameter (see
/// `CongestionController.initialWindowOverride`'s own doc comment in
/// recovery/congestion_control.dart for the full rationale: commander's
/// Remote VNC Forwarding sends FramebufferUpdate payloads that can be
/// hundreds of KB to several MB, and RFC 9002's own conservative
/// ~14.7KB default initial window forces such a payload through many
/// "send a small window, wait a full round trip" cycles before slow
/// start ramps up far enough -- a fixed, generously-sized override lets
/// the whole payload go out in its very first round trip instead).
///
/// Correctness only (not a timing/perf assertion): localhost's own
/// near-zero RTT means the RTT-per-window-cycle cost this override
/// targets is not meaningfully observable in this test environment
/// (see PLAN.md's own notes on this feature's real-network origin) --
/// what this DOES verify is that overriding the window doesn't break
/// anything (still round-trips correctly, still respects flow control
/// and eventual loss-driven congestion avoidance, both already covered
/// unit-level in congestion_control_test.dart).
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_icw_test_server';
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
      'write() round-trips a 2MB payload correctly with '
      'initialCongestionWindow set far above RFC 9002\'s own default',
      () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const port = 48620;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$port', '1'],
    );
    addTearDown(() => serverProcess.kill());

    final readyCompleter = Completer<void>();
    final stderrLines = <String>[];
    serverProcess.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.trim() == 'READY' && !readyCompleter.isCompleted) {
        readyCompleter.complete();
      }
    });
    serverProcess.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(stderrLines.add);
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
      // Far above RFC 9002's own ~14.7KB default -- sized so the
      // entire payload below fits in a single congestion window.
      initialCongestionWindow: 4 * 1024 * 1024,
    );
    addTearDown(() => connection.close());

    const sizeBytes = 2 * 1024 * 1024;
    final payload = 'A' * (sizeBytes - 40);
    final message = '{"type":"message","content":"$payload"}\n';
    final bytes = utf8.encode(message);

    final replyCompleter = Completer<void>();
    final received = <int>[];
    final sub = connection.stream.incoming.listen((chunk) {
      received.addAll(chunk);
      if (received.length >= bytes.length && !replyCompleter.isCompleted) {
        replyCompleter.complete();
      }
    });
    addTearDown(() => sub.cancel());

    await connection.stream.write(Uint8List.fromList(bytes));

    await replyCompleter.future.timeout(
      const Duration(seconds: 20),
      onTimeout: () => throw StateError(
          'no full echo within timeout; received ${received.length}/'
          '${bytes.length} bytes so far. server stderr: '
          '${stderrLines.join("\n")}'),
    );

    expect(received.length, bytes.length);
    expect(utf8.decode(received), message);
  }, timeout: const Timeout(Duration(seconds: 30)));
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
