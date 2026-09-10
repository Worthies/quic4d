import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// True end-to-end interop test against a **real quic-go server**
/// (test/integration/server/main.go), mirroring
/// server/quic_visitor.go's exact TLS config (ALPN="leaf-commander",
/// RequireAndVerifyClientCert) -- this is the acceptance gate
/// DESIGN.md's testing strategy calls for: every lower-level piece
/// already has RFC-vector golden tests, but only a live quic-go peer
/// can confirm the whole stack actually interoperates with the
/// real-world implementation this library exists to talk to.
///
/// Skipped automatically if `go` isn't available on PATH, so the rest
/// of the suite (and CI environments without a Go toolchain) isn't
/// blocked by this -- but this test itself must be run at least once
/// per milestone-4-affecting change; see DESIGN.md's testing strategy.
void main() {
  // `dart test` compiles tests into a separate bundle, so
  // Platform.script does not point at this file -- resolve paths
  // relative to the package root (dart test's working directory)
  // instead.
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  Process? serverProcess;
  String? serverBinaryPath;

  setUpAll(() async {
    final hasGo = await _commandExists('go');
    if (!hasGo) return; // individual tests below check this and skip.

    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_test_quic_server';
    final build = await Process.run(
      'go',
      ['build', '-o', serverBinaryPath!, '.'],
      workingDirectory: serverDir,
    );
    if (build.exitCode != 0) {
      throw StateError('failed to build Go test server:\n${build.stderr}');
    }
  });

  tearDown(() async {
    serverProcess?.kill();
    serverProcess = null;
  });

  test(
      'full mTLS handshake + stream round trip against a real quic-go '
      'server', () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const port = 47932;
    serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$port'],
    );
    final readyCompleter = Completer<void>();
    final stdoutLines = <String>[];
    serverProcess!.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      stdoutLines.add(line);
      if (line.trim() == 'READY' && !readyCompleter.isCompleted) {
        readyCompleter.complete();
      }
    });
    final stderrLines = <String>[];
    serverProcess!.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(stderrLines.add);

    await readyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw StateError(
          'Go test server did not print READY in time. stderr: '
          '${stderrLines.join("\n")}'),
    );

    final clientCertDer =
        _pemCertToDer(File('$fixturesDir/client.crt').readAsStringSync());
    final clientKeyPem = File('$fixturesDir/client.key').readAsStringSync();
    final clientPrivateKey = CryptoUtils.rsaPrivateKeyFromPem(clientKeyPem);

    final clientIdentity = ClientIdentity(
      certificateChainDer: [clientCertDer],
      privateKey: clientPrivateKey,
      signatureScheme: SignatureScheme.rsaPssRsaeSha256,
    );

    List<Uint8List>? observedServerChain;
    final connection = await Connection.connect(
      host: '127.0.0.1',
      port: port,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      onServerCertificateChain: (chain) => observedServerChain = chain,
      handshakeTimeout: const Duration(seconds: 10),
    );

    addTearDown(() => connection.close());

    expect(connection.state, ConnectionState.connected);
    expect(observedServerChain, isNotNull);
    expect(observedServerChain, isNotEmpty);

    final replyCompleter = Completer<String>();
    final subscription = connection.stream.incoming.listen((chunk) {
      if (!replyCompleter.isCompleted) {
        replyCompleter.complete(utf8.decode(chunk));
      }
    });
    addTearDown(() => subscription.cancel());

    await connection.stream
        .write(Uint8List.fromList(utf8.encode('hello from dart_quic\n')));

    final reply = await replyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw StateError(
          'no reply from Go server within timeout. server stderr: '
          '${stderrLines.join("\n")}, stdout: ${stdoutLines.join("\n")}'),
    );

    expect(reply, contains('echo:hello from dart_quic'));
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
