import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Live interop test proving real multi-stream support against a real
/// quic-go server (see test/integration/server/main.go's own "-multi"
/// flag): this connection's own control stream (stream 0, opened
/// automatically on handshake completion -- see [Connection.stream])
/// stays usable exactly as before, AND a second, independently-opened
/// bidirectional stream (via [Connection.openAdditionalStream]) carries
/// its own data with no cross-talk between the two -- this is
/// commander's Remote VNC Forwarding's own real-world requirement (see
/// leaf's PLAN.md "Remote VNC Forwarding" section, Correction #2): the
/// existing JSON control channel and a dedicated VNC data stream must
/// coexist on one connection.
///
/// Skipped automatically if `go` isn't available on PATH, matching
/// quic_go_interop_test.dart's own precedent.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  Process? serverProcess;
  String? serverBinaryPath;

  setUpAll(() async {
    final hasGo = await _commandExists('go');
    if (!hasGo) return;

    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_test_multi_stream_server';
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
      'a second, independently-opened bidirectional stream carries its '
      'own data with no cross-talk against the control stream, against '
      'a real quic-go server', () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const port = 47940;
    serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$port', '-1', '-multi'],
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

    final connection = await Connection.connect(
      host: '127.0.0.1',
      port: port,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(() => connection.close());
    expect(connection.state, ConnectionState.connected);

    // Open the second stream FIRST and tag it, so the Go server (which
    // pairs incoming streams by a leading tag line, mirroring
    // leaf server/vnc_relay.go's own real wire contract) can route
    // bytes on it independently of the control stream.
    final secondStream = connection.openAdditionalStream();
    await secondStream.write(utf8.encode('STREAM2 hello-from-stream-2\n'));

    // The control stream (stream 0) still works normally and
    // independently -- write something distinguishable on it too.
    final controlReplyCompleter = Completer<String>();
    final controlSub = connection.stream.incoming.listen((chunk) {
      final text = utf8.decode(chunk);
      if (text.contains('echo:hello-from-control') &&
          !controlReplyCompleter.isCompleted) {
        controlReplyCompleter.complete(text);
      }
    });
    addTearDown(() => controlSub.cancel());
    await connection.stream.write(utf8.encode('hello-from-control\n'));

    final secondReplyCompleter = Completer<String>();
    final secondSub = secondStream.incoming.listen((chunk) {
      final text = utf8.decode(chunk);
      if (!secondReplyCompleter.isCompleted) {
        secondReplyCompleter.complete(text);
      }
    });
    addTearDown(() => secondSub.cancel());

    final controlReply = await controlReplyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw StateError(
          'no reply on control stream within timeout. server stderr: '
          '${stderrLines.join("\n")}'),
    );
    final secondReply = await secondReplyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw StateError(
          'no reply on second stream within timeout. server stderr: '
          '${stderrLines.join("\n")}'),
    );

    expect(controlReply, contains('echo:hello-from-control'));
    // The Go "-multi" server echoes the second stream's own payload
    // back verbatim (see main.go's own tag-then-echo handling), proving
    // this stream's bytes were received and routed independently of
    // the control stream's own reassembly.
    expect(secondReply, contains('hello-from-stream-2'));
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
