import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/dart_quic.dart';
import 'package:test/test.dart';

/// Covers [QuicConnection.openAdditionalBi] specifically -- the actual
/// public API surface commander's quic_client.dart calls (as opposed
/// to test/integration/multi_stream_test.dart, which exercises the
/// lower-level [Connection.openAdditionalStream] this method wraps).
/// Proves the full public API path (QuicEndpoint -> QuicConnection ->
/// openBi + openAdditionalBi) works end-to-end against a real quic-go
/// server, matching leaf's PLAN.md "Remote VNC Forwarding" section's
/// actual consumer.
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
        '${Directory.systemTemp.path}/dart_quic_test_api_multi_stream_server';
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
      'QuicConnection.openBi (control) and openAdditionalBi (a second, '
      'independent stream) both work against a real quic-go server, '
      'through the actual public API surface', () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const port = 47943;
    serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$port', '-1', '-multi'],
    );
    final readyCompleter = Completer<void>();
    final stderrLines = <String>[];
    serverProcess!.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.trim() == 'READY' && !readyCompleter.isCompleted) {
        readyCompleter.complete();
      }
    });
    serverProcess!.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(stderrLines.add);

    await readyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw StateError('Go test server did not start'),
    );

    final clientCertDer =
        _pemCertToDer(File('$fixturesDir/client.crt').readAsStringSync());
    final clientKeyDer =
        _pemKeyToDer(File('$fixturesDir/client.key').readAsBytesSync());

    final endpoint = await QuicEndpoint.createClientWithCert(
      caRoots: [_pemCertToDer(File('$fixturesDir/ca.crt').readAsStringSync())],
      certChain: [clientCertDer],
      clientKey: clientKeyDer,
    );

    final connection = await endpoint.connect(
      addr: '127.0.0.1:$port',
      serverName: 'localhost',
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(() => connection.close());

    final (controlSend, controlRecv) = await connection.openBi();
    final (secondSend, secondRecv) = connection.openAdditionalBi();

    await secondSend.writeAll(
        Uint8List.fromList(utf8.encode('STREAM2 second-stream-payload\n')));
    await controlSend
        .writeAll(Uint8List.fromList(utf8.encode('control-payload\n')));

    final controlReplyCompleter = Completer<String>();
    final controlSub = controlRecv.incoming.listen((chunk) {
      final text = utf8.decode(chunk);
      if (text.contains('echo:control-payload') &&
          !controlReplyCompleter.isCompleted) {
        controlReplyCompleter.complete(text);
      }
    });
    addTearDown(() => controlSub.cancel());

    final secondReplyCompleter = Completer<String>();
    final secondSub = secondRecv.incoming.listen((chunk) {
      final text = utf8.decode(chunk);
      if (!secondReplyCompleter.isCompleted) {
        secondReplyCompleter.complete(text);
      }
    });
    addTearDown(() => secondSub.cancel());

    final controlReply = await controlReplyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw StateError(
          'no reply on control stream. stderr: ${stderrLines.join("\n")}'),
    );
    final secondReply = await secondReplyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () => throw StateError(
          'no reply on second stream. stderr: ${stderrLines.join("\n")}'),
    );

    expect(controlReply, contains('echo:control-payload'));
    expect(secondReply, contains('second-stream-payload'));
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

/// Verbatim copy of quic_client.dart's own `_pemKeyToDer` (see
/// quic_api_interop_test.dart's identical copy, which this test
/// mirrors the overall structure of).
Uint8List _pemKeyToDer(List<int> pemBytes) {
  final pem = utf8.decode(pemBytes);
  final regex = RegExp(
      r'-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----([A-Za-z0-9+/=\s]+?)-----END \1-----');
  final match = regex.firstMatch(pem);
  if (match == null) {
    throw const FormatException('no PEM private key found in input');
  }
  final b64 = match.group(2)!.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList(base64Decode(b64));
}
