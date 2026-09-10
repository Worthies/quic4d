import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/dart_quic.dart';
import 'package:test/test.dart';

/// End-to-end interop test driven entirely through the *public*
/// QuicEndpoint/QuicConnection/QuicSendStream/QuicRecvStream API (not
/// dart_quic's internal Connection/ClientHandshake classes) -- this is
/// the actual surface commander/lib/client/quic_client.dart would use
/// after switching from quic4d, so it's the real acceptance test for
/// milestone 5's "shaped like quic4d" claim, mirroring the PEM->DER
/// conversion quic_client.dart already does today.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_api_interop_test_server';
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
      'full mTLS handshake + stream round trip via the public '
      'QuicEndpoint/QuicConnection API', () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const port = 48500;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$port', '1'],
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

    // Mirrors quic_client.dart's own _pemChainToDer/_pemKeyToDer PEM
    // parsing exactly, since that's the real call site this API is
    // designed to slot into unchanged.
    final caRoots =
        _pemChainToDer(File('$fixturesDir/ca.crt').readAsBytesSync());
    final certChain =
        _pemChainToDer(File('$fixturesDir/client.crt').readAsBytesSync());
    final clientKey =
        _pemKeyToDer(File('$fixturesDir/client.key').readAsBytesSync());

    final endpoint = await QuicEndpoint.createClientWithCert(
      caRoots: caRoots,
      certChain: certChain,
      clientKey: clientKey,
    );

    List<Uint8List>? observedServerChain;
    final connection = await endpoint.connect(
      addr: '127.0.0.1:$port',
      serverName: 'localhost',
      onServerCertificateChain: (chain) => observedServerChain = chain,
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(() => connection.close());

    expect(connection.state, ConnectionState.connected);
    expect(observedServerChain, isNotNull);
    expect(observedServerChain, isNotEmpty);

    final (sendStream, recvStream) = await connection.openBi();

    final replyCompleter = Completer<String>();
    final subscription = recvStream.incoming.listen((chunk) {
      if (!replyCompleter.isCompleted) {
        replyCompleter.complete(utf8.decode(chunk));
      }
    });
    addTearDown(subscription.cancel);

    await sendStream
        .writeAll(Uint8List.fromList(utf8.encode('hello via public API\n')));

    final reply = await replyCompleter.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () =>
          throw StateError('no reply within timeout. server stderr: '
              '${stderrLines.join("\n")}'),
    );

    expect(reply, 'echo:hello via public API\n');

    // openBi() a second time must return the *same* stream pair
    // (DESIGN.md's single-stream model), not open a fresh one.
    final (sendStream2, recvStream2) = await connection.openBi();
    expect(identical(sendStream, sendStream2), isTrue);
    expect(identical(recvStream, recvStream2), isTrue);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('QuicRecvStream.read() delivers a chunk (quic4d-style poll API)',
      () async {
    if (!await _commandExists('go')) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const port = 48510;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$port', '1'],
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

    final caRoots =
        _pemChainToDer(File('$fixturesDir/ca.crt').readAsBytesSync());
    final certChain =
        _pemChainToDer(File('$fixturesDir/client.crt').readAsBytesSync());
    final clientKey =
        _pemKeyToDer(File('$fixturesDir/client.key').readAsBytesSync());

    final endpoint = await QuicEndpoint.createClientWithCert(
      caRoots: caRoots,
      certChain: certChain,
      clientKey: clientKey,
    );
    final connection = await endpoint.connect(
      addr: '127.0.0.1:$port',
      serverName: 'localhost',
      handshakeTimeout: const Duration(seconds: 10),
    );
    addTearDown(() => connection.close());

    final (sendStream, recvStream) = await connection.openBi();
    await sendStream.writeAll(Uint8List.fromList(utf8.encode('poll me\n')));

    final chunk = await recvStream.read().timeout(const Duration(seconds: 10));
    expect(chunk, isNotNull);
    expect(utf8.decode(chunk!), 'echo:poll me\n');
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

/// Verbatim copy of quic_client.dart's own `_pemChainToDer` -- see that
/// file's doc comment for the rationale; kept identical here since the
/// whole point of this test is proving the real call site's conversion
/// code needs no changes.
List<Uint8List> _pemChainToDer(List<int> pemBytes) {
  final pem = utf8.decode(pemBytes);
  final out = <Uint8List>[];
  final regex = RegExp(
      r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----');
  for (final m in regex.allMatches(pem)) {
    final b64 = m.group(1)!.replaceAll(RegExp(r'\s'), '');
    out.add(Uint8List.fromList(base64Decode(b64)));
  }
  if (out.isEmpty) {
    throw const FormatException('no PEM certificates found in input');
  }
  return out;
}

/// Verbatim copy of quic_client.dart's own `_pemKeyToDer`.
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
