import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Regression coverage for the EXACT combination Remote VNC
/// Forwarding's low-bandwidth mode exercises in production (see leaf's
/// PLAN.md "Remote VNC Forwarding" section): a large, unframed binary
/// payload round-tripped on the SECOND stream (opened via
/// [Connection.openAdditionalStream], mirroring VncManager's own
/// dedicated data stream -- never the control stream every other
/// large-payload test in this package exercises), with a non-default
/// `initialCongestionWindow` in effect. large_stream_write_test.dart
/// and initial_congestion_window_test.dart each cover one half of this
/// combination (large payload on stream 0; the window override on
/// stream 0) but neither covers the second stream specifically, which
/// is the one gap a user-reported "low bandwidth mode can no longer
/// connect at all" regression could hide in without any of the
/// existing suite catching it.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_second_stream_test_server';
    final build = await Process.run(
      'go',
      ['build', '-o', serverBinaryPath!, '.'],
      workingDirectory: serverDir,
    );
    if (build.exitCode != 0) {
      throw StateError('failed to build Go test server:\n${build.stderr}');
    }
  });

  for (final (label, initialCongestionWindow) in [
    ('RFC 9002 default window', null),
    ('a 1 MiB override (commander\'s own VNC-forwarding value)',
        1 * 1024 * 1024),
  ]) {
    test(
        'a 3MB binary payload on the SECOND (non-control) stream round-'
        'trips byte-for-byte against a real quic-go server, with '
        '$label', () async {
      if (!await _commandExists('go')) {
        markTestSkipped('go toolchain not available on PATH');
        return;
      }

      final port = 48700 +
          (initialCongestionWindow == null ? 0 : 1); // distinct ports
      final serverProcess = await Process.start(
        serverBinaryPath!,
        [fixturesDir, '127.0.0.1:$port', '-1', '-multi-echo-all'],
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
        initialCongestionWindow: initialCongestionWindow,
      );
      addTearDown(() => connection.close());

      // Open the SECOND stream -- mirrors VncManager._maybeStartBridging
      // opening the dedicated VNC data stream via
      // ChatTransport.openVncStream/QuicConnection.openAdditionalBi,
      // never the control stream.
      final dataStream = connection.openAdditionalStream();

      // Tag line first (leaf server/vnc_relay.go's own wire contract),
      // then a large pseudo-random binary payload with no message
      // framing at all -- matching real VNC/RFB protocol bytes, which
      // are NOT newline-delimited the way the control channel's JSON
      // is (a payload containing arbitrary byte values, including
      // 0x0A, is exactly what a naive newline-based test fixture would
      // fail to exercise correctly).
      final rnd = Random(1234);
      const payloadSize = 3 * 1024 * 1024; // 3MB
      final payload = Uint8List(payloadSize);
      for (var i = 0; i < payloadSize; i++) {
        payload[i] = rnd.nextInt(256);
      }

      final received = <int>[];
      final receivedCompleter = Completer<void>();
      final sub = dataStream.incoming.listen((chunk) {
        received.addAll(chunk);
        if (received.length >= payloadSize && !receivedCompleter.isCompleted) {
          receivedCompleter.complete();
        }
      });
      addTearDown(() => sub.cancel());

      await dataStream.write(utf8.encode('STREAM2 '));
      await dataStream.write(payload);

      await receivedCompleter.future.timeout(
        const Duration(seconds: 30),
        onTimeout: () => throw StateError(
            'no full echo within timeout; received ${received.length}/'
            '$payloadSize bytes so far. server stderr: '
            '${stderrLines.join("\n")}'),
      );

      // The server's own echo-all handler doesn't strip the "STREAM2 "
      // tag prefix (unlike handleSecondStream's single-tag-line
      // variant) -- it echoes literally everything it reads, so the
      // first 8 bytes of what we received are that prefix, echoed
      // back, and the payload itself starts right after.
      const prefixLength = 8; // 'STREAM2 '.length
      expect(received.length, equals(prefixLength + payloadSize));
      expect(
        received.sublist(prefixLength),
        equals(payload),
        reason: 'the 3MB binary payload must round-trip byte-for-byte on '
            'the second stream',
      );
    }, timeout: const Timeout(Duration(seconds: 45)));
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
