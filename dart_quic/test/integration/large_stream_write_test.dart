import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Regression test for a write() call whose payload doesn't fit in a
/// single packet: [QuicStream.write] used to place an entire write()
/// call's data into ONE STREAM frame in ONE UDP packet, however large.
/// That's invisible for short chat messages but breaks completely once
/// a message approaches even ~1KB against a real quic-go peer (which
/// silently drops any packet exceeding the negotiated
/// max_udp_payload_size) and outright throws an EMSGSIZE
/// SocketException once the payload nears 64KB (the OS UDP `sendto()`
/// limit) -- both reproduced live against
/// server/quic_visitor.go's real quic-go-based server before
/// [kMaxStreamFrameChunkSize]-based chunking was added.
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/server';
  final fixturesDir = '$testDir/fixtures';

  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_large_write_test_server';
    final build = await Process.run(
      'go',
      ['build', '-o', serverBinaryPath!, '.'],
      workingDirectory: serverDir,
    );
    if (build.exitCode != 0) {
      throw StateError('failed to build Go test server:\n${build.stderr}');
    }
  });

  // 12 MiB deliberately exceeds dart_quic's advertised 10 MiB initial
  // flow-control windows in BOTH directions: the outbound half can only
  // complete if the client honors the server's MAX_DATA/MAX_STREAM_DATA
  // grants, and the echoed inbound half only if the client sends its own
  // window updates -- before flow control was implemented, the server
  // would silently stop sending at the 10 MiB mark (stall -> watchdog
  // reconnect loop in production).
  for (final sizeBytes in [64 * 1024, 2 * 1024 * 1024, 12 * 1024 * 1024]) {
    test(
        'write() round-trips a $sizeBytes-byte payload against a real '
        'quic-go server', () async {
      if (!await _commandExists('go')) {
        markTestSkipped('go toolchain not available on PATH');
        return;
      }

      final port = 48500 + (sizeBytes % 100);
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
      );
      addTearDown(() => connection.close());

      // A JSON-object-shaped payload, matching commander's real wire
      // framing (see main.go's echo-verbatim-if-JSON-shaped behavior) --
      // this exercises the same "one big message" path a chat client's
      // large paste/file-as-base64 message would.
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
