import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:dart_quic/src/connection.dart';
import 'package:dart_quic/src/diagnostics.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:test/test.dart';

/// Isolates the exact scenario path_probe_false_positive_test.dart
/// stumbled onto: a connection sends ONE small application message,
/// its packet is deterministically dropped exactly once, and nothing
/// else. Does dart_quic's PTO/retransmission machinery recover it
/// within a bounded time -- proving the earlier probabilistic-loss
/// test's stalls were something else (server bug, framing bug, or a
/// genuine dart_quic retransmission defect this isolates cleanly)?
void main() {
  final testDir = '${Directory.current.path}/test/integration';
  final serverDir = '$testDir/multi_accept_server';
  final fixturesDir = '$testDir/fixtures';
  String? serverBinaryPath;

  setUpAll(() async {
    if (!await _commandExists('go')) return;
    serverBinaryPath =
        '${Directory.systemTemp.path}/dart_quic_single_drop_server';
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
      'a single deterministically-dropped application packet recovers '
      'via PTO retransmission within a bounded time', () async {
    if (serverBinaryPath == null) {
      markTestSkipped('go toolchain not available on PATH');
      return;
    }

    const serverPort = 48480;
    const proxyPort = 48481;
    final serverProcess = await Process.start(
      serverBinaryPath!,
      [fixturesDir, '127.0.0.1:$serverPort'],
    );
    addTearDown(() => serverProcess.kill());

    final serverStderr = <String>[];
    serverProcess.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(serverStderr.add);

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

    final diagnosticLog = <String>[];
    final unsubscribe = QuicDiagnostics.listen(diagnosticLog.add);
    addTearDown(unsubscribe);

    // Deterministic single-shot-drop proxy: drops exactly the Nth
    // client->server packet (by count, not probability), forwards
    // everything else -- and NEVER drops server->client.
    final dropOnCount = _DeterministicDropProxy(
      listenPort: proxyPort,
      targetPort: serverPort,
      dropPacketNumber: 3, // handshake uses a few packets; pick one
      // safely inside the post-handshake application traffic based on
      // this test's own observed packet counts below.
    );
    await dropOnCount.start();
    addTearDown(dropOnCount.stop);

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
      port: proxyPort,
      serverName: 'localhost',
      clientIdentity: clientIdentity,
      handshakeTimeout: const Duration(seconds: 15),
    );
    addTearDown(connection.close);

    final replies = <String>[];
    connection.stream.incoming.listen((c) => replies.add(utf8.decode(c)));

    // Drop the NEXT THREE outbound packets consecutively -- e.g. the
    // probe ping, its first PTO retransmission, and the marker write
    // itself, or some similar tight burst -- the kind of correlated
    // loss a real proxy's independent-per-packet 20% roll produces
    // occasionally (P(>=2 consecutive) is not rare over dozens of
    // packets), which the earlier single-drop trial above didn't
    // exercise.
    dropOnCount
      ..armDropNext()
      ..armDropNext()
      ..armDropNext();

    const marker = 'burst-drop-marker';
    await connection.stream.write(Uint8List.fromList(utf8.encode('$marker\n')));

    await _waitUntil(
      () => replies.any((r) => r.contains(marker)),
      timeout: const Duration(seconds: 20),
      onTimeout: () => 'marker never echoed back after a 3-packet burst '
          'drop. replies=$replies; dropped packet numbers: '
          '${dropOnCount.droppedAtCounts}; total forwarded: '
          '${dropOnCount.forwardedCount}; server stderr: '
          '${serverStderr.join(' | ')}; diagnostic log: $diagnosticLog',
    );
  }, timeout: const Timeout(Duration(seconds: 40)));
}

/// Drops exactly one client->server packet, chosen by an explicit
/// arm-then-drop-the-next-one call rather than a fixed count from
/// connection start (handshake packet counts can vary run to run),
/// so the single drop lands deterministically on a packet sent AFTER
/// the caller decides -- e.g. right before a specific write().
class _DeterministicDropProxy {
  final int listenPort;
  final int targetPort;
  final int dropPacketNumber; // unused with armDropNext(), kept for clarity

  RawDatagramSocket? _clientSocket;
  RawDatagramSocket? _serverSocket;
  InternetAddress? _clientAddress;
  int? _clientPort;

  int _armedDrops = 0;
  int forwardedCount = 0;
  final List<int> droppedAtCounts = [];

  _DeterministicDropProxy({
    required this.listenPort,
    required this.targetPort,
    required this.dropPacketNumber,
  });

  void armDropNext() => _armedDrops++;

  Future<void> start() async {
    _clientSocket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, listenPort);
    _serverSocket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);

    _clientSocket!.listen((event) {
      if (event != RawSocketEvent.read) return;
      final datagram = _clientSocket!.receive();
      if (datagram == null) return;
      _clientAddress = datagram.address;
      _clientPort = datagram.port;

      if (_armedDrops > 0) {
        _armedDrops--;
        droppedAtCounts.add(forwardedCount);
        return;
      }
      forwardedCount++;
      _serverSocket!
          .send(datagram.data, InternetAddress.loopbackIPv4, targetPort);
    });

    _serverSocket!.listen((event) {
      if (event != RawSocketEvent.read) return;
      final datagram = _serverSocket!.receive();
      if (datagram == null) return;
      final clientAddress = _clientAddress;
      final clientPort = _clientPort;
      if (clientAddress == null || clientPort == null) return;
      _clientSocket!.send(datagram.data, clientAddress, clientPort);
    });
  }

  Future<void> stop() async {
    _clientSocket?.close();
    _serverSocket?.close();
  }
}

Future<void> _waitUntil(
  bool Function() condition, {
  required Duration timeout,
  String Function()? onTimeout,
}) async {
  final deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail(onTimeout != null
          ? onTimeout()
          : 'condition not met within $timeout');
    }
    await Future<void>.delayed(const Duration(milliseconds: 50));
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
