// Manual end-to-end check of dart_quic against a REAL leaf server
// (commander.horsing.top:8443), using the same debug certs the real
// commander app uses (~/.config/commander/debug/). Not part of the
// automated test suite: it depends on an external server being up and
// reachable, so run it by hand:
//
//   dart run tool/real_server_check.dart
//
// It mirrors commander/lib/client/quic_client.dart's exact sequence:
// PEM->DER conversion, QuicEndpoint.createClientWithCert, connect,
// openBi, the {"type":"_quic_hello"} frame that unblocks the server's
// AcceptStream, then the newline-delimited JSON loop.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/dart_quic.dart';

const host = 'commander.horsing.top';
const port = 8443;
const certDir = String.fromEnvironment(
  'CERT_DIR',
  defaultValue: '.config/commander/debug',
);
const certName = String.fromEnvironment(
  'CERT_NAME',
  defaultValue: 'commander-asus',
);

Future<void> main() async {
  final home = Platform.environment['HOME']!;
  final caPem = File('$home/$certDir/ca.crt').readAsBytesSync();
  final certPem = File('$home/$certDir/$certName.crt').readAsBytesSync();
  final keyPem = File('$home/$certDir/$certName.key').readAsBytesSync();
  print('certs loaded from $home/$certDir ($certName)');

  final sw = Stopwatch()..start();

  final endpoint = await QuicEndpoint.createClientWithCert(
    caRoots: pemChainToDer(caPem),
    certChain: pemChainToDer(certPem),
    clientKey: pemKeyToDer(keyPem),
  );

  List<Uint8List>? serverChain;
  final connection = await endpoint.connect(
    addr: '$host:$port',
    serverName: host,
    onServerCertificateChain: (chain) => serverChain = chain,
    handshakeTimeout: const Duration(seconds: 15),
  );
  print('handshake complete in ${sw.elapsedMilliseconds}ms '
      '(server chain: ${serverChain?.length ?? 0} cert(s))');

  final (send, recv) = await connection.openBi();

  final serverLines = <String>[];
  final lineSink = StreamController<String>.broadcast();
  final buffer = <int>[];
  late final StreamSubscription<Uint8List> sub;
  sub = recv.incoming.listen((chunk) {
    buffer.addAll(chunk);
    int idx;
    while ((idx = buffer.indexOf(10)) >= 0) {
      final line = utf8.decode(buffer.sublist(0, idx));
      buffer.removeRange(0, idx + 1);
      if (line.trim().isNotEmpty) {
        serverLines.add(line);
        lineSink.add(line);
      }
    }
  });

  // commander's handshake frame: makes the stream observable to the
  // server's AcceptStream (server recognizes and silently skips it).
  await send.writeAll(Uint8List.fromList(utf8.encode('{"type":"_quic_hello"}\n')));

  try {
    final welcome = await lineSink.stream
        .firstWhere((l) => _jsonType(l) == 'welcome')
        .timeout(const Duration(seconds: 10));
    final decoded = jsonDecode(welcome) as Map<String, dynamic>;
    print('welcome: visitor_name=${decoded['visitor_name']}, '
        'visitors=${(decoded['visitors'] as List).length}');
  } on TimeoutException {
    stderr.writeln('no welcome within 10s; received: $serverLines');
    rethrow;
  }

  // Round-trip: get_visitors → expect a "visitors" reply; ping → pong.
  await send.writeAll(
      Uint8List.fromList(utf8.encode('{"type":"get_visitors","content":""}\n')));
  await lineSink.stream
      .firstWhere((l) => _jsonType(l) == 'visitors')
      .timeout(const Duration(seconds: 10));
  print('get_visitors -> visitors reply OK');

  await send.writeAll(
      Uint8List.fromList(utf8.encode('{"type":"ping","content":""}\n')));
  await lineSink.stream
      .firstWhere((l) => _jsonType(l) == 'pong')
      .timeout(const Duration(seconds: 10));
  print('ping -> pong OK');

  // Hold the connection idle across two keepalive intervals to prove
  // dart_quic's 10s PING keeps it alive against the real server's 30s
  // idle timeout (same as the loopback keepalive test, but over the
  // real internet path).
  print('idling 22s across keepalive pings...');
  await Future<void>.delayed(const Duration(seconds: 22));
  if (connection.state != ConnectionState.connected) {
    throw StateError('connection did not survive 22s idle via keepalive '
        '(state=${connection.state})');
  }
  await send.writeAll(
      Uint8List.fromList(utf8.encode('{"type":"ping","content":""}\n')));
  await lineSink.stream
      .firstWhere((l) => _jsonType(l) == 'pong')
      .timeout(const Duration(seconds: 10));
  print('post-idle ping -> pong OK (keepalive works over real path)');

  await sub.cancel();
  await lineSink.close();
  await connection.close();
  print('ALL CHECKS PASSED against $host:$port');
}

String? _jsonType(String line) {
  if (line.isEmpty || line.codeUnitAt(0) != 123) return null;
  try {
    return (jsonDecode(line) as Map<String, dynamic>)['type'] as String?;
  } catch (_) {
    return null;
  }
}

List<Uint8List> pemChainToDer(List<int> pemBytes) {
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

Uint8List pemKeyToDer(List<int> pemBytes) {
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
