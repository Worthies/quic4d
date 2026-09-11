// Manual reproduction of the "visitor list missing after idle disconnect
// + reconnect" report against a REAL leaf server. Two scenarios:
//
//   dart run tool/reconnect_check.dart
//
// A) silent death: drop the connection WITHOUT a close (mimics a dead
//    NAT path / phone sleep), reconnect immediately — the server has
//    NOT yet reaped the old visitor (30s MaxIdleTimeout), so this shows
//    what the second connection's welcome/visitors look like while the
//    ghost entry still exists.
// B) after reaping: same, but wait 35s first so the server has kicked
//    the ghost — the steady-state reconnect path.
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

  final endpoint = await QuicEndpoint.createClientWithCert(
    caRoots: pemChainToDer(caPem),
    certChain: pemChainToDer(certPem),
    clientKey: pemKeyToDer(keyPem),
  );

  final first = await connectAndGreet(endpoint, 'A1');
  print('--- scenario A: silent death, immediate reconnect ---');
  // Drop the handle without close(): from this process's view the path
  // is dead, but the server still sees the visitor until its idle
  // timeout fires. This mirrors a phone that slept mid-connection.
  await Future<void>.delayed(const Duration(seconds: 2));
  final second = await connectAndGreet(endpoint, 'A2');
  final ghost = (second.visitors)
      .where((v) => v.startsWith('commander@'))
      .toList();
  print('commander entries in A2 welcome visitors: $ghost '
      '(A1 was ${first.visitorName})');

  // get_visitors on the second connection: the authoritative full list.
  await second.sendGetVisitors(second);
  final fullList = await second.nextOfType('visitors', 10);
  final decoded = jsonDecode(fullList) as Map<String, dynamic>;
  print('A2 get_visitors -> ${(decoded['visitors'] as List).length} visitors: '
      '${decoded['visitors']}');

  print('--- scenario B: after server reaps the ghost (35s) ---');
  await Future<void>.delayed(const Duration(seconds: 35));
  final third = await connectAndGreet(endpoint, 'B1');
  final ghostB =
      (third.visitors).where((v) => v.startsWith('commander@')).toList();
  print('commander entries in B1 welcome visitors: $ghostB '
      '(B1 is ${third.visitorName})');

  await third.connection.close();
  await second.connection.close();
  print('DONE');
}

class Conn {
  final QuicConnection connection;
  final QuicSendStream send;
  final String visitorName;
  final List<String> visitors;
  final StreamController<String> lines;
  final StreamSubscription<Uint8List> sub;

  Conn(this.connection, this.send, this.visitorName, this.visitors,
      this.lines, this.sub);

  Future<String> nextOfType(String type, int timeoutSecs) => lines.stream
      .firstWhere((l) => _jsonType(l) == type)
      .timeout(Duration(seconds: timeoutSecs));

  Future<void> sendGetVisitors(Conn c) => c.send.writeAll(Uint8List.fromList(
      utf8.encode('{"type":"get_visitors","content":""}\n')));
}

Future<Conn> connectAndGreet(QuicEndpoint endpoint, String label) async {
  final connection = await endpoint.connect(
    addr: '$host:$port',
    serverName: host,
    handshakeTimeout: const Duration(seconds: 15),
  );
  final (send, recv) = await connection.openBi();
  await send.writeAll(
      Uint8List.fromList(utf8.encode('{"type":"_quic_hello"}\n')));

  final lines = StreamController<String>.broadcast();
  final buffer = <int>[];
  final sub = recv.incoming.listen((chunk) {
    buffer.addAll(chunk);
    int idx;
    while ((idx = buffer.indexOf(10)) >= 0) {
      final line = utf8.decode(buffer.sublist(0, idx));
      buffer.removeRange(0, idx + 1);
      if (line.trim().isNotEmpty) lines.add(line);
    }
  });

  final welcome =
      await lines.stream.firstWhere((l) => _jsonType(l) == 'welcome').timeout(
    const Duration(seconds: 10),
    onTimeout: () {
      throw TimeoutException('$label: no welcome within 10s');
    },
  );
  final decoded = jsonDecode(welcome) as Map<String, dynamic>;
  final name = decoded['visitor_name'] as String?;
  final visitors = (decoded['visitors'] as List).cast<String>();
  print('$label connected as $name, welcome visitors=${visitors.length}');
  return Conn(connection, send, name ?? '', visitors, lines, sub);
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
