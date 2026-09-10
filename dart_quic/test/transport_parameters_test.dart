import 'dart:typed_data';

import 'package:dart_quic/src/tls/transport_parameters.dart';
import 'package:dart_quic/src/varint.dart';
import 'package:test/test.dart';

void main() {
  group('TransportParameters round trip', () {
    test('clientDefaults encodes and decodes back to the same values', () {
      final cid = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final params =
          TransportParameters.clientDefaults(initialSourceConnectionId: cid);

      final encoded = params.encode();
      final decoded = TransportParameters.decode(encoded);

      expect(decoded.maxIdleTimeout, 30000);
      expect(decoded.initialMaxData, 10 * 1024 * 1024);
      expect(decoded.initialMaxStreamDataBidiLocal, 10 * 1024 * 1024);
      expect(decoded.initialMaxStreamDataBidiRemote, 10 * 1024 * 1024);
      expect(decoded.initialMaxStreamsBidi, 1);
      expect(decoded.initialMaxStreamsUni, 0);
      expect(decoded.initialSourceConnectionId, cid);
    });

    test('defaults match RFC 9000 §18.2 when a parameter is absent', () {
      // An empty encoded blob (no parameters at all) must decode back to
      // the RFC-specified defaults, not zero/null for everything.
      final decoded = TransportParameters.decode(Uint8List(0));
      expect(decoded.maxUdpPayloadSize, 65527);
      expect(decoded.ackDelayExponent, 3);
      expect(decoded.maxAckDelay, 25);
      expect(decoded.activeConnectionIdLimit, 2);
      expect(decoded.disableActiveMigration, isFalse);
      expect(decoded.initialSourceConnectionId, isNull);
    });

    test('disableActiveMigration round-trips as a zero-length parameter', () {
      final params = const TransportParameters(disableActiveMigration: true);
      final decoded = TransportParameters.decode(params.encode());
      expect(decoded.disableActiveMigration, isTrue);
    });

    test('unknown parameters are preserved rather than dropped', () {
      // A server might send original_destination_connection_id (0x00,
      // server-only) or a reserved "31*N+27" parameter -- both must
      // survive a decode even though dart_quic doesn't model them as
      // named fields.
      final serverBlob = _hex(
        '00' // id 0x00 (original_destination_connection_id)
        '04' // length 4
        'aabbccdd', // arbitrary 4-byte CID value
      );
      final decoded = TransportParameters.decode(serverBlob);
      expect(decoded.unknown[0x00], _hex('aabbccdd'));
    });

    test('decoding a real quic-go-shaped parameter set works end to end', () {
      // A plausible server parameter set: max_idle_timeout=30000,
      // initial_max_data=1048576, initial_source_connection_id=8 bytes,
      // stateless_reset_token=16 bytes (server-only, unknown to this
      // client's named fields but must not break decoding).
      final sink = BytesBuilder();
      void param(int id, List<int> value) {
        sink.addByte(id);
        sink.addByte(value.length);
        sink.add(value);
      }

      param(TransportParameters.idMaxIdleTimeout,
          encodeVarInt(30000)); // 30000 ms
      param(TransportParameters.idInitialMaxData, [0x80, 0x10, 0x00, 0x00]);
      param(TransportParameters.idInitialSourceConnectionId,
          [1, 2, 3, 4, 5, 6, 7, 8]);
      param(TransportParameters.idStatelessResetToken, List.filled(16, 0xAB));

      final decoded = TransportParameters.decode(sink.toBytes());
      expect(decoded.maxIdleTimeout, 30000);
      expect(decoded.initialSourceConnectionId, [1, 2, 3, 4, 5, 6, 7, 8]);
      expect(decoded.unknown[TransportParameters.idStatelessResetToken],
          List.filled(16, 0xAB));
    });
  });
}

Uint8List _hex(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  final bytes = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}
