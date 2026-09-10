import 'dart:typed_data';

import '../varint.dart';

/// RFC 9000 §18: QUIC transport parameters, carried in the TLS
/// quic_transport_parameters extension (0x39, RFC 9001 §8.2). Only the
/// parameters dart_quic's client role actually sends or needs to read
/// are modeled as named fields — everything else (server-only
/// parameters like preferred_address, or ones this client doesn't act
/// on like active_connection_id_limit) is preserved in [unknown] so
/// decoding a real quic-go server's parameter set never drops bytes it
/// doesn't understand, matching RFC 9000 §18.1's requirement that
/// unrecognized parameters be ignored rather than rejected.
class TransportParameters {
  static const int idOriginalDestinationConnectionId = 0x00;
  static const int idMaxIdleTimeout = 0x01;
  static const int idStatelessResetToken = 0x02;
  static const int idMaxUdpPayloadSize = 0x03;
  static const int idInitialMaxData = 0x04;
  static const int idInitialMaxStreamDataBidiLocal = 0x05;
  static const int idInitialMaxStreamDataBidiRemote = 0x06;
  static const int idInitialMaxStreamDataUni = 0x07;
  static const int idInitialMaxStreamsBidi = 0x08;
  static const int idInitialMaxStreamsUni = 0x09;
  static const int idAckDelayExponent = 0x0a;
  static const int idMaxAckDelay = 0x0b;
  static const int idDisableActiveMigration = 0x0c;
  static const int idPreferredAddress = 0x0d;
  static const int idActiveConnectionIdLimit = 0x0e;
  static const int idInitialSourceConnectionId = 0x0f;
  static const int idRetrySourceConnectionId = 0x10;

  /// Milliseconds; 0 (the default) means disabled. dart_quic sets this
  /// to match DESIGN.md's keepalive requirement (30s, mirroring
  /// agents/quic_conn.go and server/quic_visitor.go's shared
  /// quicKeepaliveConfig).
  final int maxIdleTimeout;

  final int maxUdpPayloadSize;
  final int initialMaxData;
  final int initialMaxStreamDataBidiLocal;
  final int initialMaxStreamDataBidiRemote;
  final int initialMaxStreamDataUni;
  final int initialMaxStreamsBidi;
  final int initialMaxStreamsUni;
  final int ackDelayExponent;
  final int maxAckDelay;
  final bool disableActiveMigration;
  final int activeConnectionIdLimit;

  /// The Source Connection ID this endpoint put in its first Initial
  /// packet — required by RFC 9000 §7.3 for both client and server to
  /// send, and the peer's copy must be validated against the CID the
  /// endpoint actually observed on the wire (a mismatch is a
  /// connection-migration/injection defense, not just informational).
  final Uint8List? initialSourceConnectionId;

  /// Server-only parameters and anything with an unrecognized ID,
  /// preserved verbatim (ID -> raw value bytes) rather than dropped.
  final Map<int, Uint8List> unknown;

  const TransportParameters({
    this.maxIdleTimeout = 0,
    this.maxUdpPayloadSize = 65527,
    this.initialMaxData = 0,
    this.initialMaxStreamDataBidiLocal = 0,
    this.initialMaxStreamDataBidiRemote = 0,
    this.initialMaxStreamDataUni = 0,
    this.initialMaxStreamsBidi = 0,
    this.initialMaxStreamsUni = 0,
    this.ackDelayExponent = 3,
    this.maxAckDelay = 25,
    this.disableActiveMigration = false,
    this.activeConnectionIdLimit = 2,
    this.initialSourceConnectionId,
    this.unknown = const {},
  });

  /// dart_quic's own client transport parameters (DESIGN.md's scope:
  /// single bidi stream, generous-enough default limits since this
  /// client doesn't implement flow-control-aware sending, and the
  /// keepalive timing that matches the leaf server/agent's
  /// quicKeepaliveConfig).
  factory TransportParameters.clientDefaults({
    required Uint8List initialSourceConnectionId,
  }) {
    return TransportParameters(
      maxIdleTimeout: 30000, // 30s, matches quicKeepaliveConfig peers.
      initialMaxData: 10 * 1024 * 1024, // 10 MiB - a generous fixed budget
      initialMaxStreamDataBidiLocal: 10 * 1024 * 1024,
      initialMaxStreamDataBidiRemote: 10 * 1024 * 1024,
      initialMaxStreamsBidi: 1, // DESIGN.md: exactly one bidi stream ever
      initialMaxStreamsUni: 0,
      initialSourceConnectionId: initialSourceConnectionId,
    );
  }

  Uint8List encode() {
    final sink = BytesBuilder();
    void writeVarIntParam(int id, int value) {
      writeVarInt(sink, id);
      final encoded = encodeVarInt(value);
      writeVarInt(sink, encoded.length);
      sink.add(encoded);
    }

    if (maxIdleTimeout != 0) {
      writeVarIntParam(idMaxIdleTimeout, maxIdleTimeout);
    }
    writeVarIntParam(idMaxUdpPayloadSize, maxUdpPayloadSize);
    writeVarIntParam(idInitialMaxData, initialMaxData);
    writeVarIntParam(
        idInitialMaxStreamDataBidiLocal, initialMaxStreamDataBidiLocal);
    writeVarIntParam(
        idInitialMaxStreamDataBidiRemote, initialMaxStreamDataBidiRemote);
    writeVarIntParam(idInitialMaxStreamDataUni, initialMaxStreamDataUni);
    writeVarIntParam(idInitialMaxStreamsBidi, initialMaxStreamsBidi);
    writeVarIntParam(idInitialMaxStreamsUni, initialMaxStreamsUni);
    writeVarIntParam(idAckDelayExponent, ackDelayExponent);
    writeVarIntParam(idMaxAckDelay, maxAckDelay);
    if (disableActiveMigration) {
      writeVarInt(sink, idDisableActiveMigration);
      writeVarInt(sink, 0);
    }
    writeVarIntParam(idActiveConnectionIdLimit, activeConnectionIdLimit);

    final cid = initialSourceConnectionId;
    if (cid != null) {
      writeVarInt(sink, idInitialSourceConnectionId);
      writeVarInt(sink, cid.length);
      sink.add(cid);
    }

    for (final entry in unknown.entries) {
      writeVarInt(sink, entry.key);
      writeVarInt(sink, entry.value.length);
      sink.add(entry.value);
    }

    return sink.toBytes();
  }

  static TransportParameters decode(Uint8List bytes) {
    var pos = 0;
    var maxIdleTimeout = 0;
    var maxUdpPayloadSize = 65527;
    var initialMaxData = 0;
    var initialMaxStreamDataBidiLocal = 0;
    var initialMaxStreamDataBidiRemote = 0;
    var initialMaxStreamDataUni = 0;
    var initialMaxStreamsBidi = 0;
    var initialMaxStreamsUni = 0;
    var ackDelayExponent = 3;
    var maxAckDelay = 25;
    var disableActiveMigration = false;
    var activeConnectionIdLimit = 2;
    Uint8List? initialSourceConnectionId;
    final unknown = <int, Uint8List>{};

    while (pos < bytes.length) {
      final id = readVarInt(bytes, pos);
      pos += id.bytesConsumed;
      final length = readVarInt(bytes, pos);
      pos += length.bytesConsumed;

      if (pos + length.value > bytes.length) {
        throw ArgumentError(
            'transport parameter 0x${id.value.toRadixString(16)} value '
            'length exceeds available bytes');
      }
      final value = Uint8List.sublistView(bytes, pos, pos + length.value);
      pos += length.value;

      switch (id.value) {
        case idMaxIdleTimeout:
          maxIdleTimeout = readVarInt(value, 0).value;
        case idMaxUdpPayloadSize:
          maxUdpPayloadSize = readVarInt(value, 0).value;
        case idInitialMaxData:
          initialMaxData = readVarInt(value, 0).value;
        case idInitialMaxStreamDataBidiLocal:
          initialMaxStreamDataBidiLocal = readVarInt(value, 0).value;
        case idInitialMaxStreamDataBidiRemote:
          initialMaxStreamDataBidiRemote = readVarInt(value, 0).value;
        case idInitialMaxStreamDataUni:
          initialMaxStreamDataUni = readVarInt(value, 0).value;
        case idInitialMaxStreamsBidi:
          initialMaxStreamsBidi = readVarInt(value, 0).value;
        case idInitialMaxStreamsUni:
          initialMaxStreamsUni = readVarInt(value, 0).value;
        case idAckDelayExponent:
          ackDelayExponent = readVarInt(value, 0).value;
        case idMaxAckDelay:
          maxAckDelay = readVarInt(value, 0).value;
        case idDisableActiveMigration:
          disableActiveMigration = true;
        case idActiveConnectionIdLimit:
          activeConnectionIdLimit = readVarInt(value, 0).value;
        case idInitialSourceConnectionId:
          initialSourceConnectionId = value;
        default:
          unknown[id.value] = value;
      }
    }

    return TransportParameters(
      maxIdleTimeout: maxIdleTimeout,
      maxUdpPayloadSize: maxUdpPayloadSize,
      initialMaxData: initialMaxData,
      initialMaxStreamDataBidiLocal: initialMaxStreamDataBidiLocal,
      initialMaxStreamDataBidiRemote: initialMaxStreamDataBidiRemote,
      initialMaxStreamDataUni: initialMaxStreamDataUni,
      initialMaxStreamsBidi: initialMaxStreamsBidi,
      initialMaxStreamsUni: initialMaxStreamsUni,
      ackDelayExponent: ackDelayExponent,
      maxAckDelay: maxAckDelay,
      disableActiveMigration: disableActiveMigration,
      activeConnectionIdLimit: activeConnectionIdLimit,
      initialSourceConnectionId: initialSourceConnectionId,
      unknown: unknown,
    );
  }
}
