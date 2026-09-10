/// RFC 9000 §17: long and short header packet formats, and the packet
/// number encode/decode algorithms from Appendix A.2/A.3. This module
/// only handles the *unprotected* header shape (fields, byte layout,
/// varint length prefix) -- applying/removing header protection is
/// header_protection.dart's job, run on top of what this module
/// produces/consumes.
library;

import 'dart:typed_data';

import '../varint.dart';

final Uint8List _emptyBytes = Uint8List(0);

/// QUIC v1's fixed version number (RFC 9000 §15).
const int quicVersion1 = 0x00000001;

class PacketHeaderException implements Exception {
  final String message;
  const PacketHeaderException(this.message);

  @override
  String toString() => 'PacketHeaderException: $message';
}

enum LongPacketType { initial, zeroRtt, handshake, retry }

int _longPacketTypeBits(LongPacketType type) {
  switch (type) {
    case LongPacketType.initial:
      return 0x00;
    case LongPacketType.zeroRtt:
      return 0x01;
    case LongPacketType.handshake:
      return 0x02;
    case LongPacketType.retry:
      return 0x03;
  }
}

/// RFC 9000 Appendix A.2: chooses the smallest packet number encoding
/// (in bytes, 1-4) that lets the peer unambiguously recover [fullPn]
/// given the largest packet number it has acknowledged so far
/// ([largestAcked], null if none yet).
int packetNumberEncodingLength(int fullPn, int? largestAcked) {
  final numUnacked = largestAcked == null ? fullPn + 1 : fullPn - largestAcked;
  if (numUnacked <= 0) {
    // fullPn <= largestAcked shouldn't happen for a packet we're about
    // to send, but guard against a degenerate 0/negative range rather
    // than calling log2 of a non-positive number.
    return 1;
  }
  final minBits = (_log2(numUnacked)) + 1;
  final numBytes = (minBits / 8).ceil();
  return numBytes.clamp(1, 4);
}

int _log2(int value) {
  var bits = 0;
  var v = value;
  while (v > 1) {
    v >>= 1;
    bits++;
  }
  return bits;
}

/// Encodes [fullPn]'s truncated representation using exactly [length]
/// bytes (the least-significant bytes of the full packet number).
Uint8List encodeTruncatedPacketNumber(int fullPn, int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[length - 1 - i] = (fullPn >> (8 * i)) & 0xFF;
  }
  return bytes;
}

/// RFC 9000 Appendix A.3: reconstructs the full packet number from a
/// truncated on-wire value, given the largest packet number
/// successfully processed so far in this packet number space.
int decodeFullPacketNumber({
  required int largestPn,
  required int truncatedPn,
  required int pnBits,
}) {
  final expectedPn = largestPn + 1;
  final pnWin = 1 << pnBits;
  final pnHwin = pnWin ~/ 2;
  final pnMask = pnWin - 1;

  final candidatePn = (expectedPn & ~pnMask) | truncatedPn;
  if (candidatePn <= expectedPn - pnHwin && candidatePn < (1 << 62) - pnWin) {
    return candidatePn + pnWin;
  }
  if (candidatePn > expectedPn + pnHwin && candidatePn >= pnWin) {
    return candidatePn - pnWin;
  }
  return candidatePn;
}

/// An unprotected long-header packet's fields (RFC 9000 §17.2), for the
/// three long-header types dart_quic's client sends/receives: Initial,
/// Handshake, and (decode-only, to reject cleanly) Retry. 0-RTT is
/// decode-unreachable in dart_quic's scope (no 0-RTT, per DESIGN.md)
/// but the type tag exists so a stray 0-RTT packet from a
/// confused/malicious peer is recognized and dropped rather than
/// misparsed as something else.
class LongHeader {
  final LongPacketType type;
  final int reservedBits; // must be 0 once unprotected, RFC 9000 §17.2
  final int packetNumberLength; // 1-4, only meaningful for non-Retry
  final int version;
  final Uint8List destinationConnectionId;
  final Uint8List sourceConnectionId;
  final Uint8List token; // only meaningful for Initial
  final int packetNumber; // truncated on-wire value; only for non-Retry

  LongHeader({
    required this.type,
    required this.reservedBits,
    required this.packetNumberLength,
    required this.version,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    Uint8List? token,
    this.packetNumber = 0,
  }) : token = token ?? _emptyBytes;

  /// Encodes the header fields (unprotected -- caller applies header
  /// protection afterward) up to and including the packet number, plus
  /// writes the correct Length field for [payloadLength] (the
  /// to-be-appended protected payload's byte length, i.e. plaintext
  /// length + AEAD tag length).
  ///
  /// Returns the encoded bytes and the byte offset within them where
  /// the packet number field begins (needed by header_protection.dart).
  ({Uint8List bytes, int packetNumberOffset}) encode({
    required int payloadLength,
  }) {
    if (type == LongPacketType.retry) {
      throw const PacketHeaderException(
          'Retry packets have no packet number field; use a dedicated '
          'encoder if Retry support is ever added');
    }
    final sink = BytesBuilder();
    final pnLen = packetNumberLength;
    final firstByte = 0xC0 | // header form(1) + fixed bit(1)
        (_longPacketTypeBits(type) << 4) |
        (reservedBits << 2) |
        (pnLen - 1);
    sink.addByte(firstByte);

    final versionBytes = ByteData(4)..setUint32(0, version);
    sink.add(versionBytes.buffer.asUint8List());

    sink.addByte(destinationConnectionId.length);
    sink.add(destinationConnectionId);
    sink.addByte(sourceConnectionId.length);
    sink.add(sourceConnectionId);

    if (type == LongPacketType.initial) {
      writeVarInt(sink, token.length);
      sink.add(token);
    }

    // Length = packet number length + payload length (RFC 9000 §17.2).
    writeVarInt(sink, pnLen + payloadLength);

    final packetNumberOffset = sink.length;
    sink.add(encodeTruncatedPacketNumber(packetNumber, pnLen));

    return (bytes: sink.toBytes(), packetNumberOffset: packetNumberOffset);
  }

  /// Parses a long header's fields (before header protection removal --
  /// only the version-independent and protection-agnostic fields, i.e.
  /// everything except the true packet number length/value and
  /// reserved bits, which remain masked until header protection is
  /// removed). Returns the header (with [packetNumberLength]/
  /// [packetNumber]/[reservedBits] left at 0 -- caller fills those in
  /// after unmasking) plus the byte offset where the (still-masked)
  /// packet number field begins and the declared Length field's value
  /// (needed to know where the packet ends).
  static ({
    LongHeader header,
    int packetNumberOffset,
    int length,
  }) decodeUpToPacketNumber(Uint8List bytes, int offset) {
    var pos = offset;
    if (pos >= bytes.length) {
      throw const PacketHeaderException('no bytes for long header');
    }
    final firstByte = bytes[pos];
    if ((firstByte & 0x80) == 0) {
      throw const PacketHeaderException('not a long header packet');
    }
    if ((firstByte & 0x40) == 0) {
      throw const PacketHeaderException(
          'fixed bit is 0 -- not a valid QUIC v1 packet');
    }
    final typeBits = (firstByte >> 4) & 0x03;
    final type = LongPacketType.values.firstWhere(
        (t) => _longPacketTypeBits(t) == typeBits,
        orElse: () =>
            throw const PacketHeaderException('unrecognized long packet type'));
    pos += 1;

    if (pos + 4 > bytes.length) {
      throw const PacketHeaderException('truncated before version');
    }
    final version = ByteData.sublistView(bytes, pos, pos + 4).getUint32(0);
    pos += 4;

    if (pos >= bytes.length) {
      throw const PacketHeaderException('truncated before DCID length');
    }
    final dcidLen = bytes[pos];
    pos += 1;
    if (pos + dcidLen > bytes.length) {
      throw const PacketHeaderException('truncated DCID');
    }
    final dcid = Uint8List.sublistView(bytes, pos, pos + dcidLen);
    pos += dcidLen;

    if (pos >= bytes.length) {
      throw const PacketHeaderException('truncated before SCID length');
    }
    final scidLen = bytes[pos];
    pos += 1;
    if (pos + scidLen > bytes.length) {
      throw const PacketHeaderException('truncated SCID');
    }
    final scid = Uint8List.sublistView(bytes, pos, pos + scidLen);
    pos += scidLen;

    if (type == LongPacketType.retry) {
      // No token/length/packet-number fields at all -- the remainder
      // is the Retry-specific payload + integrity tag, which dart_quic
      // doesn't parse further (Retry isn't supported; see DESIGN.md).
      return (
        header: LongHeader(
          type: type,
          reservedBits: 0,
          packetNumberLength: 0,
          version: version,
          destinationConnectionId: dcid,
          sourceConnectionId: scid,
        ),
        packetNumberOffset: pos,
        length: bytes.length - pos,
      );
    }

    var token = const <int>[];
    if (type == LongPacketType.initial) {
      final tokenLen = readVarInt(bytes, pos);
      pos += tokenLen.bytesConsumed;
      if (pos + tokenLen.value > bytes.length) {
        throw const PacketHeaderException('truncated token');
      }
      token = Uint8List.sublistView(bytes, pos, pos + tokenLen.value);
      pos += tokenLen.value;
    }

    final length = readVarInt(bytes, pos);
    pos += length.bytesConsumed;

    return (
      header: LongHeader(
        type: type,
        reservedBits: (firstByte >> 2) & 0x03, // still masked
        packetNumberLength: (firstByte & 0x03) + 1, // still masked
        version: version,
        destinationConnectionId: dcid,
        sourceConnectionId: scid,
        token: Uint8List.fromList(token),
      ),
      packetNumberOffset: pos,
      length: length.value,
    );
  }
}

/// An unprotected short-header (1-RTT) packet's fields (RFC 9000
/// §17.3.1). Unlike a long header, there's no explicit Length field --
/// the payload extends to the end of the UDP datagram (RFC 9000 §12.2
/// notes short-header packets are typically the last in a datagram).
class ShortHeader {
  final bool spinBit;
  final int reservedBits;
  final int keyPhase;
  final int packetNumberLength;
  final Uint8List destinationConnectionId;
  final int packetNumber;

  const ShortHeader({
    this.spinBit = false,
    required this.reservedBits,
    required this.keyPhase,
    required this.packetNumberLength,
    required this.destinationConnectionId,
    this.packetNumber = 0,
  });

  ({Uint8List bytes, int packetNumberOffset}) encode() {
    final sink = BytesBuilder();
    final pnLen = packetNumberLength;
    final firstByte = 0x40 | // fixed bit
        (spinBit ? 0x20 : 0) |
        (reservedBits << 3) |
        (keyPhase != 0 ? 0x04 : 0) |
        (pnLen - 1);
    sink.addByte(firstByte);
    sink.add(destinationConnectionId);

    final packetNumberOffset = sink.length;
    sink.add(encodeTruncatedPacketNumber(packetNumber, pnLen));

    return (bytes: sink.toBytes(), packetNumberOffset: packetNumberOffset);
  }

  /// Parses a short header's fields up to (not including unmasking) the
  /// packet number -- [destinationConnectionIdLength] must be supplied
  /// by the caller since a short header carries no explicit CID length
  /// field (RFC 9000 §17.3.1: both endpoints already agreed on a fixed
  /// CID length out of band, from the long-header handshake packets).
  static ({ShortHeader header, int packetNumberOffset}) decodeUpToPacketNumber(
    Uint8List bytes,
    int offset, {
    required int destinationConnectionIdLength,
  }) {
    var pos = offset;
    if (pos >= bytes.length) {
      throw const PacketHeaderException('no bytes for short header');
    }
    final firstByte = bytes[pos];
    if ((firstByte & 0x80) != 0) {
      throw const PacketHeaderException('not a short header packet');
    }
    if ((firstByte & 0x40) == 0) {
      throw const PacketHeaderException(
          'fixed bit is 0 -- not a valid QUIC v1 packet');
    }
    pos += 1;

    if (pos + destinationConnectionIdLength > bytes.length) {
      throw const PacketHeaderException('truncated DCID');
    }
    final dcid =
        Uint8List.sublistView(bytes, pos, pos + destinationConnectionIdLength);
    pos += destinationConnectionIdLength;

    return (
      header: ShortHeader(
        spinBit: (firstByte & 0x20) != 0,
        reservedBits: (firstByte >> 3) & 0x03, // still masked
        keyPhase: (firstByte & 0x04) != 0 ? 1 : 0, // still masked
        packetNumberLength: (firstByte & 0x03) + 1, // still masked
        destinationConnectionId: dcid,
      ),
      packetNumberOffset: pos,
    );
  }
}
