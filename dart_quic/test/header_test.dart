import 'dart:typed_data';

import 'package:dart_quic/src/packet/header.dart';
import 'package:test/test.dart';

void main() {
  group('packetNumberEncodingLength — RFC 9000 Appendix A.2 examples', () {
    test('0xac5c02 after acking 0xabe8b3 needs 16 bits (2 bytes)', () {
      final length = packetNumberEncodingLength(0xac5c02, 0xabe8b3);
      expect(length, 2);
    });

    test('0xace8fe after acking 0xabe8b3 needs 24 bits (3 bytes)', () {
      final length = packetNumberEncodingLength(0xace8fe, 0xabe8b3);
      expect(length, 3);
    });

    test('with no prior ack, packet 2 fits in 1 byte', () {
      expect(packetNumberEncodingLength(2, null), 1);
    });
  });

  group('decodeFullPacketNumber — RFC 9000 Appendix A.3 example', () {
    test(
        '0x9b32 (16 bits) after largest 0xa82f30ea decodes to '
        '0xa82f9b32', () {
      final decoded = decodeFullPacketNumber(
        largestPn: 0xa82f30ea,
        truncatedPn: 0x9b32,
        pnBits: 16,
      );
      expect(decoded, 0xa82f9b32);
    });
  });

  group('encodeTruncatedPacketNumber / decode round trip', () {
    test(
        'round-trips a packet number through the length its own '
        'encoding needs', () {
      // 12345 needs 14 bits -> packetNumberEncodingLength would pick 2
      // bytes; use exactly that length here so truncation doesn't lose
      // information (a 1-byte truncation of 12345 is lossy by design --
      // that's what packetNumberEncodingLength exists to avoid).
      const fullPn = 12345;
      for (final length in [2, 3, 4]) {
        final encoded = encodeTruncatedPacketNumber(fullPn, length);
        expect(encoded.length, length);

        var truncated = 0;
        for (final b in encoded) {
          truncated = (truncated << 8) | b;
        }
        final decoded = decodeFullPacketNumber(
          largestPn: -1, // nothing acked yet, matches encode's fullPn+1
          truncatedPn: truncated,
          pnBits: length * 8,
        );
        expect(decoded, fullPn);
      }
    });

    test(
        'a too-short truncation is lossy (documents the tradeoff, not '
        'a bug)', () {
      const fullPn = 12345; // 0x3039
      final encoded = encodeTruncatedPacketNumber(fullPn, 1);
      expect(encoded, Uint8List.fromList([0x39])); // low byte only
    });
  });

  group('LongHeader — RFC 9001 Appendix A.2 client Initial header', () {
    // From the RFC: the unprotected header for packet number 2, DCID
    // 0x8394c8f03e515708 (8 bytes), empty SCID, empty token, Length
    // 0x449e (4-byte PN + 1162-byte payload + 16-byte tag = 1182 =
    // 0x49e).
    final expectedHeaderBytes =
        _hex('c300000001088394c8f03e5157080000449e00000002');

    test('encode reproduces the exact RFC header bytes', () {
      final header = LongHeader(
        type: LongPacketType.initial,
        reservedBits: 0,
        packetNumberLength: 4,
        version: quicVersion1,
        destinationConnectionId: _hex('8394c8f03e515708'),
        sourceConnectionId: Uint8List(0),
        packetNumber: 2,
      );
      // payload length = 1162 (plaintext) + 16 (AEAD tag) = 1178.
      final result = header.encode(payloadLength: 1178);
      expect(result.bytes, expectedHeaderBytes);
      expect(result.packetNumberOffset, expectedHeaderBytes.length - 4);
    });

    test('decodeUpToPacketNumber parses the same header back', () {
      final decoded = LongHeader.decodeUpToPacketNumber(expectedHeaderBytes, 0);
      expect(decoded.header.type, LongPacketType.initial);
      expect(decoded.header.version, quicVersion1);
      expect(decoded.header.destinationConnectionId, _hex('8394c8f03e515708'));
      expect(decoded.header.sourceConnectionId, isEmpty);
      expect(decoded.header.token, isEmpty);
      // The wire bytes are 0x449e, but that's a QUIC varint (top 2 bits
      // 01 => 2-byte encoding, value = 0x449e & 0x3FFF) -- exactly
      // 1182, matching the RFC's own prose: "a length of 1182 bytes:
      // the 4-byte packet number, 1162 bytes of frames, and the
      // 16-byte authentication tag."
      expect(decoded.length, 1182);
      expect(decoded.packetNumberOffset, expectedHeaderBytes.length - 4);
      // Reserved bits and PN length are still "masked" pre-protection-
      // removal in this decode step -- the RFC's example already has
      // its true values (0 reserved, 4-byte PN) since this test feeds
      // in the *unprotected* header directly.
      expect(decoded.header.packetNumberLength, 4);
      expect(decoded.header.reservedBits, 0);
    });

    test('rejects a header with the fixed bit unset', () {
      final corrupted = Uint8List.fromList(expectedHeaderBytes);
      corrupted[0] &= ~0x40;
      expect(() => LongHeader.decodeUpToPacketNumber(corrupted, 0),
          throwsA(isA<PacketHeaderException>()));
    });

    test('rejects a short-header byte as a long header', () {
      final shortHeaderByte = Uint8List.fromList([0x40, 0, 0, 0, 0]);
      expect(() => LongHeader.decodeUpToPacketNumber(shortHeaderByte, 0),
          throwsA(isA<PacketHeaderException>()));
    });
  });

  group('ShortHeader round trip', () {
    test('encode/decode preserves DCID, spin bit, key phase, PN length', () {
      final dcid = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final header = ShortHeader(
        spinBit: true,
        reservedBits: 0,
        keyPhase: 1,
        packetNumberLength: 2,
        destinationConnectionId: dcid,
        packetNumber: 999,
      );
      final result = header.encode();

      final decoded = ShortHeader.decodeUpToPacketNumber(
        result.bytes,
        0,
        destinationConnectionIdLength: dcid.length,
      );
      expect(decoded.header.spinBit, isTrue);
      expect(decoded.header.keyPhase, 1);
      expect(decoded.header.packetNumberLength, 2);
      expect(decoded.header.destinationConnectionId, dcid);
      expect(decoded.packetNumberOffset, result.packetNumberOffset);
    });

    test('rejects a long-header byte as a short header', () {
      final longHeaderByte = Uint8List.fromList([0xC0, 0, 0, 0, 0]);
      expect(
        () => ShortHeader.decodeUpToPacketNumber(longHeaderByte, 0,
            destinationConnectionIdLength: 0),
        throwsA(isA<PacketHeaderException>()),
      );
    });

    test('rejects a header with the fixed bit unset', () {
      final corrupted = Uint8List.fromList([0x00, 0, 0, 0, 0]);
      expect(
        () => ShortHeader.decodeUpToPacketNumber(corrupted, 0,
            destinationConnectionIdLength: 0),
        throwsA(isA<PacketHeaderException>()),
      );
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
