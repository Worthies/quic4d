import 'dart:typed_data';

import 'package:dart_quic/src/varint.dart';
import 'package:test/test.dart';

void main() {
  group('readVarInt — RFC 9000 §16 worked examples', () {
    // These four are the exact worked examples from RFC 9000 §16
    // ("Sample Variable-Length Integer Decoding"), used verbatim as
    // golden vectors rather than invented ones.
    test('8-byte encoding: 0xc2197c5eff14e88c -> 151288809941952652', () {
      final bytes = Uint8List.fromList(
          [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
      final result = readVarInt(bytes, 0);
      expect(result.value, 151288809941952652);
      expect(result.bytesConsumed, 8);
    });

    test('4-byte encoding: 0x9d7f3e7d -> 494878333', () {
      final bytes = Uint8List.fromList([0x9d, 0x7f, 0x3e, 0x7d]);
      final result = readVarInt(bytes, 0);
      expect(result.value, 494878333);
      expect(result.bytesConsumed, 4);
    });

    test('2-byte encoding: 0x7bbd -> 15293', () {
      final bytes = Uint8List.fromList([0x7b, 0xbd]);
      final result = readVarInt(bytes, 0);
      expect(result.value, 15293);
      expect(result.bytesConsumed, 2);
    });

    test('1-byte encoding: 0x25 -> 37', () {
      final bytes = Uint8List.fromList([0x25]);
      final result = readVarInt(bytes, 0);
      expect(result.value, 37);
      expect(result.bytesConsumed, 1);
    });

    test('decodes starting at a non-zero offset', () {
      final bytes = Uint8List.fromList([0xff, 0xff, 0x25]);
      final result = readVarInt(bytes, 2);
      expect(result.value, 37);
      expect(result.bytesConsumed, 1);
    });

    test('throws on empty input', () {
      expect(() => readVarInt(Uint8List(0), 0),
          throwsA(isA<VarIntFormatException>()));
    });

    test('throws on truncated multi-byte varint', () {
      // First byte 0x9d signals a 4-byte encoding but only 2 bytes follow.
      final bytes = Uint8List.fromList([0x9d, 0x7f]);
      expect(() => readVarInt(bytes, 0),
          throwsA(isA<VarIntFormatException>()));
    });
  });

  group('writeVarInt / encodeVarInt — round trip against RFC examples', () {
    test('encodes 37 as the canonical 1-byte form', () {
      expect(encodeVarInt(37), Uint8List.fromList([0x25]));
    });

    test('encodes 15293 as the canonical 2-byte form', () {
      expect(encodeVarInt(15293), Uint8List.fromList([0x7b, 0xbd]));
    });

    test('encodes 494878333 as the canonical 4-byte form', () {
      expect(
          encodeVarInt(494878333), Uint8List.fromList([0x9d, 0x7f, 0x3e, 0x7d]));
    });

    test('encodes 151288809941952652 as the canonical 8-byte form', () {
      expect(
        encodeVarInt(151288809941952652),
        Uint8List.fromList(
            [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
      );
    });

    test('round-trips boundary values at every length transition', () {
      for (final value in [
        0, 1, 0x3F, // 1-byte boundary
        0x40, 0x3FFF, // 2-byte boundary
        0x4000, 0x3FFFFFFF, // 4-byte boundary
        0x40000000, maxVarInt, // 8-byte boundary
      ]) {
        final encoded = encodeVarInt(value);
        final decoded = readVarInt(encoded, 0);
        expect(decoded.value, value, reason: 'round trip failed for $value');
        expect(decoded.bytesConsumed, encoded.length);
      }
    });

    test('throws when encoding a negative value', () {
      expect(() => encodeVarInt(-1), throwsA(isA<VarIntFormatException>()));
    });

    test('throws when encoding a value beyond 2^62-1', () {
      expect(() => encodeVarInt(maxVarInt + 1),
          throwsA(isA<VarIntFormatException>()));
    });

    test('varIntLength matches the length writeVarInt actually produces',
        () {
      for (final value in [0, 63, 64, 16383, 16384, 1073741823, 1073741824,
          maxVarInt]) {
        expect(encodeVarInt(value).length, varIntLength(value));
      }
    });
  });
}
