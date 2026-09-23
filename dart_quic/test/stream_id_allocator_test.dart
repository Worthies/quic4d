import 'package:dart_quic/src/stream_id_allocator.dart';
import 'package:test/test.dart';

void main() {
  group('ClientBidiStreamIdAllocator', () {
    test('the first allocated ID is 0 (the control stream\'s own ID)', () {
      final allocator = ClientBidiStreamIdAllocator();
      expect(allocator.allocate(), equals(0));
    });

    test(
        'successive allocations follow RFC 9000 §2.1\'s client-'
        'initiated-bidirectional sequence (0, 4, 8, 12, ...)', () {
      final allocator = ClientBidiStreamIdAllocator();
      expect(allocator.allocate(), equals(0));
      expect(allocator.allocate(), equals(4));
      expect(allocator.allocate(), equals(8));
      expect(allocator.allocate(), equals(12));
    });

    test('peekNext reports the next ID without consuming it', () {
      final allocator = ClientBidiStreamIdAllocator();
      expect(allocator.peekNext, equals(0));
      allocator.allocate();
      expect(allocator.peekNext, equals(4));
      expect(allocator.peekNext, equals(4)); // still 4, not consumed
      allocator.allocate();
      expect(allocator.peekNext, equals(8));
    });

    test(
        'every allocated ID has the low 2 bits 0b00 (client-'
        'initiated, bidirectional, per RFC 9000 §2.1\'s encoding)', () {
      final allocator = ClientBidiStreamIdAllocator();
      for (var i = 0; i < 10; i++) {
        expect(allocator.allocate() & 0x3, equals(0));
      }
    });
  });
}
