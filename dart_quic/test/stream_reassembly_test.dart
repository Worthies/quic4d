import 'dart:typed_data';

import 'package:dart_quic/src/connection.dart' show StreamReassembler;
import 'package:test/test.dart';

void main() {
  // RFC 9000 §19.8 permits overlapping frames, and RFC 9002 §7.2.2 lets
  // a peer retransmit stream data re-chunked under DIFFERENT frame
  // boundaries -- these tests pin the reassembler's handling of the
  // resulting straddling/overlapping shapes, each of which previously
  // either stalled the stream forever or silently dropped bytes.
  test('in-order frames deliver directly', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    r.add(0, Uint8List.fromList([1, 2, 3]));
    r.add(3, Uint8List.fromList([4, 5]));
    expect(out, [1, 2, 3, 4, 5]);
    expect(r.receiveOffset, 5);
  });

  test('straddling retransmission contributes its new tail bytes', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    r.add(0, Uint8List.fromList([1, 2, 3, 4, 5]));
    // Re-chunked retransmission covering 2..8: prefix 2..5 already
    // delivered, tail 6,7,8 is NEW and must not be dropped (the old
    // code treated any offset < frontier as a full duplicate).
    r.add(2, Uint8List.fromList([3, 4, 5, 6, 7, 8]));
    expect(out, [1, 2, 3, 4, 5, 6, 7, 8]);
    expect(r.receiveOffset, 8);
  });

  test('fully-duplicate retransmissions are ignored', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    r.add(0, Uint8List.fromList([1, 2, 3]));
    r.add(0, Uint8List.fromList([1, 2, 3]));
    r.add(1, Uint8List.fromList([2, 3]));
    expect(out, [1, 2, 3]);
  });

  test('reordered frames buffer and drain in order', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    r.add(3, Uint8List.fromList([4, 5, 6]));
    r.add(0, Uint8List.fromList([1, 2, 3]));
    expect(out, [1, 2, 3, 4, 5, 6]);
  });

  test('shorter re-chunk never shrinks buffered out-of-order coverage', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    // Buffer 4..9 out of order, then a shorter frame covering only
    // 4..6 arrives -- the buffered 7..9 must survive.
    r.add(4, Uint8List.fromList([5, 6, 7, 8, 9]));
    r.add(4, Uint8List.fromList([5, 6]));
    r.add(0, Uint8List.fromList([1, 2, 3, 4]));
    expect(out, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  test(
      'straddling buffered entry drains its tail when the frontier '
      'reaches into it', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    // Buffer 4..9, then deliver 0..6: the buffered entry straddles the
    // new frontier (6) -- its tail 7..9 must be delivered, not stuck.
    r.add(4, Uint8List.fromList([5, 6, 7, 8, 9]));
    r.add(0, Uint8List.fromList([1, 2, 3, 4, 5, 6]));
    expect(out, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  test('overlapping out-of-order frames keep the furthest reach', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    r.add(3, Uint8List.fromList([4, 5, 6, 7]));
    // Same start, reaches further (to 9).
    r.add(3, Uint8List.fromList([4, 5, 6, 7, 8, 9]));
    r.add(0, Uint8List.fromList([1, 2, 3]));
    expect(out, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  test('stale entries fully covered by the frontier are evicted', () {
    final out = <int>[];
    final r = StreamReassembler(out.addAll);
    // Buffer a long entry at 4..9 and a shorter one at 6..6 (a
    // re-chunked retransmission overlapping the longer one).
    r.add(4, Uint8List.fromList([5, 6, 7, 8, 9]));
    r.add(6, Uint8List.fromList([7]));
    expect(r.pendingEntryCount, 2);
    // Delivering 0..8 drains the straddling long entry (tail 9) and
    // leaves the short 6..6 entry fully covered -- it must be evicted,
    // not linger for the connection's lifetime.
    r.add(0, Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]));
    expect(out, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(r.receiveOffset, 9);
    expect(r.pendingEntryCount, 0);
  });
}
