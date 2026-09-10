import 'dart:typed_data';

import 'package:dart_quic/src/frame/frame_codec.dart';
import 'package:test/test.dart';

void main() {
  group('PaddingFrame / PingFrame / HandshakeDoneFrame', () {
    test('PADDING encodes as a single 0x00 byte and round-trips', () {
      final sink = BytesBuilder();
      const PaddingFrame().encode(sink);
      final bytes = sink.toBytes();
      expect(bytes, Uint8List.fromList([0x00]));

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, const PaddingFrame());
      expect(decoded.bytesConsumed, 1);
    });

    test('PING encodes as a single 0x01 byte and round-trips', () {
      final sink = BytesBuilder();
      const PingFrame().encode(sink);
      final bytes = sink.toBytes();
      expect(bytes, Uint8List.fromList([0x01]));

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, const PingFrame());
      expect(decoded.bytesConsumed, 1);
    });

    test('HANDSHAKE_DONE encodes as a single 0x1e byte and round-trips', () {
      final sink = BytesBuilder();
      const HandshakeDoneFrame().encode(sink);
      final bytes = sink.toBytes();
      expect(bytes, Uint8List.fromList([0x1e]));

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, const HandshakeDoneFrame());
    });
  });

  group('CryptoFrame', () {
    test('round-trips offset + data', () {
      final frame =
          CryptoFrame(offset: 128, data: Uint8List.fromList([1, 2, 3, 4]));
      final sink = BytesBuilder();
      frame.encode(sink);
      final bytes = sink.toBytes();

      expect(bytes[0], CryptoFrame.wireType);

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, frame);
      expect(decoded.bytesConsumed, bytes.length);
    });

    test('round-trips a zero offset and empty data', () {
      final frame = CryptoFrame(offset: 0, data: Uint8List(0));
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded = decodeFrame(sink.toBytes(), 0);
      expect(decoded.frame, frame);
    });

    test('throws on truncated crypto data', () {
      // Type 0x06, offset varint 0x00, length varint says 10 bytes follow,
      // but only 2 are actually present.
      final bytes = Uint8List.fromList([0x06, 0x00, 0x0a, 0x01, 0x02]);
      expect(() => decodeFrame(bytes, 0), throwsA(isA<FrameFormatException>()));
    });
  });

  group('StreamFrame', () {
    test('round-trips with a non-zero offset and fin set', () {
      final frame = StreamFrame(
        streamId: 4,
        offset: 100,
        data: Uint8List.fromList('hello'.codeUnits),
        fin: true,
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final bytes = sink.toBytes();

      // OFF|LEN|FIN bits all set: 0x08 | 0x04 | 0x02 | 0x01 = 0x0f
      expect(bytes[0], 0x0f);

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, frame);
    });

    test('round-trips with offset 0 (OFF bit unset) and fin unset', () {
      final frame = StreamFrame(
        streamId: 0,
        offset: 0,
        data: Uint8List.fromList([9, 9, 9]),
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final bytes = sink.toBytes();

      // LEN bit only: 0x08 | 0x02 = 0x0a
      expect(bytes[0], 0x0a);

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, frame);
    });

    test('decodes with no LEN bit: data extends to end of buffer', () {
      // Type 0x08 (no OFF, no LEN, no FIN), stream ID varint 0x01,
      // followed by 3 bytes of stream data with nothing else in the
      // buffer.
      final bytes = Uint8List.fromList([0x08, 0x01, 0xaa, 0xbb, 0xcc]);
      final decoded = decodeFrame(bytes, 0);
      final frame = decoded.frame as StreamFrame;
      expect(frame.streamId, 1);
      expect(frame.offset, 0);
      expect(frame.data, Uint8List.fromList([0xaa, 0xbb, 0xcc]));
      expect(decoded.bytesConsumed, 5);
    });
  });

  group('AckFrame', () {
    test('round-trips with no additional ranges and no ECN', () {
      final frame = const AckFrame(
        largestAcknowledged: 10,
        ackDelay: 5,
        firstAckRange: 3,
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final bytes = sink.toBytes();
      expect(bytes[0], AckFrame.wireTypeNoEcn);

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, frame);
    });

    test('round-trips with additional ranges and ECN counts', () {
      final frame = const AckFrame(
        largestAcknowledged: 100,
        ackDelay: 42,
        firstAckRange: 5,
        ackRanges: [
          AckRange(gap: 1, ackRangeLength: 2),
          AckRange(gap: 0, ackRangeLength: 4),
        ],
        ecnCounts: EcnCounts(ect0: 1, ect1: 2, ecnCe: 3),
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final bytes = sink.toBytes();
      expect(bytes[0], AckFrame.wireTypeWithEcn);

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, frame);
    });

    test('acknowledgedPacketNumbers expands ranges correctly', () {
      // Largest=10, firstAckRange=2 covers [8,9,10].
      // One more range: gap=1, ackRangeLength=1.
      //   largest' = smallest(8) - gap(1) - 2 = 5
      //   covers [4,5]
      final frame = const AckFrame(
        largestAcknowledged: 10,
        ackDelay: 0,
        firstAckRange: 2,
        ackRanges: [AckRange(gap: 1, ackRangeLength: 1)],
      );
      expect(
        frame.acknowledgedPacketNumbers(),
        [10, 9, 8, 5, 4],
      );
    });

    test('acknowledgedPacketNumbers with only firstAckRange', () {
      final frame = const AckFrame(
        largestAcknowledged: 5,
        ackDelay: 0,
        firstAckRange: 0,
      );
      expect(frame.acknowledgedPacketNumbers(), [5]);
    });
  });

  group('ResetStreamFrame / StopSendingFrame', () {
    test('RESET_STREAM round-trips', () {
      final frame = const ResetStreamFrame(
        streamId: 4,
        applicationErrorCode: 7,
        finalSize: 1024,
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded = decodeFrame(sink.toBytes(), 0);
      expect(decoded.frame, frame);
    });

    test('STOP_SENDING round-trips', () {
      final frame =
          const StopSendingFrame(streamId: 4, applicationErrorCode: 2);
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded = decodeFrame(sink.toBytes(), 0);
      expect(decoded.frame, frame);
    });
  });

  group('ConnectionCloseFrame', () {
    test('transport variant round-trips with a frame type and reason', () {
      final frame = const ConnectionCloseFrame(
        isApplicationError: false,
        errorCode: 10,
        frameType: 0x08,
        reasonPhrase: 'boom',
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final bytes = sink.toBytes();
      expect(bytes[0], ConnectionCloseFrame.wireTypeTransport);

      final decoded = decodeFrame(bytes, 0);
      expect(decoded.frame, frame);
    });

    test('application variant round-trips without a frame type field', () {
      final frame = const ConnectionCloseFrame(
        isApplicationError: true,
        errorCode: 1,
        reasonPhrase: '',
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final bytes = sink.toBytes();
      expect(bytes[0], ConnectionCloseFrame.wireTypeApplication);

      final decoded = decodeFrame(bytes, 0);
      final decodedFrame = decoded.frame as ConnectionCloseFrame;
      expect(decodedFrame.frameType, isNull);
      expect(decodedFrame, frame);
    });
  });

  group('flow control / misc frames round-trip', () {
    test('MaxDataFrame', () {
      final frame = const MaxDataFrame(maximumData: 65536);
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded = decodeFrame(sink.toBytes(), 0).frame as MaxDataFrame;
      expect(decoded.maximumData, frame.maximumData);
    });

    test('MaxStreamDataFrame', () {
      final frame =
          const MaxStreamDataFrame(streamId: 4, maximumStreamData: 2048);
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded =
          decodeFrame(sink.toBytes(), 0).frame as MaxStreamDataFrame;
      expect(decoded.streamId, 4);
      expect(decoded.maximumStreamData, 2048);
    });

    test('MaxStreamsFrame bidi and uni', () {
      for (final bidi in [true, false]) {
        final frame = MaxStreamsFrame(bidirectional: bidi, maximumStreams: 3);
        final sink = BytesBuilder();
        frame.encode(sink);
        final bytes = sink.toBytes();
        expect(bytes[0],
            bidi ? MaxStreamsFrame.wireTypeBidi : MaxStreamsFrame.wireTypeUni);
        final decoded = decodeFrame(bytes, 0).frame as MaxStreamsFrame;
        expect(decoded.bidirectional, bidi);
        expect(decoded.maximumStreams, 3);
      }
    });

    test('DataBlockedFrame', () {
      final frame = const DataBlockedFrame(maximumData: 999);
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded = decodeFrame(sink.toBytes(), 0).frame as DataBlockedFrame;
      expect(decoded.maximumData, 999);
    });

    test('StreamDataBlockedFrame', () {
      final frame =
          const StreamDataBlockedFrame(streamId: 8, maximumStreamData: 111);
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded =
          decodeFrame(sink.toBytes(), 0).frame as StreamDataBlockedFrame;
      expect(decoded.streamId, 8);
      expect(decoded.maximumStreamData, 111);
    });

    test('StreamsBlockedFrame bidi and uni', () {
      for (final bidi in [true, false]) {
        final frame =
            StreamsBlockedFrame(bidirectional: bidi, maximumStreams: 7);
        final sink = BytesBuilder();
        frame.encode(sink);
        final decoded =
            decodeFrame(sink.toBytes(), 0).frame as StreamsBlockedFrame;
        expect(decoded.bidirectional, bidi);
        expect(decoded.maximumStreams, 7);
      }
    });

    test('RetireConnectionIdFrame', () {
      final frame = const RetireConnectionIdFrame(sequenceNumber: 3);
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded =
          decodeFrame(sink.toBytes(), 0).frame as RetireConnectionIdFrame;
      expect(decoded.sequenceNumber, 3);
    });

    test('PathChallengeFrame / PathResponseFrame carry 8 bytes', () {
      final data = Uint8List.fromList(List.generate(8, (i) => i));
      final challenge = PathChallengeFrame(data: data);
      final sinkC = BytesBuilder();
      challenge.encode(sinkC);
      final decodedC =
          decodeFrame(sinkC.toBytes(), 0).frame as PathChallengeFrame;
      expect(decodedC.data, data);

      final response = PathResponseFrame(data: data);
      final sinkR = BytesBuilder();
      response.encode(sinkR);
      final decodedR =
          decodeFrame(sinkR.toBytes(), 0).frame as PathResponseFrame;
      expect(decodedR.data, data);
    });
  });

  group('NewTokenFrame / NewConnectionIdFrame', () {
    test('NewTokenFrame round-trips', () {
      final frame = NewTokenFrame(token: Uint8List.fromList([1, 2, 3, 4, 5]));
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded = decodeFrame(sink.toBytes(), 0).frame as NewTokenFrame;
      expect(decoded.token, frame.token);
    });

    test('NewConnectionIdFrame round-trips', () {
      final frame = NewConnectionIdFrame(
        sequenceNumber: 1,
        retirePriorTo: 0,
        connectionId: Uint8List.fromList([1, 2, 3, 4]),
        statelessResetToken: Uint8List(16),
      );
      final sink = BytesBuilder();
      frame.encode(sink);
      final decoded =
          decodeFrame(sink.toBytes(), 0).frame as NewConnectionIdFrame;
      expect(decoded.sequenceNumber, 1);
      expect(decoded.connectionId, Uint8List.fromList([1, 2, 3, 4]));
      expect(decoded.statelessResetToken.length, 16);
    });

    test('NewConnectionIdFrame rejects an out-of-range CID length', () {
      // sequence=0, retirePriorTo=0, cid length byte = 21 (invalid, >20)
      final bytes = Uint8List.fromList([0x18, 0x00, 0x00, 21]);
      expect(() => decodeFrame(bytes, 0), throwsA(isA<FrameFormatException>()));
    });
  });

  group('decodeFrame error handling', () {
    test('throws on an unknown frame type', () {
      final bytes = Uint8List.fromList([0xff]);
      expect(() => decodeFrame(bytes, 0), throwsA(isA<FrameFormatException>()));
    });

    test('throws on empty input', () {
      expect(() => decodeFrame(Uint8List(0), 0),
          throwsA(isA<FrameFormatException>()));
    });
  });

  group('decodeAllFrames — RFC 9001 Appendix A.2 client Initial payload', () {
    test('decodes the real CRYPTO frame plus trailing PADDING', () {
      // Same 245-byte CRYPTO frame bytes as the RFC 9001 Appendix A
      // golden test, padded to 1162 bytes with zero (PADDING) bytes —
      // this is exactly the payload shape a real QUIC client Initial
      // packet has, so this is effectively an integration test that
      // dart_quic's frame decoder handles a real handshake packet's
      // payload without desyncing.
      final cryptoFrameBytes = _hex(
        '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
        '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
        '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
        '04616c706e0005000501000000000033'
        '00260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1'
        '5d43e994ec74d748002b000302030400'
        '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
        '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
        '75300901100f088394c8f03e51570806048000ffff',
      );
      final payload = Uint8List(1162)
        ..setRange(0, cryptoFrameBytes.length, cryptoFrameBytes);

      final frames = decodeAllFrames(payload);

      expect(frames.first, isA<CryptoFrame>());
      final crypto = frames.first as CryptoFrame;
      expect(crypto.offset, 0);
      // Length varint 0x40f1 = 0x0f1 = 241.
      expect(crypto.data.length, 241);

      // Every frame after the CRYPTO frame must be PADDING (the zero
      // bytes making up the rest of the 1162-byte payload).
      expect(frames.skip(1), everyElement(isA<PaddingFrame>()));
      expect(frames.length, 1 + (1162 - (1 + 1 + 2 + 241)));
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
