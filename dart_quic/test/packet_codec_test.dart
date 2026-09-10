import 'dart:typed_data';

import 'package:dart_quic/src/frame/frame_codec.dart';
import 'package:dart_quic/src/packet/header.dart';
import 'package:dart_quic/src/packet/initial_secrets.dart';
import 'package:dart_quic/src/packet/packet_codec.dart';
import 'package:dart_quic/src/packet/packet_number_space.dart';
import 'package:test/test.dart';

void main() {
  group('Initial packet round trip (client -> server keys)', () {
    test('build + open recovers the exact frames sent', () async {
      final dcid =
          Uint8List.fromList([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
      final secrets = await deriveInitialSecrets(dcid);
      final clientKeys = DirectionalKeys(
          key: secrets.client.key,
          iv: secrets.client.iv,
          hp: secrets.client.hp);

      final cryptoFrame = CryptoFrame(
          offset: 0, data: Uint8List.fromList(List.generate(50, (i) => i)));

      final built = await buildLongHeaderPacket(
        type: LongPacketType.initial,
        version: quicVersion1,
        destinationConnectionId: dcid,
        sourceConnectionId: Uint8List(0),
        token: Uint8List(0),
        packetNumber: 2,
        packetNumberLength: 4,
        keys: clientKeys,
        frames: [cryptoFrame, const PaddingFrame(), const PaddingFrame()],
      );

      final opened = await openLongHeaderPacket(
        datagram: built.bytes,
        offset: 0,
        keys: clientKeys,
        largestReceivedPn: null,
      );

      expect(opened.packetNumber, 2);
      expect(opened.totalBytesConsumed, built.bytes.length);
      expect(opened.frames.first, isA<CryptoFrame>());
      expect((opened.frames.first as CryptoFrame).data, cryptoFrame.data);
      expect(opened.frames.skip(1), everyElement(isA<PaddingFrame>()));
    });

    test(
        'two coalesced packets in one datagram are each independently '
        'parseable', () async {
      final dcid = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final secrets = await deriveInitialSecrets(dcid);
      final clientKeys = DirectionalKeys(
          key: secrets.client.key,
          iv: secrets.client.iv,
          hp: secrets.client.hp);

      final first = await buildLongHeaderPacket(
        type: LongPacketType.initial,
        version: quicVersion1,
        destinationConnectionId: dcid,
        sourceConnectionId: Uint8List(0),
        token: Uint8List(0),
        packetNumber: 0,
        packetNumberLength: 1,
        keys: clientKeys,
        frames: const [PingFrame()],
      );
      final second = await buildLongHeaderPacket(
        type: LongPacketType.initial,
        version: quicVersion1,
        destinationConnectionId: dcid,
        sourceConnectionId: Uint8List(0),
        token: Uint8List(0),
        packetNumber: 1,
        packetNumberLength: 1,
        keys: clientKeys,
        frames: const [PingFrame(), PingFrame()],
      );

      final datagram = Uint8List.fromList([...first.bytes, ...second.bytes]);

      final openedFirst = await openLongHeaderPacket(
        datagram: datagram,
        offset: 0,
        keys: clientKeys,
        largestReceivedPn: null,
      );
      expect(openedFirst.packetNumber, 0);
      // A lone PING frame is shorter than RFC 9001 SS5.4.2's minimum
      // header-protection-sample payload length, so buildLongHeaderPacket
      // pads it with PADDING frames -- assert on the meaningful frame,
      // not the total count.
      expect(openedFirst.frames, contains(isA<PingFrame>()));

      final openedSecond = await openLongHeaderPacket(
        datagram: datagram,
        offset: openedFirst.totalBytesConsumed,
        keys: clientKeys,
        largestReceivedPn: openedFirst.packetNumber,
      );
      expect(openedSecond.packetNumber, 1);
      expect(
        openedSecond.frames.whereType<PingFrame>().length,
        2,
      );
    });

    test('tampering with the payload causes AEAD verification to fail',
        () async {
      final dcid = Uint8List.fromList([9, 9, 9, 9]);
      final secrets = await deriveInitialSecrets(dcid);
      final clientKeys = DirectionalKeys(
          key: secrets.client.key,
          iv: secrets.client.iv,
          hp: secrets.client.hp);

      final built = await buildLongHeaderPacket(
        type: LongPacketType.initial,
        version: quicVersion1,
        destinationConnectionId: dcid,
        sourceConnectionId: Uint8List(0),
        token: Uint8List(0),
        packetNumber: 5,
        packetNumberLength: 2,
        keys: clientKeys,
        frames: const [PingFrame()],
      );
      final tampered = Uint8List.fromList(built.bytes);
      tampered[tampered.length - 1] ^= 0xFF;

      expect(
        () => openLongHeaderPacket(
          datagram: tampered,
          offset: 0,
          keys: clientKeys,
          largestReceivedPn: null,
        ),
        throwsA(anything),
      );
    });
  });

  group('Short header packet round trip', () {
    test('build + open recovers the exact frames sent', () async {
      // Use Initial-derived keys as a stand-in DirectionalKeys source
      // for this structural round-trip test -- 1-RTT keys would come
      // from key_schedule.dart in a real connection, but the codec
      // logic being tested here (header assembly + AEAD + header
      // protection) doesn't care which traffic secret produced them.
      final dcid =
          Uint8List.fromList([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
      final secrets = await deriveInitialSecrets(dcid);
      final keys = DirectionalKeys(
          key: secrets.client.key,
          iv: secrets.client.iv,
          hp: secrets.client.hp);

      final streamFrame = StreamFrame(
        streamId: 4,
        offset: 0,
        data: Uint8List.fromList('hello quic'.codeUnits),
        fin: false,
      );

      final built = await buildShortHeaderPacket(
        destinationConnectionId: dcid,
        packetNumber: 10,
        packetNumberLength: 2,
        keyPhase: false,
        keys: keys,
        frames: [streamFrame],
      );

      final opened = await openShortHeaderPacket(
        datagram: built.bytes,
        offset: 0,
        destinationConnectionIdLength: dcid.length,
        keys: keys,
        largestReceivedPn: null,
      );

      expect(opened.packetNumber, 10);
      expect(opened.frames.single, isA<StreamFrame>());
      expect((opened.frames.single as StreamFrame).data, streamFrame.data);
    });
  });
}
