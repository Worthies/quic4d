/// Ties together header.dart, header_protection.dart, and
/// protection.dart into "build one full protected long/short-header
/// packet" and "parse one full protected packet back into frames" --
/// the operations connection.dart's send/receive loop actually calls,
/// so it doesn't need to know the exact order these lower-level pieces
/// compose in (seal payload -> assemble header -> apply header
/// protection, and the mirror image for receiving).
library;

import 'dart:typed_data';

import '../frame/frame_codec.dart';
import 'header.dart';
import 'header_protection.dart';
import 'packet_number_space.dart';
import 'protection.dart';

class PacketBuildResult {
  final Uint8List bytes;
  final int packetNumber;
  const PacketBuildResult({required this.bytes, required this.packetNumber});
}

/// RFC 9001 §5.4.2: the header protection sample is the 16 bytes
/// starting 4 bytes after the start of the packet number field. Since
/// the AEAD tag (16 bytes) always follows the plaintext payload, the
/// bytes available after the packet number field are
/// `packetNumberLength + plaintextPayload.length + 16`, which must be
/// at least `4 + 16 = 20` for the sample to exist at all. Solving for
/// the minimum plaintext length: `plaintextPayload.length >= 4 -
/// packetNumberLength`. A short payload (e.g. a single PING/ACK frame
/// in a 1-byte-packet-number packet) can violate this; pad with
/// PADDING frames (single 0x00 bytes, RFC 9000 §19.1) to the minimum
/// needed length rather than letting every caller remember to do this
/// themselves.
Uint8List _padForHeaderProtectionSample(
    Uint8List plaintextPayload, int packetNumberLength) {
  final minPlaintextLength = (4 - packetNumberLength).clamp(0, 4);
  if (plaintextPayload.length >= minPlaintextLength) return plaintextPayload;

  final paddingNeeded = minPlaintextLength - plaintextPayload.length;
  final padded = Uint8List(plaintextPayload.length + paddingNeeded)
    ..setRange(0, plaintextPayload.length, plaintextPayload);
  return padded;
}

/// Builds one complete, protected long-header packet (Initial or
/// Handshake) containing [frames] as its payload.
Future<PacketBuildResult> buildLongHeaderPacket({
  required LongPacketType type,
  required int version,
  required Uint8List destinationConnectionId,
  required Uint8List sourceConnectionId,
  required Uint8List token,
  required int packetNumber,
  required int packetNumberLength,
  required DirectionalKeys keys,
  required List<Frame> frames,
}) async {
  final payloadSink = BytesBuilder();
  for (final frame in frames) {
    frame.encode(payloadSink);
  }
  var plaintextPayload = payloadSink.toBytes();
  plaintextPayload =
      _padForHeaderProtectionSample(plaintextPayload, packetNumberLength);

  final header = LongHeader(
    type: type,
    reservedBits: 0,
    packetNumberLength: packetNumberLength,
    version: version,
    destinationConnectionId: destinationConnectionId,
    sourceConnectionId: sourceConnectionId,
    token: token,
    packetNumber: packetNumber,
  );
  final encodedHeader =
      header.encode(payloadLength: plaintextPayload.length + 16);

  final protectedPayload = await aeadAes128GcmSeal(
    key: keys.key,
    iv: keys.iv,
    packetNumber: packetNumber,
    header: encodedHeader.bytes,
    plaintextPayload: plaintextPayload,
  );

  final packet = BytesBuilder()
    ..add(encodedHeader.bytes)
    ..add(protectedPayload);
  final packetBytes = packet.toBytes();

  applyHeaderProtection(
    packet: packetBytes,
    hpKey: keys.hp,
    packetNumberOffset: encodedHeader.packetNumberOffset,
    packetNumberLength: packetNumberLength,
    form: HeaderForm.long,
  );

  return PacketBuildResult(bytes: packetBytes, packetNumber: packetNumber);
}

/// Builds one complete, protected short-header (1-RTT) packet.
Future<PacketBuildResult> buildShortHeaderPacket({
  required Uint8List destinationConnectionId,
  required int packetNumber,
  required int packetNumberLength,
  required bool keyPhase,
  required DirectionalKeys keys,
  required List<Frame> frames,
}) async {
  final payloadSink = BytesBuilder();
  for (final frame in frames) {
    frame.encode(payloadSink);
  }
  var plaintextPayload = payloadSink.toBytes();
  plaintextPayload =
      _padForHeaderProtectionSample(plaintextPayload, packetNumberLength);

  final header = ShortHeader(
    reservedBits: 0,
    keyPhase: keyPhase,
    packetNumberLength: packetNumberLength,
    destinationConnectionId: destinationConnectionId,
    packetNumber: packetNumber,
  );
  final encodedHeader = header.encode();

  final protectedPayload = await aeadAes128GcmSeal(
    key: keys.key,
    iv: keys.iv,
    packetNumber: packetNumber,
    header: encodedHeader.bytes,
    plaintextPayload: plaintextPayload,
  );

  final packet = BytesBuilder()
    ..add(encodedHeader.bytes)
    ..add(protectedPayload);
  final packetBytes = packet.toBytes();

  applyHeaderProtection(
    packet: packetBytes,
    hpKey: keys.hp,
    packetNumberOffset: encodedHeader.packetNumberOffset,
    packetNumberLength: packetNumberLength,
    form: HeaderForm.short,
  );

  return PacketBuildResult(bytes: packetBytes, packetNumber: packetNumber);
}

class ParsedPacket {
  final int packetNumber;
  final List<Frame> frames;
  final int totalBytesConsumed;
  const ParsedPacket({
    required this.packetNumber,
    required this.frames,
    required this.totalBytesConsumed,
  });
}

/// Removes header + packet protection from a long-header packet at
/// [offset] in [datagram] and decodes its frames. [largestReceivedPn]
/// is this packet number space's current largest successfully-
/// processed packet number (null if none yet), needed to reconstruct
/// the full packet number from its truncated on-wire form.
Future<ParsedPacket> openLongHeaderPacket({
  required Uint8List datagram,
  required int offset,
  required DirectionalKeys keys,
  required int? largestReceivedPn,
}) async {
  final decoded = LongHeader.decodeUpToPacketNumber(datagram, offset);
  final packetEnd = decoded.packetNumberOffset + decoded.length;
  if (packetEnd > datagram.length) {
    throw const PacketHeaderException(
        'long header packet Length exceeds datagram size');
  }
  // Header protection removal needs a mutable copy scoped to just this
  // packet -- datagram may contain more packets after this one
  // (coalesced packets, RFC 9000 §12.2), and header protection removal
  // mutates the buffer it's given in place.
  final packetBytes = Uint8List.fromList(datagram.sublist(offset, packetEnd));
  final localPnOffset = decoded.packetNumberOffset - offset;

  final removal = removeHeaderProtectionFirstByte(
    packet: packetBytes,
    hpKey: keys.hp,
    packetNumberOffset: localPnOffset,
    form: HeaderForm.long,
  );
  packetBytes[0] = removal.unmaskedFirstByte;
  final pnLength = (removal.unmaskedFirstByte & 0x03) + 1;
  unmaskPacketNumber(
    packet: packetBytes,
    mask: removal.mask,
    packetNumberOffset: localPnOffset,
    packetNumberLength: pnLength,
  );

  var truncatedPn = 0;
  for (var i = 0; i < pnLength; i++) {
    truncatedPn = (truncatedPn << 8) | packetBytes[localPnOffset + i];
  }
  final fullPn = largestReceivedPn == null
      ? truncatedPn
      : decodeFullPacketNumber(
          largestPn: largestReceivedPn,
          truncatedPn: truncatedPn,
          pnBits: pnLength * 8,
        );

  final headerBytes =
      Uint8List.sublistView(packetBytes, 0, localPnOffset + pnLength);
  final protectedPayload =
      Uint8List.sublistView(packetBytes, localPnOffset + pnLength);

  final plaintext = await aeadAes128GcmOpen(
    key: keys.key,
    iv: keys.iv,
    packetNumber: fullPn,
    header: headerBytes,
    protectedPayload: protectedPayload,
  );

  final frames = decodeAllFrames(plaintext);
  return ParsedPacket(
    packetNumber: fullPn,
    frames: frames,
    totalBytesConsumed: packetEnd - offset,
  );
}

/// Removes header + packet protection from a short-header packet
/// occupying the rest of [datagram] starting at [offset] (short-header
/// packets extend to the end of the datagram -- RFC 9000 §12.2) and
/// decodes its frames.
Future<ParsedPacket> openShortHeaderPacket({
  required Uint8List datagram,
  required int offset,
  required int destinationConnectionIdLength,
  required DirectionalKeys keys,
  required int? largestReceivedPn,
}) async {
  final packetBytes = Uint8List.fromList(datagram.sublist(offset));

  final decoded = ShortHeader.decodeUpToPacketNumber(
    packetBytes,
    0,
    destinationConnectionIdLength: destinationConnectionIdLength,
  );

  final removal = removeHeaderProtectionFirstByte(
    packet: packetBytes,
    hpKey: keys.hp,
    packetNumberOffset: decoded.packetNumberOffset,
    form: HeaderForm.short,
  );
  packetBytes[0] = removal.unmaskedFirstByte;
  final pnLength = (removal.unmaskedFirstByte & 0x03) + 1;
  unmaskPacketNumber(
    packet: packetBytes,
    mask: removal.mask,
    packetNumberOffset: decoded.packetNumberOffset,
    packetNumberLength: pnLength,
  );

  var truncatedPn = 0;
  for (var i = 0; i < pnLength; i++) {
    truncatedPn =
        (truncatedPn << 8) | packetBytes[decoded.packetNumberOffset + i];
  }
  final fullPn = largestReceivedPn == null
      ? truncatedPn
      : decodeFullPacketNumber(
          largestPn: largestReceivedPn,
          truncatedPn: truncatedPn,
          pnBits: pnLength * 8,
        );

  final headerBytes = Uint8List.sublistView(
      packetBytes, 0, decoded.packetNumberOffset + pnLength);
  final protectedPayload =
      Uint8List.sublistView(packetBytes, decoded.packetNumberOffset + pnLength);

  final plaintext = await aeadAes128GcmOpen(
    key: keys.key,
    iv: keys.iv,
    packetNumber: fullPn,
    header: headerBytes,
    protectedPayload: protectedPayload,
  );

  final frames = decodeAllFrames(plaintext);
  return ParsedPacket(
    packetNumber: fullPn,
    frames: frames,
    totalBytesConsumed: packetBytes.length,
  );
}
