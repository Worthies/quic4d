/// RFC 9001 §5.4: applying/removing header protection on a QUIC packet.
///
/// Header protection masks the packet-number-length bits in the first
/// byte and the packet number field itself, using a keystream sample
/// taken from the packet's own ciphertext (so the mask can only be
/// computed by someone who already has the payload protection key —
/// this is what stops a QUIC packet from being trivially fingerprinted
/// on the wire by mutable header fields alone).
library;

import 'dart:typed_data';

import 'protection.dart';

/// Long-header packets reserve 4 bits after the fixed bit for a
/// PN-length field; short-header packets reserve 5. This affects which
/// bits of `mask[0]` get XORed (RFC 9001 §5.4.1).
enum HeaderForm { long, short }

/// Applies header protection in place to [packet] (a full packet: header
/// bytes immediately followed by the protected payload), given the
/// already-computed [hpKey] and the offset in [packet] where the packet
/// number field begins ([packetNumberOffset]) and its encoded length in
/// bytes ([packetNumberLength], 1-4).
///
/// This must run *after* payload encryption (`aeadAes128GcmSeal`), since
/// the sample it needs is drawn from that ciphertext (RFC 9001 §5.4.2:
/// "the Key Phase bit ... sample of ciphertext from the packet").
void applyHeaderProtection({
  required Uint8List packet,
  required Uint8List hpKey,
  required int packetNumberOffset,
  required int packetNumberLength,
  required HeaderForm form,
}) {
  final sample = _sample(packet, packetNumberOffset);
  final mask = aesHeaderProtectionMask(hpKey: hpKey, sample: sample);

  packet[0] ^= form == HeaderForm.long ? (mask[0] & 0x0f) : (mask[0] & 0x1f);
  for (var i = 0; i < packetNumberLength; i++) {
    packet[packetNumberOffset + i] ^= mask[1 + i];
  }
}

/// Removes header protection in place from [packet]. Unlike applying
/// it, the caller doesn't yet know the real `packetNumberLength` (that
/// information is itself protected) — this first unmasks byte 0 alone,
/// lets the caller read the now-correct PN-length bits back out, then a
/// second call (or the caller inlining the remaining XOR) finishes
/// unmasking the packet number bytes. To keep this simple and match how
/// every real implementation does it, this function takes the maximum
/// possible PN length (4) worth of sample positioning up front and
/// returns the unmasked first byte and mask so the caller can determine
/// the real PN length itself before applying the rest of the mask.
class HeaderProtectionRemoval {
  /// The unmasked first byte of the packet (safe to inspect the
  /// PN-length bits in now).
  final int unmaskedFirstByte;

  /// The full 5-byte mask — byte 0 already applied to
  /// [unmaskedFirstByte]; bytes 1-4 not yet applied to the packet number
  /// field (caller must XOR only as many as `packetNumberLength` needs).
  final Uint8List mask;

  const HeaderProtectionRemoval(
      {required this.unmaskedFirstByte, required this.mask});
}

/// Computes the header-protection mask and unmasked first byte for
/// [packet], without touching the packet number bytes yet (their real
/// length isn't known until the first byte is unmasked).
HeaderProtectionRemoval removeHeaderProtectionFirstByte({
  required Uint8List packet,
  required Uint8List hpKey,
  required int packetNumberOffset,
  required HeaderForm form,
}) {
  final sample = _sample(packet, packetNumberOffset);
  final mask = aesHeaderProtectionMask(hpKey: hpKey, sample: sample);
  final unmasked = packet[0] ^
      (form == HeaderForm.long ? (mask[0] & 0x0f) : (mask[0] & 0x1f));
  return HeaderProtectionRemoval(unmaskedFirstByte: unmasked, mask: mask);
}

/// Finishes header-protection removal once the real [packetNumberLength]
/// (decoded from [HeaderProtectionRemoval.unmaskedFirstByte]'s low bits)
/// is known: XORs the packet number field in place using the
/// previously-computed [mask].
void unmaskPacketNumber({
  required Uint8List packet,
  required Uint8List mask,
  required int packetNumberOffset,
  required int packetNumberLength,
}) {
  for (var i = 0; i < packetNumberLength; i++) {
    packet[packetNumberOffset + i] ^= mask[1 + i];
  }
}

/// RFC 9001 §5.4.2: the sample is the 16 bytes starting 4 bytes after
/// the beginning of the packet number field — fixed at 4 regardless of
/// the packet number's *actual* encoded length, so both sender and
/// receiver can locate it before agreeing on that length.
Uint8List _sample(Uint8List packet, int packetNumberOffset) {
  const sampleOffsetFromPnStart = 4;
  const sampleLength = 16;
  final start = packetNumberOffset + sampleOffsetFromPnStart;
  if (start + sampleLength > packet.length) {
    throw ArgumentError(
        'packet too short to contain a header-protection sample');
  }
  return Uint8List.sublistView(packet, start, start + sampleLength);
}
