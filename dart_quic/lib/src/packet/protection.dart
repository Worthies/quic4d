/// RFC 9001 §5.3 (packet protection) and §5.4 (header protection) for
/// AEAD_AES_128_GCM — the cipher suite RFC 9001 Appendix A's worked
/// examples use, and the one this milestone verifies byte-for-byte
/// against those examples. Other cipher suites (AES-256-GCM,
/// ChaCha20-Poly1305) are added once the TLS handshake milestone needs
/// to support whatever quic-go/rustls actually negotiates.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart' as pc;

/// Thrown when AEAD packet decryption fails (auth tag mismatch, or
/// input too short to contain a tag) — this is QUIC's primary integrity
/// check, so a caller must treat this as "drop the packet", never as a
/// partial/best-effort result.
class PacketProtectionException implements Exception {
  final String message;
  const PacketProtectionException(this.message);

  @override
  String toString() => 'PacketProtectionException: $message';
}

const int _gcmTagLength = 16;

/// Applies AEAD_AES_128_GCM packet protection (RFC 9001 §5.3) to
/// [plaintextPayload], authenticating [header] as associated data.
///
/// Returns ciphertext with the 16-byte GCM tag appended, matching QUIC's
/// wire format (the tag is not a separate field).
Future<Uint8List> aeadAes128GcmSeal({
  required Uint8List key,
  required Uint8List iv,
  required int packetNumber,
  required Uint8List header,
  required Uint8List plaintextPayload,
}) async {
  final nonce = _packetNonce(iv: iv, packetNumber: packetNumber);
  final algorithm = AesGcm.with128bits(nonceLength: nonce.length);
  final secretBox = await algorithm.encrypt(
    plaintextPayload,
    secretKey: SecretKey(key),
    nonce: nonce,
    aad: header,
  );
  final out = BytesBuilder();
  out.add(secretBox.cipherText);
  out.add(secretBox.mac.bytes);
  return out.toBytes();
}

/// Reverses [aeadAes128GcmSeal]: verifies and decrypts a protected
/// payload (ciphertext with a trailing 16-byte tag) back to plaintext.
///
/// Throws [PacketProtectionException] on any failure — auth failure
/// must never be reported as anything more specific (that would create
/// a padding-oracle-style side channel), and callers must not
/// distinguish "wrong key" from "corrupted/forged packet".
Future<Uint8List> aeadAes128GcmOpen({
  required Uint8List key,
  required Uint8List iv,
  required int packetNumber,
  required Uint8List header,
  required Uint8List protectedPayload,
}) async {
  if (protectedPayload.length < _gcmTagLength) {
    throw const PacketProtectionException(
        'protected payload shorter than the AEAD tag');
  }
  final nonce = _packetNonce(iv: iv, packetNumber: packetNumber);
  final algorithm = AesGcm.with128bits(nonceLength: nonce.length);
  final cipherTextLen = protectedPayload.length - _gcmTagLength;
  final secretBox = SecretBox(
    protectedPayload.sublist(0, cipherTextLen),
    nonce: nonce,
    mac: Mac(protectedPayload.sublist(cipherTextLen)),
  );
  try {
    final plaintext = await algorithm.decrypt(
      secretBox,
      secretKey: SecretKey(key),
      aad: header,
    );
    return Uint8List.fromList(plaintext);
  } on SecretBoxAuthenticationError {
    throw const PacketProtectionException(
        'AEAD authentication failed — packet dropped');
  }
}

/// RFC 9001 §5.3: the per-packet nonce is the IV with the packet number
/// (big-endian, left-padded with zeroes to the IV's length) XORed in.
Uint8List _packetNonce({required Uint8List iv, required int packetNumber}) {
  final nonce = Uint8List.fromList(iv);
  final pnBytes = ByteData(8)..setUint64(0, packetNumber);
  final pnList = pnBytes.buffer.asUint8List();
  // XOR the packet number into the low-order bytes of the nonce (i.e.
  // right-aligned, matching "left-padded with zeros to the size of the
  // IV" in RFC 9001 §5.3).
  final offset = nonce.length - 8;
  for (var i = 0; i < 8; i++) {
    nonce[offset + i] ^= pnList[i];
  }
  return nonce;
}

/// RFC 9001 §5.4.3: computes the 5-byte header protection mask for an
/// AES-based cipher suite by running one block of AES-ECB(hp, sample).
///
/// [sample] must be exactly 16 bytes (one AES block) — taken from the
/// packet's ciphertext starting 4 bytes after the start of the packet
/// number field, per §5.4.2.
Uint8List aesHeaderProtectionMask({
  required Uint8List hpKey,
  required Uint8List sample,
}) {
  if (sample.length != 16) {
    throw ArgumentError(
        'header protection sample must be 16 bytes, got ${sample.length}');
  }
  final cipher = pc.ECBBlockCipher(pc.AESEngine())
    ..init(true, pc.KeyParameter(hpKey));
  final block = Uint8List(16);
  cipher.processBlock(sample, 0, block, 0);
  // Only the first 5 bytes of the AES-ECB output are used as the mask
  // (RFC 9001 §5.4.1: "mask = header_protection(hp_key, sample)... The
  // output ... is truncated to the first five bytes").
  return Uint8List.sublistView(block, 0, 5);
}
