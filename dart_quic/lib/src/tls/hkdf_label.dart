/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) plus the QUIC-specific
/// Initial-secret derivation (RFC 9001 §5.2 / Appendix A.1).
///
/// This is the one piece of TLS 1.3's key schedule dart_quic needs
/// standalone (outside a full handshake) to bootstrap Initial packet
/// protection — the Initial secret is derived from nothing but the
/// destination connection ID and a fixed salt, before any real
/// handshake bytes exist.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// The version-specific salt used to derive Initial secrets for QUIC v1,
/// per RFC 9001 §5.2.
final Uint8List initialSaltV1 = Uint8List.fromList([
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, //
  0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
  0xcc, 0xbb, 0x7f, 0x0a,
]);

final _sha256 = Sha256();

/// HKDF-Extract(salt, ikm) using HMAC-SHA256, matching TLS 1.3's KDF.
///
/// `package:cryptography`'s [Hkdf.deriveKey] treats its `secretKey`
/// argument as HKDF's IKM and `nonce` as HKDF's salt (see its own
/// example, which passes the salt as `nonce`) — so calling it with a
/// 32-byte fixed `outputLength` and no `info` performs exactly
/// HKDF-Extract followed by one round of HKDF-Expand with empty info,
/// which is *not* the same as a bare HKDF-Extract. Implement Extract
/// directly instead: it is nothing more than
/// `HMAC-Hash(salt, ikm)` (RFC 5869 §2.2).
Future<Uint8List> hkdfExtract({
  required Uint8List salt,
  required Uint8List ikm,
}) async {
  final mac = await Hmac.sha256().calculateMac(
    ikm,
    secretKey: SecretKey(salt),
  );
  return Uint8List.fromList(mac.bytes);
}

/// HKDF-Expand-Label(secret, label, context, length) per RFC 8446 §7.1.
///
/// `label` must be the short label without the `"tls13 "` prefix (e.g.
/// `"client in"`, `"quic key"`) — the prefix is added here, matching how
/// RFC 9001 Appendix A's worked examples show `HkdfLabel.label` already
/// including it (`"tls13 client in"` encoded as
/// `0f746c73313320636c69656e7420696e`, where `0f` = 15 = length of
/// `"tls13 client in"`).
Future<Uint8List> hkdfExpandLabel({
  required Uint8List secret,
  required String label,
  Uint8List? context,
  required int length,
}) async {
  final fullLabel = 'tls13 $label';
  final labelBytes = Uint8List.fromList(fullLabel.codeUnits);
  final ctx = context ?? Uint8List(0);

  // HkdfLabel structure (RFC 8446 §7.1):
  //   uint16 length;
  //   opaque label<7..255>;   // length-prefixed with a single byte
  //   opaque context<0..255>; // length-prefixed with a single byte
  final builder = BytesBuilder();
  builder.add(_uint16(length));
  builder.addByte(labelBytes.length);
  builder.add(labelBytes);
  builder.addByte(ctx.length);
  builder.add(ctx);
  final hkdfLabel = builder.toBytes();

  return _hkdfExpand(secret: secret, info: hkdfLabel, length: length);
}

/// HKDF-Expand(secret, info, length) using HMAC-SHA256 (RFC 5869 §2.3).
///
/// Implemented directly (rather than via [Hkdf.deriveKey], whose
/// `outputLength` is fixed per-instance and whose argument semantics
/// don't map cleanly onto a bare Expand-with-arbitrary-length call) so
/// callers can request any output length, matching HKDF-Expand-Label's
/// variable `length` field.
Future<Uint8List> _hkdfExpand({
  required Uint8List secret,
  required Uint8List info,
  required int length,
}) async {
  const hashLen = 32; // SHA-256
  final n = (length + hashLen - 1) ~/ hashLen;
  if (n > 255) {
    throw ArgumentError('HKDF-Expand: requested length $length too large');
  }
  final prk = SecretKey(secret);
  final okm = BytesBuilder();
  var previous = Uint8List(0);
  for (var i = 1; i <= n; i++) {
    final sink = await Hmac.sha256().newMacSink(secretKey: prk);
    sink.add(previous);
    sink.add(info);
    sink.add([i & 0xFF]);
    sink.close();
    final mac = await sink.mac();
    previous = Uint8List.fromList(mac.bytes);
    okm.add(previous);
  }
  final full = okm.toBytes();
  return Uint8List.sublistView(full, 0, length);
}

Uint8List _uint16(int value) {
  final buf = ByteData(2)..setUint16(0, value);
  return buf.buffer.asUint8List();
}

/// SHA-256 hash of [data] — exposed for handshake transcript hashing
/// (used once the full TLS handshake is implemented in a later
/// milestone).
Future<Uint8List> sha256Hash(Uint8List data) async {
  final hash = await _sha256.hash(data);
  return Uint8List.fromList(hash.bytes);
}
