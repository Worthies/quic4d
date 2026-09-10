import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'key_schedule.dart';

/// RFC 8446 §4.4.4: computes a Finished message's `verify_data` —
/// `HMAC(finished_key, Transcript-Hash(...))` — given a handshake
/// traffic secret (client or server) and the transcript hash at the
/// point the Finished message is sent/expected.
///
/// The same function computes both the value dart_quic *sends* (its
/// own client Finished) and the value it *checks* the peer's Finished
/// message against (compare byte-for-byte; a mismatch means the
/// handshake must be aborted — see RFC 8446 §4.4.4's "recipient MUST
/// verify" requirement).
Future<Uint8List> computeFinishedVerifyData({
  required Uint8List handshakeTrafficSecret,
  required Uint8List transcriptHash,
}) async {
  final finishedKey = await deriveFinishedKey(handshakeTrafficSecret);
  final mac = await Hmac.sha256().calculateMac(
    transcriptHash,
    secretKey: SecretKey(finishedKey),
  );
  return Uint8List.fromList(mac.bytes);
}

/// Constant-time comparison for verify_data — RFC 8446 doesn't mandate
/// this explicitly for Finished (unlike, say, session ticket
/// comparison in some other protocols), but a length/early-exit
/// timing side channel on a MAC comparison is a well-known class of
/// bug and there is no reason to accept the risk here.
bool verifyDataMatches(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
