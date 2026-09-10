import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// RFC 8446 §4.4.1: Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 ||
/// ... || Mn) — a running SHA-256 digest over every handshake message's
/// raw bytes (handshake header included, record layer framing
/// excluded) seen so far, in the exact order sent/received.
///
/// This is a thin incremental wrapper rather than a bare "hash the
/// concatenation" helper: recomputing the hash of an ever-growing byte
/// buffer from scratch on every new message would be quadratic in
/// handshake size, and — more importantly — several key-schedule steps
/// need the transcript hash's value *at a specific point* (e.g. "up
/// through ServerHello", "up through server Finished"), so this
/// exposes [snapshot] rather than only a single final digest.
class TranscriptHash {
  final List<int> _buffer = [];

  /// Appends a handshake message's raw bytes (as it appears on the
  /// wire, including its own type+length header) to the running
  /// transcript.
  void addMessage(Uint8List messageBytes) {
    _buffer.addAll(messageBytes);
  }

  /// The SHA-256 digest of every message added so far. Safe to call
  /// repeatedly at different points in the handshake — each call
  /// re-hashes the accumulated buffer (TLS 1.3 handshakes are small
  /// enough, and infrequent enough per connection, that this is not a
  /// performance concern at commander's scale).
  Future<Uint8List> snapshot() async {
    final hash = await Sha256().hash(_buffer);
    return Uint8List.fromList(hash.bytes);
  }
}

/// SHA-256("") — the empty-message transcript hash needed for the
/// "derived" intermediate secrets in the key schedule (RFC 8446 §7.1),
/// computed once here rather than re-hashing an empty list at every
/// call site.
Future<Uint8List> emptyTranscriptHash() async {
  final hash = await Sha256().hash(const <int>[]);
  return Uint8List.fromList(hash.bytes);
}
