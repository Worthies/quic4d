/// RFC 9000 §2.1: client-initiated bidirectional stream IDs are
/// 0, 4, 8, 12, ... (the low 2 bits of a stream ID encode
/// initiator+directionality; 0b00 is "client-initiated, bidirectional").
/// [ClientBidiStreamIdAllocator] hands out exactly that sequence, one
/// call per stream a [Connection] opens -- extracted as a small, pure,
/// directly-unit-testable class (see stream_id_allocator_test.dart)
/// rather than inlined as a mutable field on [Connection] itself, which
/// has no isolated-construction path a unit test could exercise without
/// a live handshake (see that file's own tests for why the real
/// multi-stream *routing* behavior is instead covered by a live
/// quic-go integration test, matching DESIGN.md's testing strategy).
class ClientBidiStreamIdAllocator {
  int _next = 0;

  /// Returns the next stream ID in sequence (0, then 4, then 8, ...).
  int allocate() {
    final id = _next;
    _next += 4;
    return id;
  }

  /// The stream ID that will be returned by the next [allocate] call,
  /// without consuming it -- used by [Connection.openAdditionalStream]
  /// to check the server's own `initial_max_streams_bidi` limit before
  /// actually allocating (see that method's own doc comment).
  int get peekNext => _next;
}
