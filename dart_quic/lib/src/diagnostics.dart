/// Library-wide diagnostic tap: every place dart_quic silently
/// discards or swallows something (undecryptable packets, malformed
/// datagrams, peer connection-close reasons, frame-processing
/// exceptions) reports here, so an embedding app can surface it in its
/// own logs instead of the failure being invisible behind the wire
/// protocol's discard-and-continue semantics.
///
/// Deliberately dependency-free and fire-and-forget: a listener that
/// throws must never break the protocol path, so exceptions from
/// listeners are swallowed by design.
typedef QuicDiagnosticListener = void Function(String message);

class QuicDiagnostics {
  QuicDiagnostics._();

  static final List<QuicDiagnosticListener> _listeners = [];

  /// Registers [listener]; returns a function that unregisters it.
  static void Function() listen(QuicDiagnosticListener listener) {
    _listeners.add(listener);
    return () => _listeners.remove(listener);
  }

  /// Reports [message] to all registered listeners.
  static void report(String message) {
    for (final listener in List<QuicDiagnosticListener>.from(_listeners)) {
      try {
        listener(message);
      } catch (_) {
        // Never let a diagnostic listener break the protocol path.
      }
    }
  }
}
