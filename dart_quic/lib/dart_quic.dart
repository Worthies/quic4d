/// Pure-Dart QUIC v1 client, scoped to leaf commander's needs. See
/// `DESIGN.md` for scope and architecture.
///
/// Public API surface is intentionally small and shaped closely to
/// quic4d's own (QuicEndpoint / QuicConnection / QuicSendStream /
/// QuicRecvStream) so that commander/lib/client/quic_client.dart can
/// switch implementations with an import change plus adapting a
/// handful of call sites, rather than a rewrite -- see DESIGN.md's
/// milestone 5 note.
library;

export 'src/api.dart';
export 'src/diagnostics.dart';
