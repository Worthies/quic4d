/// The top-level QUIC v1 client connection state machine (RFC 9000):
/// owns the UDP socket, drives [ClientHandshake] with real network I/O,
/// manages the three packet number spaces (Initial/Handshake/
/// ApplicationData) including their independent keys and loss/
/// congestion state, and exposes a single bidirectional stream --
/// exactly and only what DESIGN.md scopes this library to.
///
/// Concurrency model: a single receive loop (`_receiveLoop`) reads
/// datagrams off the socket and dispatches; sends happen synchronously
/// from whichever call triggered them (handshake progress, stream
/// writes, ACK/PING generation). No isolates -- see DESIGN.md's
/// architecture note on why that's deferred until profiling shows it
/// matters at commander's message rates.
library;

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'frame/frame_codec.dart';
import 'handshake/client_handshake.dart';
import 'diagnostics.dart';
import 'packet/header.dart';
import 'packet/initial_secrets.dart';
import 'packet/packet_codec.dart';
import 'packet/packet_number_space.dart';
import 'packet/protection.dart' show PacketProtectionException;
import 'recovery/congestion_control.dart';
import 'recovery/loss_detection.dart' show LostPacket;
import 'recovery/rtt_estimator.dart';
import 'recovery/sent_packet.dart';
import 'tls/transport_parameters.dart';

class ConnectionException implements Exception {
  final String message;
  const ConnectionException(this.message);

  @override
  String toString() => 'ConnectionException: $message';
}

/// RFC 9000 §14.1: the minimum UDP datagram payload size a client must
/// expand every Initial-packet-carrying datagram to.
const int kMinimumInitialDatagramSize = 1200;

/// Largest STREAM-frame payload [QuicStream.write] will place in a
/// single 1-RTT packet. RFC 9000 places no protocol-level limit on a
/// STREAM frame's data length short of the packet it travels in, but
/// nothing in this library (or the UDP layer beneath it) fragments an
/// oversized packet -- a single write() call used to build ONE packet
/// containing the ENTIRE payload, however large. That is invisible for
/// short chat messages but breaks completely for anything past roughly
/// a kilobyte: real quic-go peers silently ignore packets whose UDP
/// datagram exceeds the negotiated max_udp_payload_size, and a payload
/// anywhere near 64KB blows straight through the OS's own UDP
/// `sendto()` limit (`EMSGSIZE`) before even reaching the network --
/// both reproduced live against server/quic_visitor.go's real
/// quic-go-based server (see test/integration/large_write_test.dart).
/// [write] instead splits [data] into chunks of at most this many
/// bytes, one STREAM frame/packet per chunk, matching how every real
/// QUIC stack paces stream data across multiple packets. Deliberately
/// well under [kMinimumMaxDatagramSize] to leave headroom for the
/// short header, AEAD tag, and STREAM frame's own type/streamId/
/// offset/length varints, without needing to compute that overhead
/// exactly per chunk.
const int kMaxStreamFrameChunkSize = 1000;

enum ConnectionState { connecting, handshaking, connected, closed }

/// In-order reassembly of one stream's received data from possibly
/// overlapping, possibly reordered STREAM frames.
///
/// Two QUIC realities make this more than "append if offset matches":
///   1. RFC 9000 §19.8 allows frames to overlap already-received
///      ranges, and RFC 9002 §7.2.2 lets a peer retransmit stream data
///      re-chunked under DIFFERENT frame boundaries -- so a frame can
///      straddle the delivery frontier (start below it, end above) and
///      must contribute its new tail, never be dropped wholesale.
///      Dropping it stalled the stream forever: the peer counted those
///      bytes as delivered and nothing ever re-sent them.
///   2. Frames above the frontier may arrive in any order and may
///      themselves overlap each other; buffering keeps whichever
///      coverage reaches furthest.
class StreamReassembler {
  int _receiveOffset = 0;
  final Map<int, Uint8List> _outOfOrder = {};
  final void Function(Uint8List data) _deliver;

  StreamReassembler(this._deliver);

  /// How many contiguous bytes (from stream offset 0) have been
  /// delivered so far.
  int get receiveOffset => _receiveOffset;

  /// Number of buffered out-of-order entries still held (for tests of
  /// eviction hygiene -- stale fully-covered entries must not linger).
  int get pendingEntryCount => _outOfOrder.length;

  void add(int offset, Uint8List data) {
    if (offset < _receiveOffset) {
      final skip = _receiveOffset - offset;
      if (skip >= data.length) return; // fully-duplicate retransmission
      data = Uint8List.sublistView(data, skip);
      offset = _receiveOffset;
    }
    if (offset == _receiveOffset) {
      _deliver(data);
      _receiveOffset += data.length;
      _drainOutOfOrder();
      return;
    }
    final existing = _outOfOrder[offset];
    if (existing == null || existing.length < data.length) {
      _outOfOrder[offset] = data;
    }
  }

  void _drainOutOfOrder() {
    while (true) {
      final exact = _outOfOrder.remove(_receiveOffset);
      if (exact != null) {
        _deliver(exact);
        _receiveOffset += exact.length;
        continue;
      }
      // A buffered entry may straddle the frontier after other
      // deliveries advanced it -- deliver its tail.
      int? straddleKey;
      Uint8List? straddleData;
      for (final e in _outOfOrder.entries) {
        if (e.key < _receiveOffset && e.key + e.value.length > _receiveOffset) {
          straddleKey = e.key;
          straddleData = e.value;
          break;
        }
      }
      if (straddleKey == null || straddleData == null) {
        // Nothing deliverable: evict stale entries the frontier has
        // fully covered (e.g. a shorter retransmission buffered next
        // to a longer one that later drained) so they cannot linger
        // for the connection's lifetime.
        _outOfOrder.removeWhere(
            (k, v) => k < _receiveOffset && k + v.length <= _receiveOffset);
        return;
      }
      _outOfOrder.remove(straddleKey);
      final tail =
          Uint8List.sublistView(straddleData, _receiveOffset - straddleKey);
      _deliver(tail);
      _receiveOffset += tail.length;
    }
  }
}

/// A single client-initiated bidirectional stream -- DESIGN.md's entire
/// stream model. Always stream ID 0 (the first client-initiated
/// bidirectional stream ID per RFC 9000 §2.1's numbering scheme).
class QuicStream {
  static const int clientBidiStreamId0 = 0;

  final Connection _connection;
  // Broadcast semantics are kept (multiple listeners allowed, late
  // subscribers see only future data), but a broadcast StreamController
  // DROPS events added while nobody is listening. That is wrong for
  // stream data: bytes arrive from the network the moment the peer
  // sends them, which can precede the app's first listen() by an
  // arbitrary margin (commander's first-entry bug: the server's
  // welcome message landed between openBi()/writeAll() and the read
  // loop's listen(), and was silently discarded -- empty visitor
  // panel, nothing received until a forced reconnect). So chunks
  // delivered before the first listener are parked here and replayed
  // in order on listen.
  final List<Uint8List> _pendingBeforeFirstListener = [];
  late final StreamController<Uint8List> _incomingController;
  int _sendOffset = 0;
  late final StreamReassembler _reassembler = StreamReassembler(_deliver);

  QuicStream._(this._connection) {
    _incomingController = StreamController<Uint8List>.broadcast(
      onListen: _replayParkedChunks,
    );
  }

  void _replayParkedChunks() {
    final parked = List<Uint8List>.from(_pendingBeforeFirstListener);
    _pendingBeforeFirstListener.clear();
    for (final chunk in parked) {
      _incomingController.add(chunk);
    }
  }

  void _deliver(Uint8List data) {
    if (!_incomingController.hasListener) {
      // No listener yet: park the chunk (bounded by the receive
      // flow-control window, i.e. no more than what a listening app
      // would have buffered anyway) and replay on the first listen().
      _pendingBeforeFirstListener.add(data);
      return;
    }
    _incomingController.add(data);
  }

  /// Bytes received on this stream, in order, as they arrive --
  /// possibly split across multiple events per STREAM frame rather
  /// than reassembled into an application-level framing (that's
  /// commander's own newline-delimited-JSON layer's job, same as the
  /// existing MTLSClient/QuicClient transports).
  Stream<Uint8List> get incoming => _incomingController.stream;

  /// Sends [data] on this stream, transparently splitting it across
  /// multiple STREAM frames/packets of at most
  /// [kMaxStreamFrameChunkSize] bytes each -- see that constant's doc
  /// for why a single write() call used to silently fail for anything
  /// much bigger than a short chat message. Each chunk carries its own
  /// correct offset ([_sendOffset] is advanced by the connection layer
  /// as each chunk is actually transmitted, honoring send-side flow
  /// control -- chunks may queue until the peer opens its window), so
  /// the receiver's existing offset-based reassembly
  /// ([_handleFrame]/[_drainOutOfOrder]) needs no changes.
  Future<void> write(Uint8List data) async {
    if (data.isEmpty) return;
    var pos = 0;
    while (pos < data.length) {
      final end = (pos + kMaxStreamFrameChunkSize < data.length)
          ? pos + kMaxStreamFrameChunkSize
          : data.length;
      final chunk = Uint8List.sublistView(data, pos, end);
      await _connection._sendStreamData(chunk);
      pos = end;
    }
  }

  void _handleFrame(StreamFrame frame) {
    _reassembler.add(frame.offset, frame.data);
  }

  Future<void> close() async {
    await _incomingController.close();
  }
}

/// Top-level connection API, shaped closely to quic4d's
/// QuicEndpoint/QuicConnection surface (see DESIGN.md's milestone 5
/// note) so a future swap in commander's quic_client.dart is mostly an
/// import change plus adapting the async/stream call sites.
class Connection {
  RawDatagramSocket? _socket;
  InternetAddress? _remoteAddress;
  int? _remotePort;

  /// The initial randomly-chosen DCID used only to derive Initial
  /// packet protection keys (RFC 9001 §5.2: fixed to the *first*
  /// Initial packet's DCID for the lifetime of the connection, even
  /// after the server's real connection ID is learned).
  final Uint8List _initialDestinationConnectionId;

  /// The DCID actually placed in outgoing packet headers -- starts as
  /// [_initialDestinationConnectionId] but RFC 9000 §7.2 requires
  /// switching to the server's Source Connection ID (learned from its
  /// first Initial/Handshake packet) for everything sent afterward.
  Uint8List _destinationConnectionId;
  bool _destinationConnectionIdConfirmed = false;

  final Uint8List _sourceConnectionId;
  final ClientHandshake _handshake;

  final RttEstimator _sharedRtt = RttEstimator();
  late final PacketNumberSpace _initialSpace;
  late final PacketNumberSpace _handshakeSpace;
  late final PacketNumberSpace _oneRttSpace;
  final CongestionController _congestion = CongestionController();

  // ---- Receive-side flow control (RFC 9000 §4) ----
  // The limits we advertised in our transport parameters. Once the
  // peer has sent half the current limit, [_onStreamBytesReceived]
  // raises it and queues MAX_DATA/MAX_STREAM_DATA frames onto the next
  // ACK. Without these updates the peer is flow-control BLOCKED
  // forever once it has sent the initial 10 MiB -- observed live as
  // "connection goes silent, commander's 45s watchdog reconnects",
  // with every reconnect's history sync burning through the fresh
  // window faster and disconnects getting more frequent.
  int _connectionReceiveLimit = 10 * 1024 * 1024;
  int _connectionBytesReceived = 0;
  int _streamReceiveLimit = 10 * 1024 * 1024;
  int _maxStreamEndOffset = 0;

  // ---- Send-side flow control (RFC 9000 §4) ----
  // How much this endpoint may still send, per the peer's advertised
  // initial limits (parsed from the server's transport parameters --
  // previously never parsed at all, so sends beyond the server's
  // initial window worked only by luck of the server's reader keeping
  // up) plus any MAX_DATA/MAX_STREAM_DATA updates it sends while the
  // connection is live. Writes beyond the allowance queue in
  // [_pendingSends] until the peer opens the window.
  int _connectionSendAllowance = 0;
  int _streamSendAllowance = 0;
  final List<Uint8List> _pendingSends = [];

  /// Total stream payload bytes this endpoint has SENT (1-RTT), for
  /// converting the peer's absolute MAX_DATA/MAX_STREAM_DATA offsets
  /// into remaining allowances.
  int _connectionBytesSent = 0;
  int _streamBytesSent = 0;

  /// Window-update frames queued for the next outbound packet, set by
  /// [_onStreamBytesReceived] and consumed by
  /// [_takePendingFlowControlFrames].
  final List<Frame> _pendingFlowControlFrames = [];

  ConnectionState state = ConnectionState.connecting;

  /// RFC 9001 §8.2: the Source Connection ID of the server's first
  /// Initial packet, captured at receive time so
  /// [_validateServerInitialSourceConnectionId] can compare it against
  /// the initial_source_connection_id the server later declares in its
  /// transport parameters.
  Uint8List? _serverFirstInitialScid;
  QuicStream? _stream;
  Timer? _pingTimer;
  Timer? _lossDetectionTimer;
  Timer? _idleTimeoutTimer;
  final StreamController<void> _handshakeCompleteController =
      StreamController<void>.broadcast();

  /// RFC 9000 §10.1: the connection is idle-timed-out if no packet has
  /// been received from the peer for this long. DESIGN.md fixes this
  /// at 30s to match agents/quic_conn.go and server/quic_visitor.go's
  /// shared quicKeepaliveConfig.MaxIdleTimeout -- both peers use the
  /// same value, so whichever side's timer fires first tears down the
  /// connection.
  static const Duration _maxIdleTimeout = Duration(seconds: 30);
  DateTime _lastPacketReceivedAt = DateTime.now();

  final StreamController<void> _connectionClosedController =
      StreamController<void>.broadcast();

  /// Fires (once) when the connection transitions to
  /// [ConnectionState.closed] for any reason -- idle timeout, a
  /// received CONNECTION_CLOSE, or an explicit [close] call. Lets
  /// commander's transport layer detect an unexpected drop without
  /// polling [state].
  Stream<void> get onClosed => _connectionClosedController.stream;

  Connection._({
    required Uint8List destinationConnectionId,
    required Uint8List sourceConnectionId,
    required ClientHandshake handshake,
  })  : _initialDestinationConnectionId = destinationConnectionId,
        _destinationConnectionId = destinationConnectionId,
        _sourceConnectionId = sourceConnectionId,
        _handshake = handshake {
    _initialSpace = PacketNumberSpace(_sharedRtt);
    _handshakeSpace = PacketNumberSpace(_sharedRtt);
    _oneRttSpace = PacketNumberSpace(_sharedRtt);
  }

  /// Opens a UDP socket, performs the full QUIC handshake (including
  /// mTLS if [clientIdentity] is given) against [host]:[port], and
  /// returns a connected [Connection] once the handshake completes.
  /// [onServerCertificateChain] mirrors [ClientHandshake]'s own
  /// callback -- see its doc comment for why chain validation is the
  /// caller's responsibility.
  static Future<Connection> connect({
    required String host,
    required int port,
    String? serverName,
    ClientIdentity? clientIdentity,
    void Function(List<Uint8List> serverCertificateChainDer)?
        onServerCertificateChain,
    Duration handshakeTimeout = const Duration(seconds: 10),
  }) async {
    final random = Random.secure();
    final destinationConnectionId =
        Uint8List.fromList(List.generate(8, (_) => random.nextInt(256)));
    final sourceConnectionId =
        Uint8List.fromList(List.generate(8, (_) => random.nextInt(256)));
    final clientRandom =
        Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));

    final clientTransportParameters = TransportParameters.clientDefaults(
      initialSourceConnectionId: sourceConnectionId,
    );

    final handshake = await ClientHandshake.create(
      clientRandom: clientRandom,
      clientTransportParameters: clientTransportParameters,
      serverName: serverName ?? host,
      clientIdentity: clientIdentity,
      onServerCertificateChain: onServerCertificateChain,
    );

    final connection = Connection._(
      destinationConnectionId: destinationConnectionId,
      sourceConnectionId: sourceConnectionId,
      handshake: handshake,
    );

    await connection._openSocketAndHandshake(
      host: host,
      port: port,
      handshakeTimeout: handshakeTimeout,
    );

    return connection;
  }

  Future<void> _openSocketAndHandshake({
    required String host,
    required int port,
    required Duration handshakeTimeout,
  }) async {
    final addresses = await InternetAddress.lookup(host);
    if (addresses.isEmpty) {
      throw ConnectionException('could not resolve host: $host');
    }
    _remoteAddress = addresses.first;
    _remotePort = port;

    _socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    _socket!.listen(_onSocketEvent);

    final initialSecrets =
        await deriveInitialSecrets(_initialDestinationConnectionId);
    _initialSpace.keys.client = DirectionalKeyRing(Uint8List(0));
    await _initialSpace.keys.client!.installInitial(
      initialSecrets.client.key,
      initialSecrets.client.iv,
      initialSecrets.client.hp,
    );
    _initialSpace.keys.server = DirectionalKeyRing(Uint8List(0));
    await _initialSpace.keys.server!.installInitial(
      initialSecrets.server.key,
      initialSecrets.server.iv,
      initialSecrets.server.hp,
    );

    _handshake.start();
    await _flushHandshakeOutbound();
    _rearmLossDetectionTimer(); // covers the handshake's own PTO too

    final completer = Completer<void>();
    final sub = _handshakeCompleteController.stream.listen((_) {
      if (!completer.isCompleted) completer.complete();
    }, onError: (Object e, StackTrace st) {
      if (!completer.isCompleted) completer.completeError(e, st);
    });
    try {
      await completer.future.timeout(handshakeTimeout);
    } on TimeoutException {
      throw const ConnectionException('handshake timed out');
    } finally {
      await sub.cancel();
    }

    state = ConnectionState.connected;
    _lastPacketReceivedAt = DateTime.now();
    _startPingTimer();
    _startIdleTimeoutTimer();
    _rearmLossDetectionTimer();
  }

  /// Serializes datagram processing: [_onSocketEvent] fires
  /// synchronously and can drain several already-arrived datagrams in
  /// one call, but each datagram's processing is itself async (crypto
  /// operations, handshake state transitions). Firing those
  /// concurrently via bare `unawaited` calls let a second datagram's
  /// processing interleave with the first's -- observed empirically as
  /// a corrupted TLS transcript hash (and thus a Finished
  /// verify_data mismatch) against a live quic-go server when it
  /// retransmitted a Handshake packet while the first one was still
  /// being processed. This future chains each datagram strictly after
  /// the previous one finishes.
  Future<void> _processingChain = Future.value();

  void _onSocketEvent(RawSocketEvent event) {
    if (event != RawSocketEvent.read) return;
    // RawDatagramSocket can coalesce multiple already-arrived datagrams
    // behind a single read-ready event -- drain every pending datagram
    // now rather than assuming one event means exactly one datagram,
    // or a second datagram that arrived in the same tick could sit
    // unprocessed until some unrelated future event happens to fire.
    Datagram? datagram;
    while ((datagram = _socket!.receive()) != null) {
      final data = datagram!.data;
      // RFC 9000 SS12.2: a packet whose protection can't be removed MUST
      // be discarded while the rest of the datagram is still attempted --
      // and a single bad packet must never poison this chain, since every
      // later datagram is chained behind it. Without this catchError an
      // AEAD failure on any packet permanently stopped ALL inbound
      // processing (observed live as "connects, welcome arrives, then no
      // messages ever again" against a real quic-go server).
      _processingChain =
          _processingChain.then((_) => _handleDatagram(data)).catchError(
        (Object e, StackTrace st) {
          // Diagnostics only, RFC 9000 §12.2 discard-and-continue applies
          // regardless: swallow it rather than letting it escape to the
          // socket-event handler -- but report it, since a recurring
          // exception here is exactly the "messages silently stop"
          // class of failure that is otherwise invisible.
          QuicDiagnostics.report(
              'datagram processing failed (${e.runtimeType}): $e @ '
              '${st.toString().split('\n').take(3).join(' | ')}');
        },
      );
    }
  }

  /// The key era outgoing 1-RTT packets are protected with -- always
  /// the client ring's latest, whose keyPhase the short-header first
  /// byte carries (updated by _handleShortHeaderPacketAt when the peer
  /// rotates, per RFC 9001 §6.1).
  KeyEra _oneRttSendEra() => _oneRttSpace.keys.client!.latest;

  Future<void> _handleDatagram(Uint8List datagram) async {
    // NOTE: the idle timer is deliberately NOT reset here, at datagram
    // arrival -- only once a packet actually decrypts/authenticates
    // (see the two handlers below). RFC 9000 §10.1: "An endpoint
    // restarts its idle timer ... when a packet it receives is
    // successfully processed"; resetting on undecryptable garbage let
    // any spoofed datagram keep a dead connection alive indefinitely.
    var offset = 0;
    while (offset < datagram.length) {
      final firstByte = datagram[offset];
      final isLongHeader = (firstByte & 0x80) != 0;
      if (isLongHeader) {
        offset = await _handleLongHeaderPacketAt(datagram, offset);
      } else {
        try {
          await _handleShortHeaderPacketAt(datagram, offset);
        } on PacketProtectionException {
          // RFC 9000 §12.2: a packet that can't be authenticated is
          // discarded silently; processing continues with whatever
          // else is in flight rather than treating this as fatal.
        }
        offset = datagram.length; // short header always consumes the rest
      }
      if (offset < 0) break;
    }
  }

  Future<int> _handleLongHeaderPacketAt(Uint8List datagram, int offset) async {
    final peek = LongHeader.decodeUpToPacketNumber(datagram, offset);
    // RFC 9000 §7.2: once the client processes the server's first
    // Initial (or, in practice against a real quic-go peer, whichever
    // packet actually arrives first -- Initial and Handshake can be
    // coalesced in the same datagram, and only the DCID matters here,
    // not which packet type carried it) packet, it must switch its own
    // outgoing Destination Connection ID to the server's Source
    // Connection ID rather than keep using its own initial guess.
    if (!_destinationConnectionIdConfirmed &&
        peek.header.sourceConnectionId.isNotEmpty) {
      _destinationConnectionId = peek.header.sourceConnectionId;
      _destinationConnectionIdConfirmed = true;
    }
    // RFC 9001 §8.2 prerequisite: remember the Source Connection ID of
    // the server's FIRST Initial packet, for later comparison against
    // the initial_source_connection_id in its transport parameters.
    if (_serverFirstInitialScid == null &&
        peek.header.type == LongPacketType.initial &&
        peek.header.sourceConnectionId.isNotEmpty) {
      _serverFirstInitialScid = peek.header.sourceConnectionId;
    }
    final space = switch (peek.header.type) {
      LongPacketType.initial => _initialSpace,
      LongPacketType.handshake => _handshakeSpace,
      LongPacketType.zeroRtt => throw const ConnectionException(
          '0-RTT is not supported (see DESIGN.md scope)'),
      LongPacketType.retry => throw const ConnectionException(
          'Retry packets are not supported (see DESIGN.md scope)'),
    };
    if (space.discarded || !space.keys.hasKeys) {
      // Can't decrypt (keys already discarded, or not installed yet) --
      // RFC 9000 §12.2 permits dropping and continuing with whatever
      // else is coalesced, but since the Length field is inside the
      // still-unprotected header we already parsed, we know exactly
      // how many bytes to skip.
      if (space.discarded) {
        QuicDiagnostics.report(
            'dropped ${peek.header.type.name} packet after key discard '
            '(pn offset ${peek.packetNumberOffset}, len ${peek.length})');
      }
      return peek.packetNumberOffset + peek.length;
    }

    final parsed = await openLongHeaderPacket(
      datagram: datagram,
      offset: offset,
      keys: space.keys.serverLatest!,
      largestReceivedPn: space.largestReceivedPacketNumber,
    );
    space.largestReceivedPacketNumber =
        space.largestReceivedPacketNumber == null
            ? parsed.packetNumber
            : (space.largestReceivedPacketNumber! > parsed.packetNumber
                ? space.largestReceivedPacketNumber!
                : parsed.packetNumber);
    space.received.onReceived(parsed.packetNumber);
    _noteAuthenticatedPacketReceived();

    await _processFrames(
      parsed.frames,
      level: peek.header.type == LongPacketType.initial
          ? EncryptionLevel.initial
          : EncryptionLevel.handshake,
      space: space,
    );

    await _maybeSendAck(space, type: peek.header.type);

    return offset + parsed.totalBytesConsumed;
  }

  Future<void> _handleShortHeaderPacketAt(
      Uint8List datagram, int offset) async {
    if (!_oneRttSpace.keys.hasKeys) return; // 1-RTT keys not ready yet
    final serverRing = _oneRttSpace.keys.server!;
    final eraCountBeforeOpen = serverRing.eras.length;
    final parsed = await openShortHeaderPacket(
      datagram: datagram,
      offset: offset,
      destinationConnectionIdLength: _sourceConnectionId.length,
      keyRing: serverRing,
      largestReceivedPn: _oneRttSpace.largestReceivedPacketNumber,
    );
    // RFC 9001 §6.1: the trial next-era derivation inside
    // openShortHeaderPacket authenticated, so the peer genuinely
    // rotated its keys -- the server ring just grew. Follow by rotating
    // OUR send keys too, so both directions stay in adjacent eras and
    // the peer's own receive path sees the same key-update handshake
    // (quic-go accepts either era on receive, same as we now do).
    if (serverRing.eras.length > eraCountBeforeOpen) {
      await _oneRttSpace.keys.client!.advance();
    }
    _oneRttSpace.largestReceivedPacketNumber =
        _oneRttSpace.largestReceivedPacketNumber == null
            ? parsed.packetNumber
            : (_oneRttSpace.largestReceivedPacketNumber! > parsed.packetNumber
                ? _oneRttSpace.largestReceivedPacketNumber!
                : parsed.packetNumber);
    _oneRttSpace.received.onReceived(parsed.packetNumber);
    _noteAuthenticatedPacketReceived();

    await _processFrames(
      parsed.frames,
      level: EncryptionLevel.oneRtt,
      space: _oneRttSpace,
    );
    await _maybeSendShortHeaderAck();
  }

  /// RFC 9000 §10.1: the idle timer restarts only for packets that
  /// were successfully processed (decrypted + authenticated) -- called
  /// from both packet handlers at their decrypt-success points, never
  /// at raw datagram arrival (see _handleDatagram's note).
  void _noteAuthenticatedPacketReceived() {
    _lastPacketReceivedAt = DateTime.now();
    if (state != ConnectionState.closed) _startIdleTimeoutTimer();
  }

  /// RFC 9000 §13.2.1 (roughly): dart_quic acknowledges every
  /// ack-eliciting Initial/Handshake packet immediately rather than
  /// implementing full delayed-ack batching -- the handshake is a
  /// handful of packets total, and a real quic-go server needs a
  /// prompt ACK to release more of its anti-amplification budget
  /// (RFC 9000 §8.1) before it can send the rest of its flight (the
  /// Certificate/CertificateVerify/Finished messages, empirically
  /// observed to get stuck without this against a live quic-go
  /// server; see test/integration/quic_go_interop_test.dart).
  Future<void> _maybeSendAck(PacketNumberSpace space,
      {required LongPacketType type}) async {
    // Honest multi-range ACK from the received-packet tracker: every
    // packet actually received so far is acknowledged, not just the
    // single largest -- see ReceivedPacketTracker's doc for the
    // retransmission-amplification bug the old largest-only ACK
    // caused against a real quic-go server.
    final ackFrame = space.received.buildAckFrame(0);
    if (ackFrame == null) return;
    final packetNumber = space.allocatePacketNumber();
    final pnLength =
        packetNumberEncodingLength(packetNumber, space.largestAckedPacket);
    final built = await buildLongHeaderPacket(
      type: type,
      version: quicVersion1,
      destinationConnectionId: _destinationConnectionId,
      sourceConnectionId: _sourceConnectionId,
      token: Uint8List(0),
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keys: space.keys.clientLatest!,
      frames: [ackFrame],
    );
    space.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: false,
      inFlight: false,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
    ));
    final datagram = type == LongPacketType.initial
        ? _padDatagramTo(built.bytes, kMinimumInitialDatagramSize)
        : built.bytes;
    _sendDatagram(datagram);
  }

  Future<void> _maybeSendShortHeaderAck() async {
    if (!_oneRttSpace.keys.hasKeys) return;
    final ackFrame = _oneRttSpace.received.buildAckFrame(0);
    if (ackFrame == null) return;
    // Piggyback pending flow-control window updates (MAX_DATA /
    // MAX_STREAM_DATA) onto this ACK rather than sending them as their
    // own packets -- window updates are needed exactly when data is
    // arriving, which is exactly when an ACK is being sent anyway.
    final frames = <Frame>[ackFrame];
    frames.addAll(_takePendingFlowControlFrames());
    final packetNumber = _oneRttSpace.allocatePacketNumber();
    final pnLength = packetNumberEncodingLength(
        packetNumber, _oneRttSpace.largestAckedPacket);
    final built = await buildShortHeaderPacket(
      destinationConnectionId: _destinationConnectionId,
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keyPhase: _oneRttSendEra().keyPhase,
      keys: _oneRttSendEra().keys,
      frames: frames,
    );
    _oneRttSpace.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      // Only pure ACK/PADDING packets are non-ack-eliciting (RFC 9000
      // §13.2); a piggybacked MAX_DATA/MAX_STREAM_DATA makes this
      // packet ack-eliciting and in-flight.
      ackEliciting: frames.any((f) => f is! AckFrame),
      inFlight: frames.any((f) => f is! AckFrame),
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
    ));
    _sendDatagram(built.bytes);
  }

  Future<void> _processFrames(
    List<Frame> frames, {
    required EncryptionLevel level,
    required PacketNumberSpace space,
  }) async {
    final acknowledgedPns = <int>[];
    // The last ACK frame's delay field, decoded from the wire in the
    // peer's units. RFC 9000 §18.2: ack_delay_exponent applies ONLY to
    // packets in the application-data (1-RTT) space -- ACK frames sent
    // in Initial/Handshake packets always use the default exponent 3.
    final ackDelayShift =
        level == EncryptionLevel.oneRtt ? _ackDelayExponentShift : 1 << 3;
    var latestAckDelayMicros = 0;
    for (final frame in frames) {
      if (frame is CryptoFrame) {
        await _handshake.feedCryptoData(level, frame.offset, frame.data);
      } else if (frame is AckFrame) {
        acknowledgedPns.addAll(frame.acknowledgedPacketNumbers());
        latestAckDelayMicros = frame.ackDelay * ackDelayShift;
      } else if (frame is StreamFrame) {
        _onStreamBytesReceived(frame);
        // Frames for any stream other than our single bidi stream 0
        // (a server-initiated stream we never opened) must not
        // corrupt stream 0's reassembly -- drop them for this
        // scope (DESIGN.md: exactly one stream, ever).
        if (frame.streamId == QuicStream.clientBidiStreamId0) {
          _stream?._handleFrame(frame);
        }
      } else if (frame is MaxDataFrame) {
        _connectionSendAllowance = frame.maximumData - _connectionBytesSent;
      } else if (frame is MaxStreamDataFrame) {
        if (frame.streamId == QuicStream.clientBidiStreamId0) {
          _streamSendAllowance = frame.maximumStreamData - _streamBytesSent;
        }
      } else if (frame is ConnectionCloseFrame) {
        QuicDiagnostics.report(
            'peer closed connection: errorCode=${frame.errorCode} '
            '${frame.isApplicationError ? '(application)' : '(transport)'}'
            '${frame.reasonPhrase.isEmpty ? '' : ' reason="${frame.reasonPhrase}"'}');
        unawaited(_closeInternal());
        return;
      }
      // PADDING/PING/HANDSHAKE_DONE and the remaining decode-only
      // frames (BLOCKED/MAX_STREAMS variants etc.) need no action per
      // DESIGN.md's scope -- they're accepted (so decoding never
      // breaks) but not acted on.
    }

    if (acknowledgedPns.isNotEmpty) {
      final result = space.lossDetector.onAckReceived(
        acknowledgedPacketNumbers: acknowledgedPns,
        ackDelay: Duration(microseconds: latestAckDelayMicros),
        handshakeConfirmed: _handshake.isComplete,
        maxAckDelay: _serverMaxAckDelay,
        now: DateTime.now(),
      );
      for (final acked in result.newlyAcked) {
        _congestion.onPacketAcked(acked);
      }
      if (result.newlyLost.isNotEmpty) {
        _congestion.onPacketsLost(
            result.newlyLost.map((l) => l.packet).toList(), DateTime.now());
        await _retransmitLostPackets(result.newlyLost, space: space);
      }
    }

    if (level != EncryptionLevel.oneRtt) {
      await _maybeInstallLaterKeys();
      await _flushHandshakeOutbound();
    }
    if (_handshake.isComplete && !_handshakeCompleteController.isClosed) {
      if (!_oneRttSpace.keys.hasKeys) {
        await _oneRttSpace.installKeys(_handshake.applicationTrafficSecrets);
        _stream = QuicStream._(this);
        _initSendAllowances();
      }
      _handshakeCompleteController.add(null);
    }
    // The peer's MAX_DATA/MAX_STREAM_DATA frames (processed above) may
    // have just unblocked queued writes.
    if (_pendingSends.isNotEmpty) {
      await _flushPendingSends();
    }
    _rearmLossDetectionTimer();
  }

  /// RFC 9000 §13.3: retransmits the CRYPTO/STREAM frames a
  /// now-declared-lost packet carried, in a *new* packet with a new
  /// packet number (lost packet numbers are never reused). Bare
  /// ACK/PING-only packets ([SentPacket.retransmittableFrames] null)
  /// need no action here -- losing an ACK is harmless (the next ACK
  /// covers the same ground), and losing a keepalive PING is handled
  /// by the PTO timer naturally sending another ack-eliciting packet
  /// if the connection is otherwise idle.
  Future<void> _retransmitLostPackets(
    List<LostPacket> lostPackets, {
    required PacketNumberSpace space,
  }) async {
    for (final lost in lostPackets) {
      final frames = lost.packet.retransmittableFrames;
      if (frames == null || frames.isEmpty) continue;
      for (final frame in frames) {
        if (frame is CryptoFrame) {
          await _retransmitCryptoFrame(frame, space: space);
        } else if (frame is StreamFrame) {
          await _retransmitStreamFrame(frame);
        }
        // Other frame types are never placed in
        // retransmittableFrames by this connection's own send paths
        // (see the SentPacket construction sites) -- nothing else to
        // handle here.
      }
    }
  }

  Future<void> _retransmitCryptoFrame(
    CryptoFrame frame, {
    required PacketNumberSpace space,
  }) async {
    if (!space.keys.hasKeys) return; // keys already discarded; nothing to do
    final type = identical(space, _initialSpace)
        ? LongPacketType.initial
        : LongPacketType.handshake;
    final packetNumber = space.allocatePacketNumber();
    final pnLength =
        packetNumberEncodingLength(packetNumber, space.largestAckedPacket);
    final built = await buildLongHeaderPacket(
      type: type,
      version: quicVersion1,
      destinationConnectionId: _destinationConnectionId,
      sourceConnectionId: _sourceConnectionId,
      token: Uint8List(0),
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keys: space.keys.clientLatest!,
      frames: [frame],
    );
    space.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
      retransmittableFrames: [frame],
    ));
    _congestion.onPacketSent(built.bytes.length);
    final datagram = type == LongPacketType.initial
        ? _padDatagramTo(built.bytes, kMinimumInitialDatagramSize)
        : built.bytes;
    _sendDatagram(datagram);
  }

  Future<void> _retransmitStreamFrame(StreamFrame frame) async {
    if (!_oneRttSpace.keys.hasKeys) return;
    final packetNumber = _oneRttSpace.allocatePacketNumber();
    final pnLength = packetNumberEncodingLength(
        packetNumber, _oneRttSpace.largestAckedPacket);
    final built = await buildShortHeaderPacket(
      destinationConnectionId: _destinationConnectionId,
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keyPhase: _oneRttSendEra().keyPhase,
      keys: _oneRttSendEra().keys,
      frames: [frame],
    );
    _oneRttSpace.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
      retransmittableFrames: [frame],
    ));
    _congestion.onPacketSent(built.bytes.length);
    _sendDatagram(built.bytes);
  }

  Future<void> _maybeInstallLaterKeys() async {
    if (!_handshakeSpace.keys.hasKeys) {
      try {
        final secrets = _handshake.handshakeTrafficSecrets;
        await _handshakeSpace.installKeys(secrets);
        // RFC 9001 §4.9.1: client discards Initial keys once it first
        // sends a Handshake packet -- approximated here as "once
        // Handshake keys are installed and about to be used," since
        // this client's very next action is to flush Handshake-level
        // CRYPTO data.
        _initialSpace.discard();
      } on HandshakeException {
        // ServerHello not processed yet -- handshake secrets aren't
        // available. Not an error; try again next time frames arrive.
      }
    }
  }

  Future<void> _flushHandshakeOutbound() async {
    final initialBytes = _handshake.pendingOutbound(EncryptionLevel.initial);
    if (initialBytes.isNotEmpty && _initialSpace.keys.hasKeys) {
      await _sendCryptoPackets(
        space: _initialSpace,
        type: LongPacketType.initial,
        data: initialBytes,
      );
    }
    final handshakeBytes =
        _handshake.pendingOutbound(EncryptionLevel.handshake);
    if (handshakeBytes.isNotEmpty && _handshakeSpace.keys.hasKeys) {
      await _sendCryptoPackets(
        space: _handshakeSpace,
        type: LongPacketType.handshake,
        data: handshakeBytes,
      );
    }

    if (_handshake.isComplete && !_oneRttSpace.keys.hasKeys) {
      await _oneRttSpace.installKeys(_handshake.applicationTrafficSecrets);
      // RFC 9001 §4.9.2: discard Handshake keys once the handshake is
      // confirmed.
      _handshakeSpace.discard();
      _stream = QuicStream._(this);
      _initSendAllowances();
    }
  }

  Future<void> _sendCryptoPackets({
    required PacketNumberSpace space,
    required LongPacketType type,
    required Uint8List data,
  }) async {
    final offset = _cryptoSendOffsets[type] ?? 0;
    final frame = CryptoFrame(offset: offset, data: data);
    _cryptoSendOffsets[type] = offset + data.length;

    final packetNumber = space.allocatePacketNumber();
    final pnLength =
        packetNumberEncodingLength(packetNumber, space.largestAckedPacket);

    final built = await buildLongHeaderPacket(
      type: type,
      version: quicVersion1,
      destinationConnectionId: _destinationConnectionId,
      sourceConnectionId: _sourceConnectionId,
      token: Uint8List(0),
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keys: space.keys.clientLatest!,
      frames: [frame],
    );

    space.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
      retransmittableFrames: [frame],
    ));
    _congestion.onPacketSent(built.bytes.length);

    final datagram = type == LongPacketType.initial
        ? _padDatagramTo(built.bytes, kMinimumInitialDatagramSize)
        : built.bytes;
    _sendDatagram(datagram);
  }

  final Map<LongPacketType, int> _cryptoSendOffsets = {};

  /// RFC 9000 §14.1: a client MUST expand every UDP datagram carrying
  /// an Initial packet to at least 1200 bytes -- a real quic-go server
  /// silently discards anything smaller (verified against a live
  /// server/quic_visitor.go-equivalent instance; see
  /// test/integration/quic_go_interop_test.dart). Trailing zero bytes
  /// after a complete, self-delimited (via its own Length field) QUIC
  /// packet are simply ignored by the receiver -- RFC 9000 §12.2 notes
  /// "Initial packets can even be coalesced with invalid packets, which
  /// a receiver will discard."
  static Uint8List _padDatagramTo(Uint8List packetBytes, int minSize) {
    if (packetBytes.length >= minSize) return packetBytes;
    final padded = Uint8List(minSize)
      ..setRange(0, packetBytes.length, packetBytes);
    return padded;
  }

  Future<void> _sendStreamData(Uint8List data) async {
    if (!_oneRttSpace.keys.hasKeys) {
      throw const ConnectionException(
          'cannot send stream data before the handshake completes');
    }
    // Send-side flow control (RFC 9000 §4.1): exceeding the peer's
    // advertised connection/stream offsets is a connection error
    // (FLOW_CONTROL_ERROR), not something to paper over. Writes that
    // don't fit the current allowance queue until the peer's
    // MAX_DATA/MAX_STREAM_DATA opens the window (handled in
    // _processFrames, which flushes via _flushPendingSends).
    _pendingSends.add(data);
    await _flushPendingSends();
  }

  /// Initial send allowances from the server's transport parameters.
  /// Called once the handshake completes (the parameters live in the
  /// server's EncryptedExtensions, parsed by ClientHandshake). Safe to
  /// call from both completion sites (see _processFrames and
  /// _flushHandshakeOutbound -- whichever runs first creates the stream
  /// and the other skips its install block).
  ///
  /// A server that omitted the extension entirely (non-conforming, but
  /// tolerated -- see ClientHandshake._parseEncryptedExtensions) leaves
  /// the allowances unlimited rather than zero: deadlocking all sends
  /// forever would be strictly worse than the pre-flow-control
  /// behavior of trusting the peer's reader to keep up.
  bool _sendAllowancesInitialized = false;
  void _initSendAllowances() {
    if (_sendAllowancesInitialized) return;
    _sendAllowancesInitialized = true;
    final server = _handshake.serverTransportParameters;
    if (server == null) {
      _connectionSendAllowance = 0x3FFFFFFFFFFFFFFF;
      _streamSendAllowance = 0x3FFFFFFFFFFFFFFF;
      return;
    }
    _connectionSendAllowance = server.initialMaxData;
    // For a client-initiated bidi stream, the limit that applies to
    // OUR sends is the server's initial_max_stream_data_bidi_remote
    // (how much the REMOTE endpoint allows on streams it didn't
    // initiate) -- RFC 9000 §18.2's table.
    _streamSendAllowance = server.initialMaxStreamDataBidiRemote;
    // RTT accounting inputs (RFC 9000 §18.2): the peer's ACK delay
    // scaling and its declared max ACK delay.
    _ackDelayExponentShift = 1 << server.ackDelayExponent;
    if (server.maxAckDelay > 0) {
      _serverMaxAckDelay = Duration(milliseconds: server.maxAckDelay);
    }
    _validateServerInitialSourceConnectionId(server);
  }

  /// An ACK frame's delay field on the wire carries the peer's ACK
  /// delay in microseconds DIVIDED by 2^ack_delay_exponent (RFC 9000
  /// §19.3); decoding multiplies it back. Default exponent 3 when the
  /// server didn't advertise one.
  int _ackDelayExponentShift = 1 << 3;
  Duration _serverMaxAckDelay = const Duration(milliseconds: 25);

  /// RFC 9001 §8.2: the client MUST verify that the
  /// initial_source_connection_id in the server's transport parameters
  /// equals the Source Connection ID from the first Initial packet it
  /// received from the server -- this binds the handshake (and thus
  /// the negotiated keys) to the actual observed peer, defeating
  /// connection-confusion/reflection attacks. A mismatch is a protocol
  /// violation and tears the connection down.
  void _validateServerInitialSourceConnectionId(TransportParameters server) {
    final expected = _serverFirstInitialScid;
    final claimed = server.initialSourceConnectionId;
    // RFC 9000 §7.3: the server MUST send initial_source_connection_id;
    // its absence is a TRANSPORT_PARAMETER_ERROR. Surfaced through the
    // handshake-complete stream (not a throw, which the packet
    // processing chain would swallow) so connect() fails with the
    // specific cause instead of a generic handshake timeout.
    if (expected == null) return; // never saw a server Initial packet
    if (claimed == null) {
      unawaited(_closeInternal());
      _handshakeCompleteController.addError(const ConnectionException(
          'server transport parameters omitted '
          'initial_source_connection_id (RFC 9000 §7.3)'));
      return;
    }
    if (!_bytesEqual(expected, claimed)) {
      unawaited(_closeInternal());
      _handshakeCompleteController.addError(ConnectionException(
          'server transport parameters initial_source_connection_id '
          'mismatch: claimed ${claimed.length} bytes, observed '
          '${expected.length} bytes -- possible connection confusion'));
    }
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// Sends as many queued stream chunks as the current flow-control
  /// allowances, congestion window, and leave queued. Each chunk reuses
  /// the stream's _sendOffset bookkeeping via _sendStreamChunk, which
  /// advances it. Flushes are re-triggered whenever an ACK grows the
  /// congestion window or a MAX_DATA frame grows the flow-control
  /// allowance (both from _processFrames), and by PTO probes if
  /// everything in flight was lost (probes themselves bypass this gate
  /// per RFC 9002 §6.2/A.9, so the loop can never wedge).
  ///
  /// Single-flight: only one loop may run at a time. canSend() reads
  /// bytesInFlight synchronously, but the in-flight counter only grows
  /// after _sendStreamChunk's packet-build await -- without this guard
  /// two interleaved flush loops both pass the gate and overshoot the
  /// congestion window (same TOCTOU family as the _sendOffset race).
  /// Re-entrant calls return immediately; the running loop re-reads
  /// the gates each iteration, so no wakeup is lost.
  bool _flushPendingSendsInFlight = false;
  Future<void> _flushPendingSends() async {
    if (_flushPendingSendsInFlight) return;
    _flushPendingSendsInFlight = true;
    try {
      while (_pendingSends.isNotEmpty) {
        final next = _pendingSends.first;
        if (_connectionSendAllowance < next.length ||
            _streamSendAllowance < next.length) {
          return; // flow-control window exhausted; retry on MAX_DATA
        }
        if (!_congestion.canSend(next.length + 64)) {
          return; // congestion window exhausted; retry on next ACK/PTO
        }
        _pendingSends.removeAt(0);
        await _sendStreamChunk(next);
      }
    } finally {
      _flushPendingSendsInFlight = false;
    }
  }

  Future<void> _sendStreamChunk(Uint8List data) async {
    final stream = _stream;
    if (stream == null) {
      throw const ConnectionException(
          'cannot send stream data before the handshake completes');
    }
    // Read AND advance all bookkeeping synchronously, before the
    // packet-build await below: two flush loops (the app's write()
    // path and _processFrames' flush on an incoming MAX_DATA) can
    // interleave at that await, and advancing after it let both read
    // the SAME _sendOffset -- two STREAM frames with identical offsets,
    // i.e. silent stream-data corruption on the peer.
    final offset = stream._sendOffset;
    stream._sendOffset = offset + data.length;
    _connectionBytesSent += data.length;
    _streamBytesSent += data.length;
    _connectionSendAllowance -= data.length;
    _streamSendAllowance -= data.length;
    final frame = StreamFrame(
        streamId: QuicStream.clientBidiStreamId0, offset: offset, data: data);
    final packetNumber = _oneRttSpace.allocatePacketNumber();
    final pnLength = packetNumberEncodingLength(
        packetNumber, _oneRttSpace.largestAckedPacket);

    final built = await buildShortHeaderPacket(
      destinationConnectionId: _destinationConnectionId,
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keyPhase: _oneRttSendEra().keyPhase,
      keys: _oneRttSendEra().keys,
      frames: [frame],
    );

    _oneRttSpace.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
      retransmittableFrames: [frame],
    ));
    _congestion.onPacketSent(built.bytes.length);

    _sendDatagram(built.bytes);
    _rearmLossDetectionTimer();
  }

  /// Receive-side flow control accounting for one received STREAM
  /// frame (RFC 9000 §4.2: a receiver MUST NOT let the peer exceed the
  /// limits it advertised, and SHOULD send MAX_DATA/MAX_STREAM_DATA to
  /// keep the window open as data is consumed). Policy: when half the
  /// current limit has been consumed, double it (bounded growth) and
  /// queue window-update frames for the next outbound packet.
  void _onStreamBytesReceived(StreamFrame frame) {
    _connectionBytesReceived += frame.data.length;
    final end = frame.offset + frame.data.length;
    if (end > _maxStreamEndOffset) _maxStreamEndOffset = end;

    var updateNeeded = false;
    if (_connectionBytesReceived >= _connectionReceiveLimit ~/ 2) {
      _connectionReceiveLimit = _connectionBytesReceived + 10 * 1024 * 1024;
      _pendingFlowControlFrames
          .add(MaxDataFrame(maximumData: _connectionReceiveLimit));
      updateNeeded = true;
    }
    if (_maxStreamEndOffset >= _streamReceiveLimit ~/ 2) {
      _streamReceiveLimit = _maxStreamEndOffset + 10 * 1024 * 1024;
      _pendingFlowControlFrames.add(MaxStreamDataFrame(
          streamId: QuicStream.clientBidiStreamId0,
          maximumStreamData: _streamReceiveLimit));
      updateNeeded = true;
    }
    // A window update with no ACK in flight (the peer is blocked, so
    // it has stopped sending, so no new ACK is imminent) still needs
    // to go out -- send a packet now rather than waiting for the next
    // piggyback opportunity that may never come.
    if (updateNeeded && _pendingFlowControlFrames.isNotEmpty) {
      unawaited(_sendFlowControlUpdate());
    }
  }

  /// Sends any queued window-update frames as their own packet.
  Future<void> _sendFlowControlUpdate() async {
    if (!_oneRttSpace.keys.hasKeys) return;
    final frames = _takePendingFlowControlFrames();
    if (frames.isEmpty) return;
    final packetNumber = _oneRttSpace.allocatePacketNumber();
    final pnLength = packetNumberEncodingLength(
        packetNumber, _oneRttSpace.largestAckedPacket);
    final built = await buildShortHeaderPacket(
      destinationConnectionId: _destinationConnectionId,
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keyPhase: _oneRttSendEra().keyPhase,
      keys: _oneRttSendEra().keys,
      frames: frames,
    );
    _oneRttSpace.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
    ));
    _congestion.onPacketSent(built.bytes.length);
    _sendDatagram(built.bytes);
    _rearmLossDetectionTimer();
  }

  List<Frame> _takePendingFlowControlFrames() {
    if (_pendingFlowControlFrames.isEmpty) return const [];
    final frames = List<Frame>.from(_pendingFlowControlFrames);
    _pendingFlowControlFrames.clear();
    return frames;
  }

  void _sendDatagram(Uint8List bytes) {
    final socket = _socket;
    final address = _remoteAddress;
    final port = _remotePort;
    if (socket == null || address == null || port == null) {
      throw const ConnectionException('socket not open');
    }
    socket.send(bytes, address, port);
  }

  /// The single bidirectional stream, once the handshake has completed.
  QuicStream get stream {
    final s = _stream;
    if (s == null) {
      throw const ConnectionException(
          'stream is not available before the handshake completes');
    }
    return s;
  }

  void _startPingTimer() {
    // DESIGN.md's keepalive requirement: send a PING periodically to
    // hold the connection open against the peer's idle timeout
    // (matches agents/quic_conn.go and server/quic_visitor.go's shared
    // 10s KeepAlivePeriod).
    _pingTimer = Timer.periodic(
        const Duration(seconds: 10), (_) => unawaited(_sendPing()));
  }

  Future<void> _sendPing() async {
    if (state != ConnectionState.connected || !_oneRttSpace.keys.hasKeys) {
      return;
    }
    final packetNumber = _oneRttSpace.allocatePacketNumber();
    final pnLength = packetNumberEncodingLength(
        packetNumber, _oneRttSpace.largestAckedPacket);
    final built = await buildShortHeaderPacket(
      destinationConnectionId: _destinationConnectionId,
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keyPhase: _oneRttSendEra().keyPhase,
      keys: _oneRttSendEra().keys,
      frames: const [PingFrame()],
    );
    _oneRttSpace.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
    ));
    _congestion.onPacketSent(built.bytes.length);
    _sendDatagram(built.bytes);
    _rearmLossDetectionTimer();
  }

  /// RFC 9000 §10.1: closes the connection locally (no CONNECTION_CLOSE
  /// is sent -- the peer has, by definition, been unreachable for the
  /// whole idle timeout, so there is no one to send it to) once no
  /// packet has been received from the peer for [_maxIdleTimeout].
  /// Re-armed after every received packet and after every ack-eliciting
  /// send that follows a receive (RFC 9000 §10.1's "restarts its idle
  /// timer when sending an ack-eliciting packet if no other ack-
  /// eliciting packets have been sent since last receiving" — approximated
  /// here by simply re-arming on every receipt, which is simpler and
  /// only makes the timeout slightly more generous, never less).
  void _startIdleTimeoutTimer() {
    _idleTimeoutTimer?.cancel();
    _idleTimeoutTimer = Timer(_maxIdleTimeout, _onIdleTimeout);
  }

  void _onIdleTimeout() {
    final sinceLastPacket = DateTime.now().difference(_lastPacketReceivedAt);
    if (sinceLastPacket < _maxIdleTimeout) {
      // A packet arrived since this timer was scheduled but the timer
      // wasn't re-armed in time (e.g. it fired concurrently with
      // _handleDatagram) -- reschedule for the real remaining time
      // instead of closing prematurely.
      _idleTimeoutTimer =
          Timer(_maxIdleTimeout - sinceLastPacket, _onIdleTimeout);
      return;
    }
    unawaited(_closeInternal());
  }

  /// RFC 9002 §6.2/Appendix A.8-A.9: a single cross-space loss
  /// detection timer, re-armed after every send/receive/loss event.
  /// When it fires with no time-threshold loss pending, it's a PTO:
  /// send a probe (PING, since dart_quic has no queued-but-unsent data
  /// concept beyond what's already been sent -- see DESIGN.md's scope)
  /// in whichever space most urgently needs one.
  void _rearmLossDetectionTimer() {
    _lossDetectionTimer?.cancel();
    if (state == ConnectionState.closed) return;

    final spaces = [_initialSpace, _handshakeSpace, _oneRttSpace];
    DateTime? earliestLossTime;
    for (final space in spaces) {
      final lt = space.lossDetector.lossTime;
      if (lt != null &&
          (earliestLossTime == null || lt.isBefore(earliestLossTime))) {
        earliestLossTime = lt;
      }
    }
    if (earliestLossTime != null) {
      final delay = earliestLossTime.difference(DateTime.now());
      _lossDetectionTimer = Timer(
          delay.isNegative ? Duration.zero : delay, _onLossDetectionTimeout);
      return;
    }

    // No time-threshold loss pending -- schedule the earliest PTO
    // across the spaces that currently have anything ack-eliciting in
    // flight (1-RTT's PTO is intentionally not armed until the
    // handshake is confirmed, matching RFC 9000 §6.2.1's "MUST NOT set
    // its PTO timer for the Application Data packet number space until
    // the handshake is confirmed").
    const zeroAckDelay = Duration.zero;
    const oneRttMaxAckDelay = Duration(milliseconds: 25);
    DateTime? earliestPto;
    for (final space in [_initialSpace, _handshakeSpace]) {
      final pto = space.lossDetector.ptoDeadline(zeroAckDelay);
      if (pto != null && (earliestPto == null || pto.isBefore(earliestPto))) {
        earliestPto = pto;
      }
    }
    if (_handshake.isComplete) {
      final pto = _oneRttSpace.lossDetector.ptoDeadline(oneRttMaxAckDelay);
      if (pto != null && (earliestPto == null || pto.isBefore(earliestPto))) {
        earliestPto = pto;
      }
    }
    if (earliestPto == null) return; // nothing in flight anywhere
    final delay = earliestPto.difference(DateTime.now());
    _lossDetectionTimer = Timer(
        delay.isNegative ? Duration.zero : delay, _onLossDetectionTimeout);
  }

  void _onLossDetectionTimeout() {
    unawaited(_handleLossDetectionTimeout());
  }

  Future<void> _handleLossDetectionTimeout() async {
    final now = DateTime.now();
    for (final space in [_initialSpace, _handshakeSpace, _oneRttSpace]) {
      if (space.lossDetector.lossTime != null &&
          !space.lossDetector.lossTime!.isAfter(now)) {
        final lost = space.lossDetector.detectLossOnTimeout(now);
        if (lost.isNotEmpty) {
          _congestion.onPacketsLost(lost.map((l) => l.packet).toList(), now);
          await _retransmitLostPackets(lost, space: space);
        }
        _rearmLossDetectionTimer();
        return;
      }
    }

    // No time-threshold loss was pending -- this is a PTO firing.
    // Send a probe: PING in the space whose PTO is earliest / whichever
    // has ack-eliciting data in flight. A bare PING is sufficient (RFC
    // 9002 §6.2: "If neither is available, send a single PING frame").
    await _sendProbe();
    for (final space in [_initialSpace, _handshakeSpace, _oneRttSpace]) {
      if (space.lossDetector.hasAckElicitingInFlight) {
        space.lossDetector.onPtoFired(now);
      }
    }
    _rearmLossDetectionTimer();
  }

  Future<void> _sendProbe() async {
    if (_initialSpace.keys.hasKeys &&
        _initialSpace.lossDetector.hasAckElicitingInFlight) {
      await _sendPingInLongHeaderSpace(_initialSpace, LongPacketType.initial);
      return;
    }
    if (_handshakeSpace.keys.hasKeys &&
        _handshakeSpace.lossDetector.hasAckElicitingInFlight) {
      await _sendPingInLongHeaderSpace(
          _handshakeSpace, LongPacketType.handshake);
      return;
    }
    if (_handshake.isComplete && _oneRttSpace.keys.hasKeys) {
      await _sendPing();
    }
  }

  /// RFC 9002 §6.2's PTO probe for the Initial/Handshake spaces: a bare
  /// PING frame (not a CRYPTO retransmission -- the lost CRYPTO data,
  /// if any, is retransmitted separately by [_retransmitLostPackets]
  /// once loss is actually detected; this probe's only job is to
  /// elicit an ACK so that detection can happen at all on a link that
  /// dropped every packet in a flight).
  Future<void> _sendPingInLongHeaderSpace(
      PacketNumberSpace space, LongPacketType type) async {
    final packetNumber = space.allocatePacketNumber();
    final pnLength =
        packetNumberEncodingLength(packetNumber, space.largestAckedPacket);
    final built = await buildLongHeaderPacket(
      type: type,
      version: quicVersion1,
      destinationConnectionId: _destinationConnectionId,
      sourceConnectionId: _sourceConnectionId,
      token: Uint8List(0),
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keys: space.keys.clientLatest!,
      frames: const [PingFrame()],
    );
    space.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
    ));
    _congestion.onPacketSent(built.bytes.length);
    final datagram = type == LongPacketType.initial
        ? _padDatagramTo(built.bytes, kMinimumInitialDatagramSize)
        : built.bytes;
    _sendDatagram(datagram);
  }

  Future<void> _closeInternal() async {
    if (state == ConnectionState.closed) return;
    _pingTimer?.cancel();
    _idleTimeoutTimer?.cancel();
    _lossDetectionTimer?.cancel();
    state = ConnectionState.closed;
    await _stream?.close();
    _socket?.close();
    if (!_connectionClosedController.isClosed) {
      _connectionClosedController.add(null);
      await _connectionClosedController.close();
    }
  }

  Future<void> close() async {
    await _closeInternal();
    if (!_handshakeCompleteController.isClosed) {
      await _handshakeCompleteController.close();
    }
  }
}
