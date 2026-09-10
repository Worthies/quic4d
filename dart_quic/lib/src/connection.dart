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
import 'packet/header.dart';
import 'packet/initial_secrets.dart';
import 'packet/packet_codec.dart';
import 'packet/packet_number_space.dart';
import 'recovery/congestion_control.dart';
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

enum ConnectionState { connecting, handshaking, connected, closed }

/// A single client-initiated bidirectional stream -- DESIGN.md's entire
/// stream model. Always stream ID 0 (the first client-initiated
/// bidirectional stream ID per RFC 9000 §2.1's numbering scheme).
class QuicStream {
  static const int clientBidiStreamId0 = 0;

  final Connection _connection;
  final StreamController<Uint8List> _incomingController =
      StreamController<Uint8List>.broadcast();
  int _sendOffset = 0;
  int _receiveOffset = 0;
  final Map<int, Uint8List> _outOfOrderReceived = {};

  QuicStream._(this._connection);

  /// Bytes received on this stream, in order, as they arrive --
  /// possibly split across multiple events per STREAM frame rather
  /// than reassembled into an application-level framing (that's
  /// commander's own newline-delimited-JSON layer's job, same as the
  /// existing MTLSClient/QuicClient transports).
  Stream<Uint8List> get incoming => _incomingController.stream;

  Future<void> write(Uint8List data) async {
    if (data.isEmpty) return;
    await _connection._sendStreamData(
      streamId: clientBidiStreamId0,
      offset: _sendOffset,
      data: data,
    );
    _sendOffset += data.length;
  }

  void _handleFrame(StreamFrame frame) {
    if (frame.offset == _receiveOffset) {
      _incomingController.add(frame.data);
      _receiveOffset += frame.data.length;
      _drainOutOfOrder();
    } else if (frame.offset > _receiveOffset) {
      _outOfOrderReceived[frame.offset] = frame.data;
    }
    // frame.offset < _receiveOffset: fully-duplicate retransmission,
    // already delivered -- ignore.
  }

  void _drainOutOfOrder() {
    while (_outOfOrderReceived.containsKey(_receiveOffset)) {
      final data = _outOfOrderReceived.remove(_receiveOffset)!;
      _incomingController.add(data);
      _receiveOffset += data.length;
    }
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

  ConnectionState state = ConnectionState.connecting;
  QuicStream? _stream;
  Timer? _pingTimer;
  final StreamController<void> _handshakeCompleteController =
      StreamController<void>.broadcast();

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
    _initialSpace.keys.client = DirectionalKeys(
      key: initialSecrets.client.key,
      iv: initialSecrets.client.iv,
      hp: initialSecrets.client.hp,
    );
    _initialSpace.keys.server = DirectionalKeys(
      key: initialSecrets.server.key,
      iv: initialSecrets.server.iv,
      hp: initialSecrets.server.hp,
    );

    _handshake.start();
    await _flushHandshakeOutbound();

    final completer = Completer<void>();
    final sub = _handshakeCompleteController.stream.listen((_) {
      if (!completer.isCompleted) completer.complete();
    });
    try {
      await completer.future.timeout(handshakeTimeout);
    } on TimeoutException {
      throw const ConnectionException('handshake timed out');
    } finally {
      await sub.cancel();
    }

    state = ConnectionState.connected;
    _startPingTimer();
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
      _processingChain = _processingChain.then((_) => _handleDatagram(data));
    }
  }

  Future<void> _handleDatagram(Uint8List datagram) async {
    var offset = 0;
    while (offset < datagram.length) {
      final firstByte = datagram[offset];
      final isLongHeader = (firstByte & 0x80) != 0;
      if (isLongHeader) {
        offset = await _handleLongHeaderPacketAt(datagram, offset);
      } else {
        await _handleShortHeaderPacketAt(datagram, offset);
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
      return peek.packetNumberOffset + peek.length;
    }

    final parsed = await openLongHeaderPacket(
      datagram: datagram,
      offset: offset,
      keys: space.keys.server!,
      largestReceivedPn: space.largestReceivedPacketNumber,
    );
    space.largestReceivedPacketNumber =
        space.largestReceivedPacketNumber == null
            ? parsed.packetNumber
            : (space.largestReceivedPacketNumber! > parsed.packetNumber
                ? space.largestReceivedPacketNumber!
                : parsed.packetNumber);

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
    final parsed = await openShortHeaderPacket(
      datagram: datagram,
      offset: offset,
      destinationConnectionIdLength: _sourceConnectionId.length,
      keys: _oneRttSpace.keys.server!,
      largestReceivedPn: _oneRttSpace.largestReceivedPacketNumber,
    );
    _oneRttSpace.largestReceivedPacketNumber =
        _oneRttSpace.largestReceivedPacketNumber == null
            ? parsed.packetNumber
            : (_oneRttSpace.largestReceivedPacketNumber! > parsed.packetNumber
                ? _oneRttSpace.largestReceivedPacketNumber!
                : parsed.packetNumber);

    await _processFrames(
      parsed.frames,
      level: EncryptionLevel.oneRtt,
      space: _oneRttSpace,
    );
    await _maybeSendShortHeaderAck();
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
    final largest = space.largestReceivedPacketNumber;
    if (largest == null) return;
    // firstAckRange=0: acknowledges only the single largest-numbered
    // packet, not a claimed contiguous range down from it -- this
    // library doesn't track every individual received packet number
    // (see DESIGN.md's simplified-loss-recovery scope), so claiming a
    // wider contiguous range risks falsely acknowledging a packet that
    // was actually lost/reordered. During the handshake specifically,
    // quic-go only needs *an* ACK to release anti-amplification
    // budget/stop retransmitting -- it doesn't require every packet
    // number be individually acked -- so this minimal-but-honest range
    // is sufficient.
    final ackFrame = AckFrame(
      largestAcknowledged: largest,
      ackDelay: 0,
      firstAckRange: 0,
    );
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
      keys: space.keys.client!,
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
    final largest = _oneRttSpace.largestReceivedPacketNumber;
    if (largest == null || !_oneRttSpace.keys.hasKeys) return;
    final ackFrame = AckFrame(
      largestAcknowledged: largest,
      ackDelay: 0,
      firstAckRange: 0,
    );
    final packetNumber = _oneRttSpace.allocatePacketNumber();
    final pnLength = packetNumberEncodingLength(
        packetNumber, _oneRttSpace.largestAckedPacket);
    final built = await buildShortHeaderPacket(
      destinationConnectionId: _destinationConnectionId,
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keyPhase: false,
      keys: _oneRttSpace.keys.client!,
      frames: [ackFrame],
    );
    _oneRttSpace.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: false,
      inFlight: false,
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
    for (final frame in frames) {
      if (frame is CryptoFrame) {
        await _handshake.feedCryptoData(level, frame.offset, frame.data);
      } else if (frame is AckFrame) {
        acknowledgedPns.addAll(frame.acknowledgedPacketNumbers());
      } else if (frame is StreamFrame) {
        _stream?._handleFrame(frame);
      } else if (frame is ConnectionCloseFrame) {
        state = ConnectionState.closed;
      }
      // PADDING/PING/HANDSHAKE_DONE and the decode-only frames
      // (flow_control_frames.dart etc.) need no action per DESIGN.md's
      // scope -- they're accepted (so decoding never breaks) but not
      // acted on.
    }

    if (acknowledgedPns.isNotEmpty) {
      final result = space.lossDetector.onAckReceived(
        acknowledgedPacketNumbers: acknowledgedPns,
        ackDelay: Duration.zero,
        handshakeConfirmed: _handshake.isComplete,
        maxAckDelay: const Duration(milliseconds: 25),
        now: DateTime.now(),
      );
      for (final acked in result.newlyAcked) {
        _congestion.onPacketAcked(acked);
      }
      if (result.newlyLost.isNotEmpty) {
        _congestion.onPacketsLost(
            result.newlyLost.map((l) => l.packet).toList(), DateTime.now());
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
      }
      _handshakeCompleteController.add(null);
    }
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
      keys: space.keys.client!,
      frames: [frame],
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

  Future<void> _sendStreamData({
    required int streamId,
    required int offset,
    required Uint8List data,
  }) async {
    if (!_oneRttSpace.keys.hasKeys) {
      throw const ConnectionException(
          'cannot send stream data before the handshake completes');
    }
    final frame = StreamFrame(streamId: streamId, offset: offset, data: data);
    final packetNumber = _oneRttSpace.allocatePacketNumber();
    final pnLength = packetNumberEncodingLength(
        packetNumber, _oneRttSpace.largestAckedPacket);

    final built = await buildShortHeaderPacket(
      destinationConnectionId: _destinationConnectionId,
      packetNumber: packetNumber,
      packetNumberLength: pnLength,
      keyPhase: false,
      keys: _oneRttSpace.keys.client!,
      frames: [frame],
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
      keyPhase: false,
      keys: _oneRttSpace.keys.client!,
      frames: const [PingFrame()],
    );
    _oneRttSpace.lossDetector.onPacketSent(SentPacket(
      packetNumber: packetNumber,
      ackEliciting: true,
      inFlight: true,
      sentBytes: built.bytes.length,
      timeSent: DateTime.now(),
    ));
    _sendDatagram(built.bytes);
  }

  Future<void> close() async {
    _pingTimer?.cancel();
    state = ConnectionState.closed;
    await _stream?.close();
    _socket?.close();
    await _handshakeCompleteController.close();
  }
}
