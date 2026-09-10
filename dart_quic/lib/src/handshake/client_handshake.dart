/// Drives dart_quic's TLS 1.3 client handshake end to end, including
/// mTLS client authentication -- the core of milestone 3. This class is
/// transport-agnostic: it only knows about CRYPTO-stream bytes per
/// encryption level (RFC 9001 §4: TLS handshake messages map onto
/// QUIC's Initial/Handshake/1-RTT encryption levels), never touching
/// UDP sockets or QUIC packet framing directly -- that's
/// connection.dart's job (a later milestone), which feeds this class
/// decrypted CRYPTO frame payloads and reads [pendingOutbound] to know
/// what to send back at each level.
///
/// Scope (see DESIGN.md): client role only, X25519 only, one
/// (EC)DHE key share (no HelloRetryRequest support -- treated as a
/// fatal error since a real quic-go server accepting X25519 has no
/// reason to send one), mTLS with exactly one client certificate chain,
/// no 0-RTT, no session resumption, no post-handshake auth.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart' as pc;

import '../tls/certificate_message.dart';
import '../tls/certificate_request.dart';
import '../tls/certificate_verify_signature.dart';
import '../tls/client_hello.dart';
import '../tls/extensions.dart';
import '../tls/finished.dart';
import '../tls/handshake_message.dart';
import '../tls/key_schedule.dart';
import '../tls/server_hello.dart';
import '../tls/transcript.dart';
import '../tls/transport_parameters.dart';

enum EncryptionLevel { initial, handshake, oneRtt }

/// Reassembles one encryption level's CRYPTO stream from
/// possibly-out-of-order, possibly-overlapping/duplicate chunks (see
/// [ClientHandshake._reassembly]'s doc comment for why duplicates are
/// expected in practice, not just a theoretical edge case).
class _ReassemblyState {
  /// The contiguous stream bytes received so far, from offset 0.
  Uint8List received = Uint8List(0);

  /// Out-of-order chunks waiting for the gap before them to close,
  /// keyed by their stream start offset.
  final Map<int, Uint8List> _pending = {};

  /// How many bytes of [received] have already been consumed into
  /// decoded handshake messages -- tracked here (rather than trimming
  /// [received] itself) so a handshake message split across chunk
  /// boundaries never needs its already-decoded prefix re-parsed.
  int consumedLength = 0;

  void addChunk(int offset, Uint8List data) {
    if (offset + data.length <= received.length) {
      return; // fully-duplicate retransmission of bytes already merged
    }
    if (offset > received.length) {
      _pending[offset] = data; // gap before this chunk -- hold it
      return;
    }
    _mergeChunk(offset, data);
    _drainPending();
  }

  void _mergeChunk(int offset, Uint8List data) {
    final newPartStart = received.length - offset;
    final newBytes = data.sublist(newPartStart);
    final merged = Uint8List(received.length + newBytes.length)
      ..setRange(0, received.length, received)
      ..setRange(received.length, received.length + newBytes.length, newBytes);
    received = merged;
  }

  void _drainPending() {
    while (true) {
      final nextOffset = _pending.keys
          .where((o) => o <= received.length)
          .fold<int?>(null, (best, o) => best == null || o < best ? o : best);
      if (nextOffset == null) return;
      final data = _pending.remove(nextOffset)!;
      if (nextOffset + data.length <= received.length) continue; // stale
      _mergeChunk(nextOffset, data);
    }
  }
}

class HandshakeException implements Exception {
  final String message;
  const HandshakeException(this.message);

  @override
  String toString() => 'HandshakeException: $message';
}

enum _HandshakeState {
  notStarted,
  sentClientHello,
  receivedServerHello,
  receivedServerFlight, // EncryptedExtensions..Finished all processed
  complete,
}

/// The client's certificate identity for mTLS -- exactly one leaf cert
/// (plus optional chain) and the matching private key. dart_quic
/// supports EC (P-256) and RSA private keys, matching
/// [certificate_verify_signature.dart]'s signing support.
class ClientIdentity {
  final List<Uint8List> certificateChainDer; // leaf first
  final pc.PrivateKey privateKey; // pc.ECPrivateKey or pc.RSAPrivateKey
  final int signatureScheme; // SignatureScheme.* matching privateKey's type

  const ClientIdentity({
    required this.certificateChainDer,
    required this.privateKey,
    required this.signatureScheme,
  });
}

/// Traffic keys plus the raw secret they were derived from -- callers
/// (connection.dart) need the derived AEAD key/iv/hp (via
/// [key_schedule.dart]'s `deriveTrafficKeys`, not duplicated here) but
/// the driver only needs to hand back secrets; deriving the actual
/// per-direction [TrafficKeys] is the connection layer's job since it
/// alone knows the negotiated cipher suite's AEAD key length.
class HandshakeSecretsSnapshot {
  final Uint8List clientSecret;
  final Uint8List serverSecret;
  const HandshakeSecretsSnapshot(
      {required this.clientSecret, required this.serverSecret});
}

class ClientHandshake {
  final SimpleKeyPair _x25519KeyPair;
  final Uint8List x25519PublicKey;
  final Uint8List clientRandom;
  final TransportParameters clientTransportParameters;
  final String? serverName;
  final ClientIdentity? clientIdentity;

  /// Called once the server's Certificate message is parsed, before
  /// CertificateVerify is checked, so the caller can validate the chain
  /// against its trusted CA roots (chain-of-trust validation is
  /// deliberately not implemented in this library -- see DESIGN.md;
  /// commander already has its own CA-pinned trust model via mTLS, and
  /// duplicating a general X.509 path-validation engine here is out of
  /// scope). Throwing from this callback aborts the handshake.
  final void Function(List<Uint8List> serverCertificateChainDer)?
      onServerCertificateChain;

  final TranscriptHash _transcript = TranscriptHash();
  _HandshakeState _state = _HandshakeState.notStarted;

  /// Per-level CRYPTO stream reassembly. [_ReassemblyState.received]
  /// holds the contiguous stream from offset 0 up to however much has
  /// arrived so far; [_ReassemblyState.pending] holds out-of-order
  /// chunks keyed by their stream offset until the gap before them
  /// closes. quic-go retransmits whole Handshake-level CRYPTO frames
  /// verbatim (observed empirically against a live server -- see
  /// test/integration/quic_go_interop_test.dart) while waiting for an
  /// ACK to release its anti-amplification budget, so overlapping/
  /// fully-duplicate offset ranges must be tolerated, not just
  /// straightforward in-order appends.
  final Map<EncryptionLevel, _ReassemblyState> _reassembly = {
    EncryptionLevel.initial: _ReassemblyState(),
    EncryptionLevel.handshake: _ReassemblyState(),
  };
  final Map<EncryptionLevel, BytesBuilder> _outboundBuffer = {
    EncryptionLevel.initial: BytesBuilder(),
    EncryptionLevel.handshake: BytesBuilder(),
  };

  HandshakeSecrets? _handshakeSecrets;
  ApplicationTrafficSecrets? _applicationSecrets;
  CertificateRequest? _certificateRequest;
  List<CertificateEntry>? _serverCertificateChain;

  ClientHandshake._({
    required SimpleKeyPair x25519KeyPair,
    required this.x25519PublicKey,
    required this.clientRandom,
    required this.clientTransportParameters,
    this.serverName,
    this.clientIdentity,
    this.onServerCertificateChain,
  }) : _x25519KeyPair = x25519KeyPair;

  static Future<ClientHandshake> create({
    required Uint8List clientRandom,
    required TransportParameters clientTransportParameters,
    String? serverName,
    ClientIdentity? clientIdentity,
    void Function(List<Uint8List> serverCertificateChainDer)?
        onServerCertificateChain,
  }) async {
    if (clientRandom.length != 32) {
      throw ArgumentError('clientRandom must be exactly 32 bytes');
    }
    final x25519 = X25519();
    final keyPair = await x25519.newKeyPair();
    final publicKey = await keyPair.extractPublicKey();

    return ClientHandshake._(
      x25519KeyPair: keyPair,
      x25519PublicKey: Uint8List.fromList(publicKey.bytes),
      clientRandom: clientRandom,
      clientTransportParameters: clientTransportParameters,
      serverName: serverName,
      clientIdentity: clientIdentity,
      onServerCertificateChain: onServerCertificateChain,
    );
  }

  bool get isComplete => _state == _HandshakeState.complete;

  /// Builds and queues the ClientHello -- call once, before feeding any
  /// inbound data. The resulting bytes appear in
  /// [pendingOutbound(EncryptionLevel.initial)].
  void start() {
    if (_state != _HandshakeState.notStarted) {
      throw const HandshakeException('start() called more than once');
    }
    final clientHello = buildClientHello(
      random: clientRandom,
      x25519PublicKey: x25519PublicKey,
      quicTransportParameters: clientTransportParameters.encode(),
      serverName: serverName,
    );
    _transcript.addMessage(clientHello);
    _outboundBuffer[EncryptionLevel.initial]!.add(clientHello);
    _state = _HandshakeState.sentClientHello;
  }

  /// Returns and clears the bytes queued to send at [level] since the
  /// last call -- the caller (connection.dart) wraps these in CRYPTO
  /// frames at the corresponding QUIC packet number space.
  Uint8List pendingOutbound(EncryptionLevel level) {
    final buffer = _outboundBuffer[level];
    if (buffer == null) return Uint8List(0);
    final bytes = buffer.toBytes();
    _outboundBuffer[level] = BytesBuilder();
    return bytes;
  }

  /// Feeds newly-received CRYPTO frame payload bytes at [level] --
  /// [offset] and [data] come directly from a received CRYPTO frame
  /// (RFC 9000 §19.6: each encryption level is its own independent
  /// byte stream, addressed by offset within that stream). Frames can
  /// arrive out of order, and quic-go has been observed retransmitting
  /// whole already-delivered frames verbatim while waiting for an ACK
  /// (see test/integration/quic_go_interop_test.dart) -- both cases
  /// are handled by keying reassembly on offset and only ever
  /// processing the contiguous prefix once, rather than assuming
  /// `data` is always new tail bytes to append.
  Future<void> feedCryptoData(
    EncryptionLevel level,
    int offset,
    Uint8List data,
  ) async {
    if (level == EncryptionLevel.oneRtt) {
      // dart_quic's client never expects post-handshake CRYPTO data
      // (no session tickets/NewSessionTicket processing -- see
      // DESIGN.md); silently ignore rather than erroring the whole
      // connection over a NewSessionTicket the client is allowed to
      // just drop.
      return;
    }
    if (data.isEmpty) return;

    final state = _reassembly[level]!;
    state.addChunk(offset, data);
    await _processBufferedMessages(level);
  }

  Future<void> _processBufferedMessages(EncryptionLevel level) async {
    final state = _reassembly[level]!;
    final bytes = state.received;
    var consumedTotal = state.consumedLength;

    while (true) {
      final message = tryDecodeHandshakeMessage(bytes, consumedTotal);
      if (message == null) break;
      await _handleMessage(level, message);
      consumedTotal += message.totalLength;
    }
    state.consumedLength = consumedTotal;
  }

  Future<void> _handleMessage(
      EncryptionLevel level, HandshakeMessage message) async {
    final fullMessageBytes = _reconstructMessageBytes(message);

    switch (message.type) {
      case HandshakeType.serverHello:
        await _handleServerHello(message, fullMessageBytes);
      case HandshakeType.encryptedExtensions:
        _transcript.addMessage(fullMessageBytes);
      // Not otherwise inspected -- ALPN is fixed at the QUIC layer
      // (ALPN="leaf-commander", negotiated outside TLS's own alpn
      // extension per commander's transport design) and this client
      // doesn't act on any other EncryptedExtensions content.
      case HandshakeType.certificateRequest:
        _transcript.addMessage(fullMessageBytes);
        _certificateRequest = CertificateRequest.decodeBody(message.body);
      case HandshakeType.certificate:
        _transcript.addMessage(fullMessageBytes);
        final cert = CertificateMessage.decodeBody(message.body);
        _serverCertificateChain = cert.certificateList;
        onServerCertificateChain
            ?.call(cert.certificateList.map((e) => e.certData).toList());
      case HandshakeType.certificateVerify:
        await _handleCertificateVerify(message);
        _transcript.addMessage(fullMessageBytes);
      case HandshakeType.finished:
        await _handleServerFinished(message);
        _transcript.addMessage(fullMessageBytes);
        // RFC 8446 §7.1: application traffic secrets are derived from
        // the transcript "ClientHello...server Finished" -- i.e.
        // *including* this Finished message, which must be added to
        // the transcript (the line above) before this snapshot, not
        // before it.
        _transcriptHashAtServerFinished = await _transcript.snapshot();
        await _sendClientFlight();
      default:
        throw HandshakeException(
            'unexpected handshake message type ${message.type} at '
            'encryption level $level');
    }
  }

  Uint8List _reconstructMessageBytes(HandshakeMessage message) {
    final sink = BytesBuilder();
    encodeHandshakeMessage(sink, message.type, message.body);
    return sink.toBytes();
  }

  Future<void> _handleServerHello(
      HandshakeMessage message, Uint8List fullMessageBytes) async {
    if (_state != _HandshakeState.sentClientHello) {
      throw const HandshakeException('unexpected second ServerHello');
    }
    final hello = ServerHello.decodeBody(message.body);
    if (hello.isHelloRetryRequest) {
      throw const HandshakeException(
          'HelloRetryRequest is not supported (see DESIGN.md scope)');
    }
    if (hello.selectedVersion != 0x0304) {
      throw HandshakeException('server selected non-TLS-1.3 version 0x'
          '${hello.selectedVersion?.toRadixString(16)}');
    }
    final keyShare = hello.keyShare;
    if (keyShare == null || keyShare.group != NamedGroup.x25519) {
      throw const HandshakeException(
          'server did not select an x25519 key share');
    }

    _transcript.addMessage(fullMessageBytes);

    final sharedSecret = await _computeDheSharedSecret(keyShare.keyExchange);
    final transcriptHash = await _transcript.snapshot();
    final empty = await emptyTranscriptHash();

    _handshakeSecrets = await deriveHandshakeSecrets(
      dheSharedSecret: sharedSecret,
      transcriptHashUpToServerHello: transcriptHash,
      emptyTranscriptHash: empty,
    );
    _state = _HandshakeState.receivedServerHello;
  }

  Future<Uint8List> _computeDheSharedSecret(Uint8List serverPublicKey) async {
    final x25519 = X25519();
    final serverKey =
        SimplePublicKey(serverPublicKey, type: KeyPairType.x25519);
    final shared = await x25519.sharedSecretKey(
        keyPair: _x25519KeyPair, remotePublicKey: serverKey);
    return Uint8List.fromList(await shared.extractBytes());
  }

  Future<void> _handleCertificateVerify(HandshakeMessage message) async {
    final chain = _serverCertificateChain;
    if (chain == null || chain.isEmpty) {
      throw const HandshakeException(
          'CertificateVerify received with no prior Certificate chain');
    }
    final verify = CertificateVerifyMessage.decodeBody(message.body);
    final transcriptHash = await _transcript.snapshot();
    final content = buildCertificateVerifyContent(
      isServer: true,
      transcriptHash: transcriptHash,
    );

    verifyCertificateSignature(
      leafCertificateDer: chain.first.certData,
      algorithm: verify.algorithm,
      signedContent: content,
      signature: verify.signature,
    );
  }

  Future<void> _handleServerFinished(HandshakeMessage message) async {
    final secrets = _handshakeSecrets;
    if (secrets == null) {
      throw const HandshakeException(
          'server Finished received before handshake secrets exist');
    }
    // Finished's verify_data covers the transcript *up to but not
    // including* this Finished message itself (RFC 8446 §4.4.4).
    final transcriptHash = await _transcript.snapshot();
    final expected = await computeFinishedVerifyData(
      handshakeTrafficSecret: secrets.serverHandshakeTrafficSecret,
      transcriptHash: transcriptHash,
    );
    final actual = message.body;
    if (!verifyDataMatches(expected, actual)) {
      throw const HandshakeException(
          'server Finished verify_data does not match -- handshake '
          'integrity check failed');
    }
    _state = _HandshakeState.receivedServerFlight;
  }

  Uint8List? _transcriptHashAtServerFinished;

  Future<void> _sendClientFlight() async {
    final identity = clientIdentity;
    final certRequested = _certificateRequest != null;

    if (certRequested) {
      final certMessage = CertificateMessage(
        certificateRequestContext:
            _certificateRequest!.certificateRequestContext,
        certificateList: identity == null
            ? const []
            : identity.certificateChainDer
                .map((der) => CertificateEntry(certData: der))
                .toList(),
      );
      final certBytes = certMessage.encode();
      _transcript.addMessage(certBytes);
      _outboundBuffer[EncryptionLevel.handshake]!.add(certBytes);

      if (identity != null) {
        final transcriptHash = await _transcript.snapshot();
        final content = buildCertificateVerifyContent(
          isServer: false,
          transcriptHash: transcriptHash,
        );
        final signature = _signWithClientIdentity(identity, content);
        final verifyMessage = CertificateVerifyMessage(
          algorithm: identity.signatureScheme,
          signature: signature,
        ).encode();
        _transcript.addMessage(verifyMessage);
        _outboundBuffer[EncryptionLevel.handshake]!.add(verifyMessage);
      }
    }

    final secrets = _handshakeSecrets!;
    final transcriptHashBeforeFinished = await _transcript.snapshot();
    final verifyData = await computeFinishedVerifyData(
      handshakeTrafficSecret: secrets.clientHandshakeTrafficSecret,
      transcriptHash: transcriptHashBeforeFinished,
    );
    final finishedSink = BytesBuilder();
    encodeHandshakeMessage(finishedSink, HandshakeType.finished, verifyData);
    final finishedBytes = finishedSink.toBytes();
    _transcript.addMessage(finishedBytes);
    _outboundBuffer[EncryptionLevel.handshake]!.add(finishedBytes);

    _applicationSecrets = await deriveApplicationTrafficSecrets(
      masterSecret: secrets.masterSecret,
      transcriptHashUpToServerFinished: _transcriptHashAtServerFinished!,
    );

    _state = _HandshakeState.complete;
  }

  Uint8List _signWithClientIdentity(
      ClientIdentity identity, Uint8List content) {
    final key = identity.privateKey;
    if (key is pc.ECPrivateKey) {
      return signWithEcdsaP256(privateKey: key, content: content);
    }
    if (key is pc.RSAPrivateKey) {
      return signWithRsaPss(privateKey: key, content: content);
    }
    throw HandshakeException(
        'unsupported client private key type ${key.runtimeType}');
  }

  /// The Handshake-level traffic secrets, available once the
  /// ServerHello has been processed (before the full flight completes)
  /// -- the connection layer needs these to switch to Handshake
  /// encryption for decrypting the rest of the server's flight.
  HandshakeSecretsSnapshot get handshakeTrafficSecrets {
    final secrets = _handshakeSecrets;
    if (secrets == null) {
      throw const HandshakeException(
          'handshake traffic secrets requested before ServerHello was '
          'processed');
    }
    return HandshakeSecretsSnapshot(
      clientSecret: secrets.clientHandshakeTrafficSecret,
      serverSecret: secrets.serverHandshakeTrafficSecret,
    );
  }

  /// The 1-RTT (application) traffic secrets, available once
  /// [isComplete] is true.
  HandshakeSecretsSnapshot get applicationTrafficSecrets {
    final secrets = _applicationSecrets;
    if (secrets == null) {
      throw const HandshakeException(
          'application traffic secrets requested before the handshake '
          'completed');
    }
    return HandshakeSecretsSnapshot(
      clientSecret: secrets.clientApplicationTrafficSecret,
      serverSecret: secrets.serverApplicationTrafficSecret,
    );
  }
}
