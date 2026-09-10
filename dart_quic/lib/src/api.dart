/// High-level public API, shaped closely to quic4d's own
/// (QuicEndpoint / QuicConnection / QuicSendStream / QuicRecvStream)
/// so that commander/lib/client/quic_client.dart can switch from the
/// FFI-based quic4d to this pure-Dart implementation with an import
/// change plus adapting call sites, rather than a rewrite.
///
/// Deliberate deviations from quic4d's exact shape (see DESIGN.md for
/// the full scope rationale):
///   - No separate "create endpoint, then connect (possibly more than
///     once) reusing it" split -- quic4d's Endpoint wraps a real Quinn
///     UDP socket that's expensive enough to want to reuse across
///     reconnects; dart_quic's [QuicEndpoint] only holds parsed
///     identity material (CA roots + client cert/key), and each
///     [QuicEndpoint.connect] call opens its own fresh UDP socket via
///     [Connection.connect] (cheap in `dart:io`, and simpler than
///     threading socket reuse through this layer for no measurable
///     benefit at commander's reconnect frequency).
///   - Certificates/keys are taken as DER bytes, matching quic4d's own
///     `createClientEndpointWithCert` signature exactly (so
///     quic_client.dart's existing PEM->DER conversion code needs no
///     changes at all).
///   - No unidirectional streams, datagrams, or connection stats --
///     out of scope per DESIGN.md; [QuicConnection] only exposes
///     [QuicConnection.openBi] for the one bidirectional stream this
///     library ever uses.
library;

import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:pointycastle/export.dart' as pc;

import 'connection.dart' as impl;
import 'handshake/client_handshake.dart' show ClientIdentity;
import 'tls/extensions.dart' show SignatureScheme;

export 'connection.dart' show ConnectionException, ConnectionState;

class QuicApiException implements Exception {
  final String message;
  const QuicApiException(this.message);

  @override
  String toString() => 'QuicApiException: $message';
}

/// Holds parsed client identity material (CA roots to verify the
/// server against, and this client's own certificate chain + private
/// key for mTLS) and creates [QuicConnection]s from it. See this
/// library's doc comment for how this differs from quic4d's endpoint
/// reuse model.
class QuicEndpoint {
  /// Stored only so [caRoots] can report back what was passed in --
  /// see this class's doc comment for why it isn't used to validate
  /// the server's certificate chain.
  final List<Uint8List> _caRoots;
  final ClientIdentity? _clientIdentity;

  QuicEndpoint._(this._caRoots, this._clientIdentity);

  /// The CA root certificates this endpoint was constructed with (see
  /// [createClientWithCert]'s doc comment on why they're accepted for
  /// API compatibility but not currently used for validation).
  List<Uint8List> get caRoots => _caRoots;

  /// Creates a client endpoint configured for mTLS, matching quic4d's
  /// `createClientEndpointWithCert` signature: [caRoots] are DER-
  /// encoded CA certificates the server's certificate must chain to
  /// (accepted for API-compatibility with quic4d's call sites, but see
  /// the note below on validation); [certChain] is this client's own
  /// DER-encoded certificate chain (leaf first); [clientKey] is the
  /// DER-encoded private key (PKCS#8, PKCS#1, or SEC1 -- auto-detected
  /// the same way quic_client.dart's existing PEM parsing comments
  /// describe rustls-pki-types doing on the Rust side).
  ///
  /// Note on [caRoots]: dart_quic does not implement general X.509
  /// chain-of-trust validation (see DESIGN.md) -- passing [caRoots]
  /// here is accepted for signature compatibility with quic4d's own
  /// API but is not currently used to validate the server's
  /// certificate. [Connection.connect]'s `onServerCertificateChain`
  /// callback is exposed by [QuicEndpoint.connect] for callers that
  /// need to pin/verify the server chain themselves.
  static Future<QuicEndpoint> createClientWithCert({
    required List<Uint8List> caRoots,
    required List<Uint8List> certChain,
    required List<int> clientKey,
  }) async {
    if (certChain.isEmpty) {
      throw const QuicApiException(
          'certChain must contain at least the leaf certificate for mTLS');
    }
    final keyBytes = Uint8List.fromList(clientKey);
    final privateKey = _parsePrivateKey(keyBytes);
    final signatureScheme = switch (privateKey) {
      pc.ECPrivateKey _ => SignatureScheme.ecdsaSecp256r1Sha256,
      pc.RSAPrivateKey _ => SignatureScheme.rsaPssRsaeSha256,
      _ => throw QuicApiException(
          'unsupported private key type ${privateKey.runtimeType}'),
    };

    final identity = ClientIdentity(
      certificateChainDer: certChain,
      privateKey: privateKey,
      signatureScheme: signatureScheme,
    );
    return QuicEndpoint._(caRoots, identity);
  }

  /// Creates a client endpoint with no client certificate -- accepted
  /// for API parity with quic4d's plain `createClientEndpoint`, but
  /// DESIGN.md's whole scope is mTLS (commander's server always
  /// requires a client certificate), so connecting with an endpoint
  /// created this way will fail once the server sends a
  /// CertificateRequest and there is no identity to answer it with.
  static Future<QuicEndpoint> createClient() async =>
      QuicEndpoint._(const [], null);

  /// Opens a fresh connection to `host:port` (parsed from [addr],
  /// matching quic4d's `endpointConnect(addr: "host:port")` shape --
  /// unlike quic4d, [addr] here accepts a hostname directly (resolved
  /// internally), not only a literal IP:port, so callers don't need
  /// their own DNS resolution step). [serverName] is used for the TLS
  /// ClientHello's SNI/server_name extension.
  Future<QuicConnection> connect({
    required String addr,
    required String serverName,
    void Function(List<Uint8List> serverCertificateChainDer)?
        onServerCertificateChain,
    Duration handshakeTimeout = const Duration(seconds: 10),
  }) async {
    final parts = _splitHostPort(addr);
    final connection = await impl.Connection.connect(
      host: parts.host,
      port: parts.port,
      serverName: serverName,
      clientIdentity: _clientIdentity,
      onServerCertificateChain: onServerCertificateChain,
      handshakeTimeout: handshakeTimeout,
    );
    return QuicConnection._(connection);
  }

  /// No-op beyond API compatibility -- this endpoint holds no live
  /// resources of its own (see this library's doc comment); each
  /// [QuicConnection] created via [connect] owns and closes its own
  /// socket independently via [QuicConnection.close].
  Future<void> close({int errorCode = 0, String reason = ''}) async {}

  static ({String host, int port}) _splitHostPort(String addr) {
    final lastColon = addr.lastIndexOf(':');
    if (lastColon <= 0 || lastColon == addr.length - 1) {
      throw QuicApiException('addr must be "host:port", got "$addr"');
    }
    final host = addr.substring(0, lastColon);
    final portStr = addr.substring(lastColon + 1);
    final port = int.tryParse(portStr);
    if (port == null) {
      throw QuicApiException('invalid port in addr "$addr"');
    }
    return (host: host, port: port);
  }

  static pc.PrivateKey _parsePrivateKey(Uint8List der) {
    try {
      return CryptoUtils.rsaPrivateKeyFromDERBytes(der);
    } catch (_) {
      // Not RSA PKCS#8 -- fall through to EC.
    }
    try {
      return CryptoUtils.ecPrivateKeyFromDerBytes(der, pkcs8: true);
    } catch (_) {
      // Not EC PKCS#8 either -- try SEC1 (pkcs8: false).
    }
    return CryptoUtils.ecPrivateKeyFromDerBytes(der);
  }
}

/// A connected QUIC connection -- wraps [impl.Connection]. Only
/// [openBi] is exposed (see this library's doc comment on scope);
/// there is no separate "accept" side since dart_quic is client-only.
class QuicConnection {
  final impl.Connection _connection;
  QuicSendStream? _sendStream;
  QuicRecvStream? _recvStream;

  QuicConnection._(this._connection);

  impl.ConnectionState get state => _connection.state;

  /// Opens (or returns the already-open) bidirectional stream --
  /// DESIGN.md's single-stream model means this is idempotent rather
  /// than opening a new stream on every call, unlike quic4d's
  /// `connectionOpenBi` (which really does open a fresh stream each
  /// time, since Quinn supports many concurrent streams).
  Future<(QuicSendStream, QuicRecvStream)> openBi() async {
    final existingSend = _sendStream;
    final existingRecv = _recvStream;
    if (existingSend != null && existingRecv != null) {
      return (existingSend, existingRecv);
    }
    final stream = _connection.stream;
    final send = QuicSendStream._(stream);
    final recv = QuicRecvStream._(stream);
    _sendStream = send;
    _recvStream = recv;
    return (send, recv);
  }

  Stream<void> get onClosed => _connection.onClosed;

  Future<void> close({int errorCode = 0, String reason = ''}) async {
    await _connection.close();
  }
}

/// Send half of the single bidirectional stream -- wraps
/// [impl.QuicStream.write]. Named/shaped to match quic4d's
/// `QuicSendStream` plus its `sendStreamWriteAll` free function.
class QuicSendStream {
  final impl.QuicStream _stream;
  QuicSendStream._(this._stream);

  /// Writes [data] fully, matching quic4d's `sendStreamWriteAll`
  /// (returns this same stream object for API-compatible chaining;
  /// unlike quic4d's Rust-side handle, there is no per-call object
  /// identity change to thread through).
  Future<QuicSendStream> writeAll(Uint8List data) async {
    await _stream.write(data);
    return this;
  }
}

/// Receive half of the single bidirectional stream -- wraps
/// [impl.QuicStream.incoming]. Named/shaped to match quic4d's
/// `QuicRecvStream` plus its `recvStreamRead` free function, but
/// exposes the underlying broadcast [Stream] too since that maps more
/// naturally onto Dart's own idioms than repeated polling reads.
class QuicRecvStream {
  final impl.QuicStream _stream;
  QuicRecvStream._(this._stream);

  /// The raw incoming byte stream -- prefer this over [read] for new
  /// code; [read] exists only for call sites that want quic4d's
  /// poll-style shape.
  Stream<Uint8List> get incoming => _stream.incoming;

  /// Returns the next chunk of received data, or `null` once the
  /// stream's underlying controller closes with no more data pending.
  /// [maxLength] is accepted for API compatibility with quic4d's
  /// `recvStreamRead` but is not enforced -- dart_quic delivers
  /// whatever a single STREAM frame's payload contained, matching how
  /// the QUIC wire protocol itself chunks data rather than imposing an
  /// additional artificial cap.
  Future<Uint8List?> read({int maxLength = 65536}) async {
    try {
      return await _stream.incoming.first;
    } on StateError {
      return null; // stream closed with nothing (more) to deliver
    }
  }
}
