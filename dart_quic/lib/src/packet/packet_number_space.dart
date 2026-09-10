/// Per-packet-number-space state (RFC 9000 §12.3: Initial, Handshake,
/// and ApplicationData packet numbers are entirely independent
/// sequences, each with its own encryption keys and loss recovery
/// state). This bundles together everything connection.dart needs to
/// send and receive packets at one encryption level -- including the
/// RFC 9001 §6 key-update era machinery for the 1-RTT space (a real
/// quic-go server rotates its keys mid-connection once enough data has
/// flowed; ignoring the Key Phase bit makes every packet after the
/// rotation fail AEAD -- observed live against a production server).
library;

import 'dart:typed_data';

import '../handshake/client_handshake.dart' show HandshakeSecretsSnapshot;
import '../recovery/loss_detection.dart';
import '../recovery/rtt_estimator.dart';
import '../tls/hkdf_label.dart';
import '../tls/key_schedule.dart';

class DirectionalKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;
  const DirectionalKeys(
      {required this.key, required this.iv, required this.hp});
}

/// One key-update era (RFC 9001 §6): the packet-protection keys derived
/// from secret_N, tagged with the value of the Key Phase bit that
/// packets protected with these keys carry. Era 0's phase is 0 and each
/// advance flips the phase.
class KeyEra {
  final int keyPhase;
  final DirectionalKeys keys;
  const KeyEra({required this.keyPhase, required this.keys});
}

/// The AEAD key length in bytes for the negotiated cipher suite --
/// dart_quic only implements AES-128-GCM's packet protection today
/// (protection.dart), so this is fixed at 16; kept as a named constant
/// rather than a magic number at call sites, and to make it obvious
/// where AES-256/ChaCha20 support would plug in if ever added.
const int aes128GcmKeyLength = 16;

/// One direction's key-update chain: the eras derived so far from that
/// direction's initial traffic secret via
/// `secret_{n+1} = HKDF-Expand-Label(secret_n, "quic ku", "", 32)`
/// (RFC 9001 §6.1). Only the last [maxRetainedEras] eras are kept --
/// older ones can no longer decrypt anything a conforming peer would
/// still send (packets protected with retired keys are dropped, not
/// errored, per RFC 9001 §6).
class DirectionalKeyRing {
  final List<KeyEra> _eras = [];
  final List<Uint8List> _eraSecrets = [];

  /// RFC 9001 §6.1: "The header protection key is not updated." Every
  /// era in this ring shares the single hp key derived once from the
  /// handshake-established 1-RTT secret -- deriving a fresh hp key per
  /// era (as a naive `deriveTrafficKeys(nextSecret)` would) breaks
  /// header protection removal for every packet after the first key
  /// update, since the peer never rotates its own hp key either.
  Uint8List? _hp;

  static const int maxRetainedEras = 3;

  /// The secret the newest era's keys were derived from -- the root of
  /// the next advance()'s "quic ku" derivation.
  Uint8List get _latestSecret => _eraSecrets.last;

  DirectionalKeyRing(Uint8List initialSecret) {
    _eraSecrets.add(initialSecret);
  }

  /// Installs era 0 (the handshake-derived keys) and fixes the hp key
  /// that every subsequent era will reuse.
  Future<void> installInitial(Uint8List key, Uint8List iv, Uint8List hp) async {
    _hp = hp;
    _eras
      ..clear()
      ..add(
          KeyEra(keyPhase: 0, keys: DirectionalKeys(key: key, iv: iv, hp: hp)));
    // _eraSecrets[0] (the initial secret, set in the constructor) is
    // the only secret era 0 derives from -- drop anything beyond it in
    // case of a re-install.
    _eraSecrets.removeRange(0, _eraSecrets.length - 1);
  }

  /// The newest era -- what outgoing packets are protected with.
  KeyEra get latest => _eras.last;

  bool get isInstalled => _eras.isNotEmpty;

  /// Every retained era, oldest first -- the receive path picks by the
  /// packet's Key Phase bit, so a reordered packet from the previous
  /// era still decrypts.
  List<KeyEra> get eras => List.unmodifiable(_eras);

  /// The era after [latest] doesn't exist yet: derives it from the
  /// "quic ku" chain (RFC 9001 §6.1) and makes it the new [latest].
  /// Used both when the local endpoint initiates an update and when the
  /// peer's Key Phase flip is observed and a next-era trial decryption
  /// must succeed before switching.
  Future<KeyEra> advance() async {
    final nextSecret = await hkdfExpandLabel(
      secret: _latestSecret,
      label: 'quic ku',
      length: 32,
    );
    final nextKeys = await deriveTrafficKeys(
      secret: nextSecret,
      aeadKeyLength: aes128GcmKeyLength,
    );
    // RFC 9001 §6.1: "The header protection key is not updated" --
    // reuse the ring's fixed hp key, not nextKeys.hp, or header
    // protection removal fails for every packet in every era after
    // the first update.
    final era = KeyEra(
      keyPhase: 1 - latest.keyPhase,
      keys: DirectionalKeys(key: nextKeys.key, iv: nextKeys.iv, hp: _hp!),
    );
    _eras.add(era);
    _eraSecrets.add(nextSecret);
    if (_eras.length > maxRetainedEras) {
      _eras.removeRange(0, _eras.length - maxRetainedEras);
      _eraSecrets.removeRange(0, _eraSecrets.length - maxRetainedEras);
    }
    return era;
  }

  /// Removes the newest era -- used by the receive path when a trial
  /// next-era derivation (triggered by an unseen Key Phase bit) failed
  /// to authenticate, i.e. the packet was garbage rather than a genuine
  /// peer key update, so the ring must return to its prior state.
  void rollbackLast() {
    if (_eras.length <= 1) return;
    _eras.removeLast();
    _eraSecrets.removeLast();
  }
}

class PacketNumberSpaceKeys {
  DirectionalKeyRing? client;
  DirectionalKeyRing? server;

  PacketNumberSpaceKeys({this.client, this.server});

  bool get hasKeys => client != null && server != null;

  /// Latest client-direction keys (for sending). Kept for the
  /// Initial/Handshake spaces where key update never happens; the
  /// 1-RTT send path should use [client]!.latest directly.
  DirectionalKeys? get clientLatest => client?.latest.keys;

  /// Latest server-direction keys (for receiving Initial/Handshake).
  DirectionalKeys? get serverLatest => server?.latest.keys;
}

class PacketNumberSpace {
  int _nextPacketNumber = 0;
  int? largestReceivedPacketNumber;
  final LossDetector lossDetector;
  final PacketNumberSpaceKeys keys = PacketNumberSpaceKeys();
  bool discarded = false;

  PacketNumberSpace(RttEstimator sharedRtt)
      : lossDetector = LossDetector(sharedRtt);

  int allocatePacketNumber() => _nextPacketNumber++;

  int? get largestAckedPacket => lossDetector.largestAckedPacket;

  /// Derives and installs this space's traffic keys from [secrets]
  /// (client_handshake.dart's snapshot type, reused here since the
  /// Handshake and 1-RTT spaces both derive from the same shape of
  /// input: a client secret and a server secret).
  Future<void> installKeys(HandshakeSecretsSnapshot secrets) async {
    final clientKeys = await deriveTrafficKeys(
      secret: secrets.clientSecret,
      aeadKeyLength: aes128GcmKeyLength,
    );
    final serverKeys = await deriveTrafficKeys(
      secret: secrets.serverSecret,
      aeadKeyLength: aes128GcmKeyLength,
    );
    keys.client = DirectionalKeyRing(secrets.clientSecret);
    await keys.client!
        .installInitial(clientKeys.key, clientKeys.iv, clientKeys.hp);
    keys.server = DirectionalKeyRing(secrets.serverSecret);
    await keys.server!
        .installInitial(serverKeys.key, serverKeys.iv, serverKeys.hp);
  }

  void discard() {
    discarded = true;
    lossDetector.discard();
  }
}
