/// Per-packet-number-space state (RFC 9000 §12.3: Initial, Handshake,
/// and ApplicationData packet numbers are entirely independent
/// sequences, each with its own encryption keys and loss recovery
/// state). This bundles together everything connection.dart needs to
/// send and receive packets at one encryption level.
library;

import 'dart:typed_data';

import '../handshake/client_handshake.dart' show HandshakeSecretsSnapshot;
import '../recovery/loss_detection.dart';
import '../recovery/rtt_estimator.dart';
import '../tls/key_schedule.dart';

class DirectionalKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;
  const DirectionalKeys(
      {required this.key, required this.iv, required this.hp});
}

/// The AEAD key length in bytes for the negotiated cipher suite --
/// dart_quic only implements AES-128-GCM's packet protection today
/// (protection.dart), so this is fixed at 16; kept as a named constant
/// rather than a magic number at call sites, and to make it obvious
/// where AES-256/ChaCha20 support would plug in if ever added.
const int aes128GcmKeyLength = 16;

class PacketNumberSpaceKeys {
  DirectionalKeys? client;
  DirectionalKeys? server;

  PacketNumberSpaceKeys({this.client, this.server});

  bool get hasKeys => client != null && server != null;
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
    keys.client = DirectionalKeys(
        key: clientKeys.key, iv: clientKeys.iv, hp: clientKeys.hp);
    keys.server = DirectionalKeys(
        key: serverKeys.key, iv: serverKeys.iv, hp: serverKeys.hp);
  }

  void discard() {
    discarded = true;
    lossDetector.discard();
  }
}
