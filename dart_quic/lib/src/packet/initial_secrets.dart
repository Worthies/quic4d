import 'dart:typed_data';

import '../tls/hkdf_label.dart';

/// Derives the QUIC Initial packet protection keys (RFC 9001 §5.2,
/// worked example in Appendix A.1) from a connection ID.
///
/// The Initial secret is the only key material in the entire QUIC/TLS
/// key schedule that doesn't depend on the TLS handshake actually
/// running — it's derived purely from a fixed salt and the client's
/// chosen Destination Connection ID, so both sides can decrypt each
/// other's very first (Initial) packet before any handshake messages
/// have been exchanged.
class InitialKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  const InitialKeys({required this.key, required this.iv, required this.hp});
}

class InitialSecrets {
  final InitialKeys client;
  final InitialKeys server;

  const InitialSecrets({required this.client, required this.server});
}

/// Computes both the client's and server's Initial packet protection
/// keys for the given [destinationConnectionId] (the connection ID the
/// client chose and put in its first Initial packet's header).
Future<InitialSecrets> deriveInitialSecrets(
  Uint8List destinationConnectionId,
) async {
  final initialSecret = await hkdfExtract(
    salt: initialSaltV1,
    ikm: destinationConnectionId,
  );

  final clientInitialSecret = await hkdfExpandLabel(
    secret: initialSecret,
    label: 'client in',
    length: 32,
  );
  final serverInitialSecret = await hkdfExpandLabel(
    secret: initialSecret,
    label: 'server in',
    length: 32,
  );

  return InitialSecrets(
    client: await _deriveInitialKeys(clientInitialSecret),
    server: await _deriveInitialKeys(serverInitialSecret),
  );
}

Future<InitialKeys> _deriveInitialKeys(Uint8List secret) async {
  final key =
      await hkdfExpandLabel(secret: secret, label: 'quic key', length: 16);
  final iv =
      await hkdfExpandLabel(secret: secret, label: 'quic iv', length: 12);
  final hp =
      await hkdfExpandLabel(secret: secret, label: 'quic hp', length: 16);
  return InitialKeys(key: key, iv: iv, hp: hp);
}
