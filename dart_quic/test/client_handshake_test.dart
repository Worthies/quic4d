import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:cryptography/cryptography.dart';
import 'package:dart_quic/src/handshake/client_handshake.dart';
import 'package:dart_quic/src/tls/certificate_message.dart';
import 'package:dart_quic/src/tls/certificate_verify_signature.dart';
import 'package:dart_quic/src/tls/extensions.dart';
import 'package:dart_quic/src/tls/finished.dart';
import 'package:dart_quic/src/tls/handshake_message.dart';
import 'package:dart_quic/src/tls/key_schedule.dart';
import 'package:dart_quic/src/tls/server_hello.dart';
import 'package:dart_quic/src/tls/transcript.dart';
import 'package:dart_quic/src/tls/transport_parameters.dart';
import 'package:test/test.dart';

/// End-to-end integration test: a scripted fake TLS 1.3 server (built
/// from the same lower-level, RFC-vector-verified codecs as dart_quic
/// itself -- extensions.dart, certificate_message.dart,
/// key_schedule.dart, finished.dart -- but driven independently here,
/// not by importing ClientHandshake's own server-side logic, since
/// ClientHandshake has none) drives a full mTLS handshake against
/// [ClientHandshake] and checks it reaches [ClientHandshake.isComplete]
/// with secrets that satisfy the same key-schedule relationships
/// checked in isolation elsewhere. This is the milestone 3 acceptance
/// test: every individual piece (ClientHello, ServerHello parsing, key
/// schedule, Certificate/CertificateVerify, Finished) already has its
/// own RFC-vector golden test; this confirms they compose correctly
/// end to end, including the mTLS round trip in both directions.
void main() {
  final fixturesDir = '${Directory.current.path}/test/fixtures';

  test(
      'full mTLS handshake completes and derives matching application '
      'secrets on both sides', () async {
    // ---- Fake server setup ----
    final serverCertDer = File('$fixturesDir/ec.der').readAsBytesSync();
    final serverKeyPem = File('$fixturesDir/ec.key').readAsStringSync();
    final serverPrivateKey = CryptoUtils.ecPrivateKeyFromPem(serverKeyPem);

    final clientCertDer = File('$fixturesDir/rsa.der').readAsBytesSync();
    final clientKeyPem = File('$fixturesDir/rsa.key').readAsStringSync();
    final clientPrivateKey = CryptoUtils.rsaPrivateKeyFromPem(clientKeyPem);

    final x25519 = X25519();
    final serverKeyPair = await x25519.newKeyPair();
    final serverPublicKey =
        Uint8List.fromList((await serverKeyPair.extractPublicKey()).bytes);

    final serverTranscript = TranscriptHash();

    // ---- Client setup ----
    final clientIdentity = ClientIdentity(
      certificateChainDer: [clientCertDer],
      privateKey: clientPrivateKey,
      signatureScheme: SignatureScheme.rsaPssRsaeSha256,
    );

    List<Uint8List>? observedServerChain;
    final client = await ClientHandshake.create(
      clientRandom: Uint8List.fromList(List.generate(32, (i) => i)),
      clientTransportParameters: TransportParameters.clientDefaults(
        initialSourceConnectionId: Uint8List.fromList([1, 2, 3, 4]),
      ),
      serverName: 'test.example.com',
      clientIdentity: clientIdentity,
      onServerCertificateChain: (chain) => observedServerChain = chain,
    );

    client.start();
    final clientHelloBytes = client.pendingOutbound(EncryptionLevel.initial);
    expect(clientHelloBytes, isNotEmpty);
    serverTranscript.addMessage(clientHelloBytes);

    final clientHelloMessage = tryDecodeHandshakeMessage(clientHelloBytes, 0)!;
    expect(clientHelloMessage.type, HandshakeType.clientHello);

    // Parse the client's key_share out of its ClientHello so the fake
    // server can compute the same DHE shared secret.
    final chBody = clientHelloMessage.body;
    var pos = 2 + 32 + 1; // version + random + session_id_len(=0)
    final cipherSuitesLen = (chBody[pos] << 8) | chBody[pos + 1];
    pos += 2 + cipherSuitesLen;
    pos += 1 + chBody[pos]; // compression methods
    final extResult = decodeExtensionList(chBody, pos);
    final clientKeyShareExt = extResult.extensions
        .firstWhere((e) => e.type == ExtensionType.keyShare);
    // ClientHello key_share wraps a list; skip the 2-byte list length.
    final clientKeyShareEntry =
        decodeKeyShareServerHello(clientKeyShareExt.data.sublist(2));
    final clientPublicKeyBytes = clientKeyShareEntry.keyExchange;

    final sharedSecret = await x25519.sharedSecretKey(
      keyPair: serverKeyPair,
      remotePublicKey:
          SimplePublicKey(clientPublicKeyBytes, type: KeyPairType.x25519),
    );
    final dheSharedSecret =
        Uint8List.fromList(await sharedSecret.extractBytes());

    // ---- Server builds ServerHello ----
    final serverHelloBody = BytesBuilder();
    serverHelloBody.add([0x03, 0x03]); // legacy_version
    final serverRandom = Uint8List.fromList(List.generate(32, (i) => 255 - i));
    serverHelloBody.add(serverRandom);
    serverHelloBody.addByte(0); // legacy_session_id_echo (client sent none)
    serverHelloBody.add([0x13, 0x01]); // cipher_suite: TLS_AES_128_GCM_SHA256
    serverHelloBody.addByte(0); // legacy_compression_method

    final serverExtensions = [
      RawExtension(
        type: ExtensionType.keyShare,
        data: Uint8List.fromList([
          ...[0x00, 0x1d], // group: x25519
          ...[0x00, 0x20], // key_exchange length: 32
          ...serverPublicKey,
        ]),
      ),
      RawExtension(
        type: ExtensionType.supportedVersions,
        data: Uint8List.fromList([0x03, 0x04]),
      ),
    ];
    serverHelloBody.add(encodeExtensionList(serverExtensions));

    final serverHelloSink = BytesBuilder();
    encodeHandshakeMessage(
        serverHelloSink, HandshakeType.serverHello, serverHelloBody.toBytes());
    final serverHelloBytes = serverHelloSink.toBytes();
    serverTranscript.addMessage(serverHelloBytes);

    // Sanity check the fake server's own ServerHello parses the way the
    // real ServerHello.decodeBody test suite expects.
    final parsedForSanity = ServerHello.decodeBody(
        tryDecodeHandshakeMessage(serverHelloBytes, 0)!.body);
    expect(parsedForSanity.keyShare!.keyExchange, serverPublicKey);

    await client.feedCryptoData(EncryptionLevel.initial, 0, serverHelloBytes);

    // ---- Server derives handshake secrets (mirrors key_schedule.dart,
    // independently invoked here, not shared state with the client) ----
    final transcriptHashUpToServerHello = await serverTranscript.snapshot();
    final empty = await emptyTranscriptHash();
    final serverSecrets = await deriveHandshakeSecrets(
      dheSharedSecret: dheSharedSecret,
      transcriptHashUpToServerHello: transcriptHashUpToServerHello,
      emptyTranscriptHash: empty,
    );

    // Client should have derived the *same* handshake secrets from its
    // side of the same DHE exchange and transcript.
    final clientHsSecrets = client.handshakeTrafficSecrets;
    expect(clientHsSecrets.clientSecret,
        serverSecrets.clientHandshakeTrafficSecret);
    expect(clientHsSecrets.serverSecret,
        serverSecrets.serverHandshakeTrafficSecret);

    // ---- Server builds EncryptedExtensions ----
    final eeSink = BytesBuilder();
    encodeHandshakeMessage(
        eeSink, HandshakeType.encryptedExtensions, encodeExtensionList([]));
    final eeBytes = eeSink.toBytes();
    serverTranscript.addMessage(eeBytes);

    // ---- Server requests client certificate ----
    final crBody = BytesBuilder();
    crBody.addByte(0); // certificate_request_context: empty
    crBody.add(encodeExtensionList([
      RawExtension(
        type: ExtensionType.signatureAlgorithms,
        data: Uint8List.fromList([0x00, 0x02, 0x08, 0x04]),
      ),
    ]));
    final crSink = BytesBuilder();
    encodeHandshakeMessage(
        crSink, HandshakeType.certificateRequest, crBody.toBytes());
    final crBytes = crSink.toBytes();
    serverTranscript.addMessage(crBytes);

    // ---- Server sends its Certificate ----
    final serverCertMessage = CertificateMessage(
      certificateList: [CertificateEntry(certData: serverCertDer)],
    ).encode();
    serverTranscript.addMessage(serverCertMessage);

    // ---- Server signs CertificateVerify over transcript-through-Certificate ----
    final transcriptThroughCert = await serverTranscript.snapshot();
    final serverCvContent = buildCertificateVerifyContent(
      isServer: true,
      transcriptHash: transcriptThroughCert,
    );
    final serverSignature = signWithEcdsaP256(
        privateKey: serverPrivateKey, content: serverCvContent);
    final serverCvMessage = CertificateVerifyMessage(
      algorithm: SignatureScheme.ecdsaSecp256r1Sha256,
      signature: serverSignature,
    ).encode();
    serverTranscript.addMessage(serverCvMessage);

    // ---- Server sends Finished ----
    final transcriptThroughCv = await serverTranscript.snapshot();
    final serverFinishedVerifyData = await computeFinishedVerifyData(
      handshakeTrafficSecret: serverSecrets.serverHandshakeTrafficSecret,
      transcriptHash: transcriptThroughCv,
    );
    final serverFinishedSink = BytesBuilder();
    encodeHandshakeMessage(
        serverFinishedSink, HandshakeType.finished, serverFinishedVerifyData);
    final serverFinishedBytes = serverFinishedSink.toBytes();
    serverTranscript.addMessage(serverFinishedBytes);
    // RFC 8446 §7.1's key schedule: application traffic secrets are
    // derived from the transcript "ClientHello...server Finished" --
    // snapshot here, before the client's own Certificate/
    // CertificateVerify/Finished get added below, matching
    // ClientHandshake's own _transcriptHashAtServerFinished.
    final transcriptAtServerFinished = await serverTranscript.snapshot();

    // ---- Feed the whole server flight to the client at once (as if it
    // arrived in one Handshake-level CRYPTO frame) ----
    final serverFlight = BytesBuilder()
      ..add(eeBytes)
      ..add(crBytes)
      ..add(serverCertMessage)
      ..add(serverCvMessage)
      ..add(serverFinishedBytes);

    await client.feedCryptoData(
        EncryptionLevel.handshake, 0, serverFlight.toBytes());

    expect(observedServerChain, isNotNull);
    expect(observedServerChain!.single, serverCertDer);
    expect(client.isComplete, isTrue);

    // ---- Client's outbound Handshake-level flight: Certificate,
    // CertificateVerify, Finished (mTLS) ----
    final clientFlight = client.pendingOutbound(EncryptionLevel.handshake);
    expect(clientFlight, isNotEmpty);

    var cpos = 0;
    final clientCertMsg = tryDecodeHandshakeMessage(clientFlight, cpos)!;
    expect(clientCertMsg.type, HandshakeType.certificate);
    cpos += clientCertMsg.totalLength;
    final decodedClientCert = CertificateMessage.decodeBody(clientCertMsg.body);
    expect(decodedClientCert.certificateList.single.certData, clientCertDer);
    serverTranscript.addMessage(_wrap(clientCertMsg));

    final clientCvMsg = tryDecodeHandshakeMessage(clientFlight, cpos)!;
    expect(clientCvMsg.type, HandshakeType.certificateVerify);
    cpos += clientCvMsg.totalLength;
    final decodedClientCv =
        CertificateVerifyMessage.decodeBody(clientCvMsg.body);
    expect(decodedClientCv.algorithm, SignatureScheme.rsaPssRsaeSha256);

    // Server independently verifies the client's CertificateVerify.
    final transcriptThroughClientCert = await serverTranscript.snapshot();
    final clientCvContent = buildCertificateVerifyContent(
      isServer: false,
      transcriptHash: transcriptThroughClientCert,
    );
    expect(
      () => verifyCertificateSignature(
        leafCertificateDer: clientCertDer,
        algorithm: decodedClientCv.algorithm,
        signedContent: clientCvContent,
        signature: decodedClientCv.signature,
      ),
      returnsNormally,
    );
    serverTranscript.addMessage(_wrap(clientCvMsg));

    final clientFinishedMsg = tryDecodeHandshakeMessage(clientFlight, cpos)!;
    expect(clientFinishedMsg.type, HandshakeType.finished);
    cpos += clientFinishedMsg.totalLength;
    expect(cpos, clientFlight.length); // nothing left unexpected

    // Server independently verifies the client's Finished verify_data.
    final transcriptThroughClientCv = await serverTranscript.snapshot();
    final expectedClientVerifyData = await computeFinishedVerifyData(
      handshakeTrafficSecret: serverSecrets.clientHandshakeTrafficSecret,
      transcriptHash: transcriptThroughClientCv,
    );
    expect(
      verifyDataMatches(expectedClientVerifyData, clientFinishedMsg.body),
      isTrue,
    );
    serverTranscript.addMessage(_wrap(clientFinishedMsg));

    // ---- Application secrets must match on both sides ----
    final serverAppSecrets = await deriveApplicationTrafficSecrets(
      masterSecret: serverSecrets.masterSecret,
      transcriptHashUpToServerFinished: transcriptAtServerFinished,
    );
    final clientAppSecrets = client.applicationTrafficSecrets;
    expect(clientAppSecrets.clientSecret,
        serverAppSecrets.clientApplicationTrafficSecret);
    expect(clientAppSecrets.serverSecret,
        serverAppSecrets.serverApplicationTrafficSecret);
  });

  test('a corrupted server Finished aborts the handshake', () async {
    final client = await ClientHandshake.create(
      clientRandom: Uint8List.fromList(List.generate(32, (i) => i)),
      clientTransportParameters: TransportParameters.clientDefaults(
        initialSourceConnectionId: Uint8List.fromList([9, 9, 9, 9]),
      ),
    );
    client.start();
    client.pendingOutbound(EncryptionLevel.initial); // drain, unused here
    // This test aborts before any DHE-derived value would ever be used
    // (the point is the corrupted Finished check below), so the
    // ClientHello's own key_share is never parsed -- the fake
    // ServerHello just needs to be shaped like a real negotiation.
    final x25519 = X25519();
    final serverKeyPair = await x25519.newKeyPair();
    final serverPublicKey =
        Uint8List.fromList((await serverKeyPair.extractPublicKey()).bytes);

    final serverHelloBody = BytesBuilder();
    serverHelloBody.add([0x03, 0x03]);
    serverHelloBody.add(Uint8List(32));
    serverHelloBody.addByte(0);
    serverHelloBody.add([0x13, 0x01]);
    serverHelloBody.addByte(0);
    serverHelloBody.add(encodeExtensionList([
      RawExtension(
        type: ExtensionType.keyShare,
        data: Uint8List.fromList([0x00, 0x1d, 0x00, 0x20, ...serverPublicKey]),
      ),
      RawExtension(
        type: ExtensionType.supportedVersions,
        data: Uint8List.fromList([0x03, 0x04]),
      ),
    ]));
    final serverHelloSink = BytesBuilder();
    encodeHandshakeMessage(
        serverHelloSink, HandshakeType.serverHello, serverHelloBody.toBytes());
    await client.feedCryptoData(
        EncryptionLevel.initial, 0, serverHelloSink.toBytes());

    final eeSink = BytesBuilder();
    encodeHandshakeMessage(
        eeSink, HandshakeType.encryptedExtensions, encodeExtensionList([]));

    // Deliberately-wrong Finished verify_data (32 zero bytes).
    final badFinishedSink = BytesBuilder();
    encodeHandshakeMessage(
        badFinishedSink, HandshakeType.finished, Uint8List(32));

    final flight = BytesBuilder()
      ..add(eeSink.toBytes())
      ..add(badFinishedSink.toBytes());

    expect(
      () =>
          client.feedCryptoData(EncryptionLevel.handshake, 0, flight.toBytes()),
      throwsA(isA<HandshakeException>()),
    );
  });
}

Uint8List _wrap(HandshakeMessage message) {
  final sink = BytesBuilder();
  encodeHandshakeMessage(sink, message.type, message.body);
  return sink.toBytes();
}
