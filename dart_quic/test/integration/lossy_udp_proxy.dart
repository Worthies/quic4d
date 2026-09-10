import 'dart:io';
import 'dart:math';

/// A minimal UDP relay that drops packets in one direction with some
/// probability -- used to force real retransmissions in the interop
/// test rather than relying on real network flakiness. Sits between
/// the Dart client and the real quic-go server: the client connects to
/// [listenPort] on localhost, and every datagram is forwarded to
/// [targetPort] (and replies back), except for a configurable fraction
/// dropped in the client->server direction.
class LossyUdpProxy {
  final int listenPort;
  final int targetPort;
  final double dropProbability;
  final Random _random;

  RawDatagramSocket? _clientSocket;
  RawDatagramSocket? _serverSocket;
  InternetAddress? _clientAddress;
  int? _clientPort;

  int droppedCount = 0;
  int forwardedCount = 0;

  LossyUdpProxy({
    required this.listenPort,
    required this.targetPort,
    this.dropProbability = 0.0,
    int? seed,
  }) : _random = Random(seed ?? 42);

  Future<void> start() async {
    _clientSocket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, listenPort);
    _serverSocket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);

    _clientSocket!.listen((event) {
      if (event != RawSocketEvent.read) return;
      final datagram = _clientSocket!.receive();
      if (datagram == null) return;
      _clientAddress = datagram.address;
      _clientPort = datagram.port;

      if (_random.nextDouble() < dropProbability) {
        droppedCount++;
        return;
      }
      forwardedCount++;
      _serverSocket!
          .send(datagram.data, InternetAddress.loopbackIPv4, targetPort);
    });

    _serverSocket!.listen((event) {
      if (event != RawSocketEvent.read) return;
      final datagram = _serverSocket!.receive();
      if (datagram == null) return;
      final clientAddress = _clientAddress;
      final clientPort = _clientPort;
      if (clientAddress == null || clientPort == null) return;
      // Server->client direction is never dropped -- this proxy only
      // needs to force *client* retransmissions for this test.
      _clientSocket!.send(datagram.data, clientAddress, clientPort);
    });
  }

  Future<void> stop() async {
    _clientSocket?.close();
    _serverSocket?.close();
  }
}
