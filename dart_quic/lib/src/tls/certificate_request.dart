/// RFC 8446 §4.3.2: the server's request for a client certificate --
/// dart_quic's whole reason for existing is mTLS (DESIGN.md), so
/// receiving this message (or not) determines whether the client sends
/// Certificate+CertificateVerify at all. Only
/// [certificateRequestContext] is surfaced as a named field (echoed
/// back in the client's Certificate message per RFC 8446 §4.4.2);
/// everything else stays in [extensions] since dart_quic doesn't act on
/// e.g. certificate_authorities.
library;

import 'dart:typed_data';

import 'extensions.dart';

class CertificateRequest {
  final Uint8List certificateRequestContext;
  final List<RawExtension> extensions;

  const CertificateRequest({
    required this.certificateRequestContext,
    required this.extensions,
  });

  static CertificateRequest decodeBody(Uint8List body) {
    var pos = 0;
    final contextLength = body[pos];
    pos += 1;
    final context = Uint8List.sublistView(body, pos, pos + contextLength);
    pos += contextLength;

    final extResult = decodeExtensionList(body, pos);

    return CertificateRequest(
      certificateRequestContext: context,
      extensions: extResult.extensions,
    );
  }
}
