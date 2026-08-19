//! Core Endpoint API - Direct Quinn endpoint wrapper

use flutter_rust_bridge::frb;
use crate::core::connection::QuicConnection;
use crate::errors::QuicError;
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

#[frb(opaque)]
pub struct QuicEndpoint {
    inner: quinn::Endpoint,
}

/// Sets a keep-alive interval and a matching max idle timeout on a client
/// TransportConfig, applied to every client endpoint this module builds
/// (both the insecure `client()` and the mTLS `client_with_cert()` path).
///
/// Quinn's TransportConfig defaults `keep_alive_interval` to `None` (no
/// keepalive traffic at all) with a 30s `max_idle_timeout`. Without any
/// keepalive, a connection that goes quiet for a while (no chat activity)
/// sends zero QUIC-level traffic — and since QUIC rides on UDP, a NAT or
/// firewall between client and server (very common on the mobile/
/// cellular links commander connects over) can silently expire its UDP
/// port mapping well before either side notices. The connection then
/// looks alive to both peers (no error, no close) right up until an
/// actual write is attempted, which fails once the server's own
/// visitorWriteTimeout elapses — this was diagnosed as the cause of the
/// server's repeating "[ASYNC SEND] Error sending to commander@...:
/// deadline exceeded" log entries specifically for commander's QUIC
/// connections (agents' own Go QUIC client and server/quic_visitor.go
/// already set the equivalent quic-go Config.KeepAlivePeriod for the
/// exact same reason — see server/quic_visitor.go's quicKeepaliveConfig).
/// A 10s keep_alive_interval keeps sending traffic often enough to hold
/// NAT mappings open, and the explicit 30s max_idle_timeout (matching
/// quinn's own default, set explicitly here so it can't silently drift
/// if quinn's default ever changes) lets a genuinely dead peer be
/// detected via idle timeout instead of only being discovered on the
/// next real write.
fn apply_keepalive_defaults(transport: &mut quinn::TransportConfig) {
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(30)) {
        transport.max_idle_timeout(Some(idle));
    }
}

impl QuicEndpoint {
    /// Create a new server endpoint with the given configuration
    pub fn server(config: crate::core::config::QuicServerConfig, addr: String) -> Result<Self, QuicError> {
        // Must run on the process-lifetime shared runtime (see
        // crate::runtime), not a throwaway one — quinn::Endpoint::server
        // spawns its I/O driver task onto whichever runtime is current at
        // construction time, and dropping that runtime immediately after
        // (as a locally-created `Runtime::new()` would be) kills the
        // driver, leaving every later call on this endpoint failing with
        // ConnectError::EndpointStopping.
        crate::runtime::shared_runtime().block_on(async {
            let addr: SocketAddr = addr.parse()
                .map_err(|e| QuicError::Config(format!("Invalid address: {:?}", e)))?;
            
            let endpoint = quinn::Endpoint::server(config.into_inner(), addr)
                .map_err(|e| QuicError::Endpoint(format!("Failed to create server endpoint: {:?}", e)))?;
            
            Ok(Self { inner: endpoint })
        })
    }

    /// Create a new client endpoint with insecure configuration (for testing)
    pub fn client() -> Result<Self, QuicError> {
        // Ensure crypto provider is installed
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|_| QuicError::Config("Failed to install default crypto provider".to_string()))?;
        }
        
        // Create insecure client config
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
            
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| QuicError::Config(format!("Failed to create QUIC client config: {:?}", e)))?
        ));
        
        // Configure transport parameters for better performance
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(100u32.into());
        apply_keepalive_defaults(&mut transport);
        config.transport_config(Arc::new(transport));
        
        // Create endpoint with default socket
        let mut endpoint = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
            .map_err(|e| QuicError::Endpoint(format!("Failed to create client endpoint: {:?}", e)))?;
            
        endpoint.set_default_client_config(config);
        
        Ok(Self { inner: endpoint })
    }

    /// Create a new client endpoint with mutual TLS (mTLS) — presents a
    /// client certificate to the server and verifies the server against the
    /// given CA roots. All inputs are DER-encoded:
    ///   ca_roots:    DER-encoded CA certificates the server must chain to.
    ///   cert_chain:  DER-encoded client certificate chain (leaf first).
    ///   client_key:  DER-encoded PKCS#8 client private key.
    pub fn client_with_cert(
        ca_roots: Vec<Vec<u8>>,
        cert_chain: Vec<Vec<u8>>,
        client_key: Vec<u8>,
    ) -> Result<Self, QuicError> {
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};

        // Ensure crypto provider is installed
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|_| QuicError::Config("Failed to install default crypto provider".to_string()))?;
        }

        // Build the root store the server certificate is verified against.
        let mut roots = rustls::RootCertStore::empty();
        for ca in ca_roots {
            roots
                .add(CertificateDer::from(ca))
                .map_err(|e| QuicError::Config(format!("Invalid CA certificate: {:?}", e)))?;
        }

        // Convert the client cert chain + key to DER types.
        let cert_chain: Vec<CertificateDer> = cert_chain
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let client_key = PrivateKeyDer::try_from(client_key)
            .map_err(|e| QuicError::Config(format!("Invalid client private key: {:?}", e)))?;

        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, client_key)
            .map_err(|e| QuicError::Config(format!("Failed to create mTLS client config: {:?}", e)))?;

        // ALPN must match the server (see server/quic_visitor.go's
        // NextProtos = ["leaf-commander"]) or the QUIC TLS handshake fails.
        let mut crypto = crypto;
        crypto.alpn_protocols = vec![b"leaf-commander".to_vec()];

        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| QuicError::Config(format!("Failed to create QUIC client config: {:?}", e)))?
        ));

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(100u32.into());
        apply_keepalive_defaults(&mut transport);
        config.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
            .map_err(|e| QuicError::Endpoint(format!("Failed to create client endpoint: {:?}", e)))?;

        endpoint.set_default_client_config(config);

        Ok(Self { inner: endpoint })
    }
    
    /// Connect to a server
    pub async fn connect(&self, addr: String, server_name: String) -> Result<QuicConnection, QuicError> {
        let addr: SocketAddr = addr.parse()
            .map_err(|e| QuicError::Connection(format!("Invalid address: {:?}", e)))?;
        
        let connecting = self.inner.connect(addr, &server_name)
            .map_err(|e| QuicError::Connection(format!("Failed to initiate connection: {:?}", e)))?;
        
        let connection = connecting.await
            .map_err(|e| QuicError::Connection(format!("Failed to establish connection: {:?}", e)))?;
        
        Ok(QuicConnection::new(connection))
    }
    
    /// Get a reference to the inner Quinn endpoint
    pub(crate) fn inner(&self) -> &quinn::Endpoint {
        &self.inner
    }

    /// Close this endpoint and every connection on it, releasing the
    /// underlying UDP socket.
    ///
    /// This is the important one for long-running clients. Each endpoint
    /// owns a bound UDP socket (an OS file descriptor) and a Quinn driver
    /// task spawned onto the process-lifetime shared runtime (see
    /// crate::runtime) — and because that runtime is deliberately never
    /// dropped, nothing reclaims the driver on its own. Dropping the Dart
    /// handle alone doesn't help either: the opaque wrapper is pointer-
    /// sized, so it creates negligible GC pressure and may not be
    /// finalized for a very long time, while the socket and driver stay
    /// alive the whole time. An app that creates a fresh endpoint per
    /// reconnect (the natural pattern) leaks one socket + one driver task
    /// per attempt, which adds up quickly on a flaky link.
    ///
    /// Idempotent, and safe to call while connections are still open —
    /// they are closed with the given code/reason first. Note this does
    /// NOT wait for in-flight close frames to be flushed to peers; use
    /// wait_idle for that when a graceful shutdown matters.
    pub fn close(&self, error_code: u32, reason: String) {
        self.inner
            .close(quinn::VarInt::from_u32(error_code), reason.as_bytes());
    }

    /// Wait until every connection on this endpoint is fully closed.
    ///
    /// Pair with close() when a graceful shutdown matters (so peers
    /// actually observe the CONNECTION_CLOSE rather than timing out); on
    /// its own this only waits, it does not initiate any close.
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

/// Skip server certificate verification for testing purposes
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
} 