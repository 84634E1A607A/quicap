use std::{net::SocketAddr, path::Path, sync::Arc};

use compio::{
    net::UdpSocket,
    quic::{self, ClientConfig, Endpoint, ServerConfig},
    rustls,
};

use super::Config;

pub struct QuicBuilder<'a> {
    listen: SocketAddr,
    peer: SocketAddr,
    root: &'a Path,
    cert: &'a Path,
    key: &'a Path,
}

impl<'a> QuicBuilder<'a> {
    pub fn with_config(config: &'a Config) -> Result<Self, Box<dyn std::error::Error>> {
        let listen = config.listen;
        let peer = config.peer;
        let cert = config.crt.as_path();
        let key = config.key.as_path();
        let root = config.ca_crt.as_path();
        Ok(Self {
            listen,
            peer,
            cert,
            key,
            root,
        })
    }
    pub async fn build(self) -> Result<Quic, Box<dyn std::error::Error>> {
        use quic::crypto::rustls::{
            QuicClientConfig as QuicClientCryptoConfig, QuicServerConfig as QuicServerCryptoConfig,
        };
        use rustls::{
            ClientConfig as TlsClientConfig, RootCertStore, ServerConfig as TlsServerConfig,
            pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject},
            server::WebPkiClientVerifier,
        };
        let cert = CertificateDer::from_pem_file(self.cert)?;
        let key = PrivatePkcs8KeyDer::from_pem_file(self.key)?;
        let ca_cert = CertificateDer::from_pem_file(self.root)?;
        let mut ca = RootCertStore::empty();
        ca.add(ca_cert.clone())?;
        let ca = Arc::new(ca);
        let tls_client_config = TlsClientConfig::builder()
            .with_root_certificates(ca.clone())
            .with_client_auth_cert(vec![cert.clone()], key.clone_key().into())?;
        let quic_client_config = ClientConfig::new(Arc::new(QuicClientCryptoConfig::try_from(
            tls_client_config,
        )?));
        let endpoint_config = quic::EndpointConfig::default()
            .max_udp_payload_size(1472)?
            .clone();
        let client = Endpoint::new(
            UdpSocket::bind(SocketAddr::new([0, 0, 0, 0].into(), 0)).await?,
            endpoint_config.clone(),
            None,
            Some(quic_client_config),
        )?;

        let chain = vec![cert, ca_cert];
        let verifier = WebPkiClientVerifier::builder(ca).build()?;
        let tls_server_config = TlsServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key.into())?;
        let quic_server_config = ServerConfig::with_crypto(Arc::<QuicServerCryptoConfig>::new(
            tls_server_config.try_into()?,
        ));
        let server = Endpoint::new(
            UdpSocket::bind(self.listen).await?,
            endpoint_config,
            Some(quic_server_config),
            None,
        )?;

        Ok(Quic { client, server })
    }
}

pub struct Quic {
    client: Endpoint,
    server: Endpoint,
}
