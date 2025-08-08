use std::{net::SocketAddr, path::Path, sync::Arc};

use compio::{
    net::UdpSocket,
    quic::{self, ClientConfig, ServerConfig},
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
    pub fn build(self) -> Result<Quic, Box<dyn std::error::Error>> {
        use quic::crypto::rustls::QuicClientConfig;
        use rustls::{
            ClientConfig as TlsClientConfig, RootCertStore, ServerConfig as TlsServerConfig,
            pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject},
            server::WebPkiClientVerifier,
            version::TLS13,
        };
        let versions = [&TLS13];
        let cert = CertificateDer::from_pem_file(self.cert)?;
        let key = PrivatePkcs8KeyDer::from_pem_file(self.key)?;
        let ca_cert = CertificateDer::from_pem_file(self.root)?;
        let mut ca = RootCertStore::empty();
        ca.add(ca_cert.clone())?;
        let ca = Arc::new(ca);
        let client = TlsClientConfig::builder()
            .with_root_certificates(ca.clone())
            .with_client_auth_cert(vec![cert.clone()], key.clone_key().into())?;
        let client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client)?));
        let chain = vec![cert, ca_cert];
        let verifier = WebPkiClientVerifier::builder(ca).build()?;
        let server = TlsServerConfig::builder_with_protocol_versions(&versions)
            .with_client_cert_verifier(verifier);
        let server = ServerConfig::with_single_cert(chain, key.into())?;
        todo!()
    }
}

pub struct Quic {
    listen: UdpSocket,
    peer: quic::Endpoint,
}
