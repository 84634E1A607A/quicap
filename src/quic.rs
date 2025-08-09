use std::{net::SocketAddr, path::Path, sync::Arc};

use compio::{
    net::UdpSocket,
    quic::{self, ClientBuilder, Connection, Endpoint, Incoming, ServerBuilder},
    rustls::{self},
};

use super::Config;

pub struct QuicBuilder<'a> {
    listen: SocketAddr,
    peer: SocketAddr,
    root: &'a Path,
    cert: &'a Path,
    key: &'a Path,
    san: &'a str,
}

impl<'a> QuicBuilder<'a> {
    pub fn with_config(config: &'a Config) -> Result<Self, Box<dyn std::error::Error>> {
        let listen = config.listen;
        let peer = config.peer;
        let cert = config.crt.as_path();
        let key = config.key.as_path();
        let root = config.ca_crt.as_path();
        let san = config.san.as_str();
        Ok(Self {
            listen,
            peer,
            cert,
            key,
            root,
            san,
        })
    }
    pub async fn build(self) -> Result<Quic, Box<dyn std::error::Error>> {
        use rustls::{
            ClientConfig as TlsClientConfig, RootCertStore, ServerConfig as TlsServerConfig,
            pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject},
            server::WebPkiClientVerifier,
        };
        let peer = self.peer;
        let cert = CertificateDer::from_pem_file(self.cert)?;
        let key = PrivatePkcs8KeyDer::from_pem_file(self.key)?;
        let ca_cert = CertificateDer::from_pem_file(self.root)?;
        let mut ca = RootCertStore::empty();
        ca.add(ca_cert.clone())?;
        let ca = Arc::new(ca);
        let tls_client_config = TlsClientConfig::builder()
            .with_root_certificates(ca.clone())
            .with_client_auth_cert(vec![cert.clone()], key.clone_key().into())?;
        let quic_client_config =
            ClientBuilder::new_with_rustls_client_config(tls_client_config).build();
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
        let quic_server_config =
            ServerBuilder::new_with_rustls_server_config(tls_server_config).build();
        let server = Endpoint::new(
            UdpSocket::bind(self.listen).await?,
            endpoint_config,
            Some(quic_server_config),
            None,
        )?;

        let san = self.san.to_string();

        Ok(Quic {
            client,
            server,
            peer,
            san,
        })
    }
}

pub struct Quic {
    client: Endpoint,
    server: Endpoint,
    peer: SocketAddr,
    san: String,
}

pub struct QuicConnection {
    client_side: Connection,
    server_side: Endpoint,
}

#[cfg(test)]
mod tests {
    use crate::tests_common::*;

    #[compio::test]
    async fn send_to_server() {
        let quic = default_quic().await;
        let client = quic.client;
        let server = quic.server;
        let task = compio::runtime::spawn(async move {
            let incoming = server.wait_incoming().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let buf = conn.recv_datagram().await.unwrap();
            assert_eq!(buf, Bytes::from([0x01u8, 0x02].as_slice()));
            conn.send_datagram(Bytes::from([0x03u8, 0x04].as_slice()))
                .unwrap();
            compio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let conn = client
            .connect(quic.peer, &quic.san, None)
            .unwrap()
            .await
            .unwrap();
        conn.send_datagram(Bytes::from([0x01u8, 0x02].as_slice()))
            .unwrap();
        let buf = conn.recv_datagram().await.unwrap();
        assert_eq!(buf, Bytes::from([0x03u8, 0x04].as_slice()));
        task.await.unwrap();
    }
}
