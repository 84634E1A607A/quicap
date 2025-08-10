use std::{net::SocketAddr, path::Path, sync::Arc};

use compio::{
    net::UdpSocket,
    quic::{self, ClientBuilder, Connection, Endpoint, ServerBuilder},
    rustls,
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
    pub async fn build(self) -> Result<(QuicServer, QuicClient), Box<dyn std::error::Error>> {
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

        Ok((
            QuicServer(server),
            QuicClient {
                end: client,
                peer,
                san,
            },
        ))
    }
}

pub struct QuicServer(Endpoint);

impl QuicServer {
    pub async fn listen(&self) -> Option<Connection> {
        log::debug!("started listening for incoming connections");
        if let Some(incoming) = self.0.wait_incoming().await {
            log::debug!("received incoming connection attempt");
            match incoming.accept() {
                Ok(connecting) => {
                    log::debug!("accepting incoming connection");
                    match connecting.await {
                        Ok(conn) => {
                            log::info!("established incoming connection");
                            Some(conn)
                        }
                        Err(e) => {
                            log::error!("failed to establish incoming connection: {e}");
                            None
                        }
                    }
                }
                Err(e) => {
                    log::warn!("failed to accept incoming connection: {e}");
                    panic!("failed to accept connection: {e}");
                }
            }
        } else {
            None
        }
    }
}

impl QuicClient {
    pub async fn connect(&self) -> Result<Connection, Box<dyn std::error::Error>> {
        log::debug!("attempting to connect to peer at {}", self.peer);
        let connecting = self.end.connect(self.peer, &self.san, None)?;
        let conn = connecting.await?;
        log::info!("connected to peer at {}", self.peer);
        Ok(conn)
    }
}

pub struct QuicClient {
    end: Endpoint,
    peer: SocketAddr,
    san: String,
}

#[cfg(test)]
mod tests {
    use crate::tests_common::*;

    #[compio::test]
    async fn send_to_and_recv_from_server() {
        let (server, client) = default_quic().await;
        let server_task = compio::runtime::spawn(async move {
            if let Some(conn) = server.listen().await {
                let buf = conn.recv_datagram().await.unwrap();
                assert_eq!(buf, Bytes::from([0x01u8, 0x02].as_slice()));
                conn.send_datagram(Bytes::from([0x03u8, 0x04].as_slice()))
                    .unwrap();
                compio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });
        compio::time::sleep(std::time::Duration::from_millis(100)).await;
        let conn = client.connect().await.unwrap();
        conn.send_datagram(Bytes::from([0x01u8, 0x02].as_slice()))
            .unwrap();
        let buf = conn.recv_datagram().await.unwrap();
        assert_eq!(buf, Bytes::from([0x03u8, 0x04].as_slice()));
        server_task.await.unwrap();
    }
}
