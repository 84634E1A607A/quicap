use std::{net::SocketAddr, path::Path};

use compio::net::UdpSocket;
use compio::quic::{self, ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::Config;

pub struct QuicBuilder<'a> {
    listen: SocketAddr,
    peer: SocketAddr,
    root: Option<&'a Path>,
    cert: &'a Path,
    key: &'a Path,
}

impl<'a> QuicBuilder<'a> {
    pub fn with_config(config: &'a Config) -> Result<Self, Box<dyn std::error::Error>> {
        let listen = config.listen;
        let peer = config.peer;
        let cert = config.crt.as_path();
        let key = config.key.as_path();
        let root = config.root.as_deref();
        Ok(Self {
            listen,
            peer,
            cert,
            key,
            root,
        })
    }
}

pub struct Quic {
    listen: UdpSocket,
    peer: quic::Endpoint,
}
