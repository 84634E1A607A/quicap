use std::net::SocketAddr;

use compio::net::UdpSocket;
use compio::quic;

use super::Config;

pub struct QuicBuilder {
    listen: SocketAddr,
    peer: SocketAddr,
}

impl QuicBuilder {
    pub fn with_config(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let listen = config.listen;
        let peer = config.peer;
        Ok(Self { listen, peer })
    }
    // pub async fn build(self) -> Result<Quic, Box<dyn std::error::Error>> {
    //     let listen = UdpSocket::bind(self.listen).await?;
    //     let peer = UdpSocket::bind(self.peer).await?;
    //     let peer = quic::Endpoint::new(peer, config, server_config, default_client_config);
    //     Ok(Quic { listen, peer })
    // }
}

pub struct Quic {
    listen: UdpSocket,
    peer: quic::Endpoint,
}
