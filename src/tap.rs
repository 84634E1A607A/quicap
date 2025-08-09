use compio::{
    BufResult,
    buf::bytes::{Bytes, BytesMut},
    fs::AsyncFd,
    io::{AsyncRead, AsyncWrite},
};
use tun_rs::{DeviceBuilder, SyncDevice};

use super::Config;

pub struct TapBuilder {
    name: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
}

pub struct Tap {
    inner: AsyncFd<SyncDevice>,
}

impl TapBuilder {
    pub fn with_config(config: &Config) -> Self {
        Self {
            name: config.name.clone(),
            ipv4: config.ipv4.clone(),
            ipv6: config.ipv6.clone(),
        }
    }
    pub fn build(self) -> Result<Tap, Box<dyn std::error::Error>> {
        if self.ipv4.is_none() && self.ipv6.is_none() {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "at least one address must be specified",
            ))?
        }
        let name = self.name;
        let inner = DeviceBuilder::new().name(name);
        let dev = if let Some(ipv4) = self.ipv4 {
            let ipv4: Vec<&str> = ipv4.split('/').collect();
            inner.ipv4(
                ipv4.first().unwrap().to_string(),
                ipv4.last().map_or(32, |s| s.parse::<u8>().unwrap()),
                None,
            )
        } else {
            inner
        };
        let dev = if let Some(ipv6) = self.ipv6 {
            let ipv6: Vec<&str> = ipv6.split('/').collect();
            dev.ipv6(
                ipv6.first().unwrap().to_string(),
                ipv6.last().map_or(128, |s| s.parse::<u8>().unwrap()),
            )
        } else {
            dev
        };
        let inner = dev
            .enable(false)
            .mtu(1400)
            .layer(tun_rs::Layer::L2)
            .build_sync()?;
        let inner = AsyncFd::new(inner)?;
        Ok(Tap { inner })
    }
}

impl Tap {
    pub fn name(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self.inner.name()?)
    }
    pub fn enable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(self.inner.enabled(true)?)
    }
    pub fn disable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(self.inner.enabled(false)?)
    }
    pub fn set_mtu(&mut self, mtu: u16) -> Result<(), Box<dyn std::error::Error>> {
        Ok(self.inner.set_mtu(mtu)?)
    }
    pub async fn recv(&mut self, buf: BytesMut) -> BufResult<usize, BytesMut> {
        self.inner.read(buf).await
    }
    pub async fn send(&mut self, buf: Bytes) -> BufResult<usize, Bytes> {
        self.inner.write(buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_common::*;

    #[compio::test]
    async fn alter_tap() {
        let tap = default_tap();
        assert_eq!(tap.name().unwrap(), "quicap0");
        assert_eq!(tap.inner.mtu().unwrap(), 1400);
        assert!(tap.inner.is_running().unwrap());
        tap.inner.set_mtu(1500).unwrap();
        assert_eq!(tap.inner.mtu().unwrap(), 1500);
    }

    #[compio::test]
    async fn send_to_and_recv_from_tap() {
        let mut tap = default_tap();
        let mac = tap.inner.mac_address().unwrap();
        let peer_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        // construct an arp request raw packet
        let mut arp_packet = vec![
            // ethernet
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        arp_packet.extend_from_slice(&peer_mac);
        arp_packet.extend_from_slice(&[
            // still ethernet
            0x08, 0x06, // type arp
            // arp
            0x00, 0x01, // hardware type (Ethernet)
            0x08, 0x00, // protocol type (IPv4)
            0x06, // hardware size
            0x04, // protocol size
            0x00, 0x01, // opcode (request)
        ]);
        arp_packet.extend_from_slice(&peer_mac); // sender MAC address
        arp_packet.extend_from_slice(&[192, 0, 2, 2]); // sender IP address
        arp_packet.extend_from_slice(&[0xff; 6]); // target MAC address
        arp_packet.extend_from_slice(&[192, 0, 2, 1]); // target IP address
        let len = arp_packet.len();
        let bytes = Bytes::from(arp_packet);
        let (result, _) = tap.send(bytes).await.unwrap();
        assert_eq!(len, result);
        let buf = BytesMut::with_capacity(1500);
        let (_, buf) = tap.recv(buf).await.unwrap();
        assert_eq!(&buf[22..28], &mac);
        assert_eq!(&buf[0..6], &peer_mac);
    }
}
