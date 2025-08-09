use compio::fs::AsyncFd;
use tun_rs::{DeviceBuilder, SyncDevice};

use super::Config;

pub struct TapBuilder {
    name: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
}

pub struct TapInterface {
    inner: SyncDevice,
}

pub struct TapHandle {
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
    pub fn build(self) -> Result<TapInterface, Box<dyn std::error::Error>> {
        let name = self.name;
        let inner = DeviceBuilder::new().name(name);
        if self.ipv4.is_none() && self.ipv6.is_none() {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "at least one address must be specified",
            ))?
        }
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
        Ok(TapInterface { inner })
    }
}

impl TapInterface {
    pub fn name(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self.inner.name()?)
    }
    pub fn enable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.inner.enabled(true)?;
        Ok(())
    }
    pub fn disable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.inner.enabled(false)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::net::UdpSocket;
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        path::PathBuf,
    };

    fn default_config() -> Config {
        Config {
            name: "quicap0".into(),
            ipv4: Some("192.0.2.1/24".into()),
            ipv6: None,
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            crt: PathBuf::from("/etc/quicap/crt.pem"),
            key: PathBuf::from("/etc/quicap/key.pem"),
            ca_crt: PathBuf::from("/etc/quicap/ca.crt"),
        }
    }

    fn default_tap() -> TapInterface {
        let config = default_config();
        let mut tap = TapBuilder::with_config(&config).build().unwrap();
        tap.enable().unwrap();
        tap.inner.set_mtu(1400).unwrap();
        tap
    }

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
        let tap = default_tap();
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
        tap.inner.send(&arp_packet).unwrap();
        let mut buf = [0u8; 100];
        tap.inner.recv(&mut buf).unwrap();
        assert_eq!(&buf[22..28], &mac);
        assert_eq!(&buf[0..6], &peer_mac);
    }
}
