use core::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd};

use tokio_uring::{fs::File, net::UdpSocket};
use tun_rs::{AsyncDevice, DeviceBuilder};

use super::Config;

pub(super) struct TapBuilder {
    config: Config,
}

pub(super) struct TapInterface {
    dev: AsyncDevice,
    listen: SocketAddr,
}

pub(super) struct TapHandle {
    fd: File,
    socket: UdpSocket,
}

impl TapBuilder {
    pub fn with_config(config: Config) -> Self {
        Self { config }
    }
    pub fn build(self) -> Result<TapInterface, Box<dyn std::error::Error>> {
        let name = self.config.name;
        let dev = DeviceBuilder::new().name(name);
        let listen = self.config.listen;
        let dev = if let Some(ipv4) = self.config.ipv4 {
            let ipv4: Vec<&str> = ipv4.split('/').collect();
            dev.ipv4(
                ipv4.first().unwrap().to_string(),
                ipv4.last().map_or(32, |s| s.parse::<u8>().unwrap()),
                None,
            )
        } else {
            dev
        };
        let dev = if let Some(ipv6) = self.config.ipv6 {
            let ipv6: Vec<&str> = ipv6.split('/').collect();
            dev.ipv6(
                ipv6.first().unwrap().to_string(),
                ipv6.last().map_or(128, |s| s.parse::<u8>().unwrap()),
            )
        } else {
            dev
        };
        let dev = dev
            .enable(false)
            .mtu(1400)
            .layer(tun_rs::Layer::L2)
            .build_async()?;
        Ok(TapInterface { dev, listen })
    }
}

impl TapInterface {
    pub fn name(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self.dev.name()?)
    }
    pub fn enable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.dev.enabled(true)?;
        Ok(())
    }
    pub fn disable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.dev.enabled(false)?;
        Ok(())
    }
    pub fn into_handle(self) -> Result<TapHandle, Box<dyn std::error::Error>> {
        let fd = self.dev.as_raw_fd();
        let file = unsafe { File::from_raw_fd(fd) };
        let socket = std::net::UdpSocket::bind(self.listen)?;
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket);
        Ok(TapHandle { fd: file, socket })
    }
    pub fn from_handle(handle: TapHandle) -> Result<Self, Box<dyn std::error::Error>> {
        let fd = handle.fd.as_raw_fd();
        let dev = unsafe { AsyncDevice::from_raw_fd(fd) };
        let listen = handle.socket.local_addr()?;
        Ok(TapInterface { dev, listen })
    }
}
