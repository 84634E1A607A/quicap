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
