mod args;
mod quic;
mod tap;
mod tunnel;

use clap::Parser;
use log::info;

use self::{
    args::{Args, Config},
    tap::{Tap, TapBuilder},
};

#[compio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(debug_assertions))]
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    let (mut tap, (mut server, mut client)) = {
        let args = Args::parse();
        let config = std::path::Path::new(args.config.as_str());
        info!("reading from {config:?}");
        let config = String::from_utf8(compio::fs::read(config).await?)?;
        let config: Config = toml::from_str(config.as_str())?;
        (
            TapBuilder::with_config(&config).build()?,
            quic::QuicBuilder::with_config(&config)?.build().await?,
        )
    };
    info!("created tap interface {}", tap.name()?);
    Ok(())
}

#[cfg(test)]
mod tests_common {
    use super::*;
    pub use compio::buf::bytes::Bytes;
    pub use quic::{QuicBuilder, QuicClient, QuicServer};
    pub use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        path::PathBuf,
    };
    pub use tap::Tap;

    pub fn default_config() -> Config {
        Config {
            name: "quicap0".into(),
            ipv4: Some("192.0.2.1/24".into()),
            ipv6: None,
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            crt: PathBuf::from("./tests/asset/crt.pem"),
            key: PathBuf::from("./tests/asset/key.pem"),
            ca_crt: PathBuf::from("./tests/asset/ca_crt.pem"),
            san: "node.quicap.local".into(),
        }
    }

    pub fn default_tap() -> Tap {
        let config = default_config();
        let mut tap = TapBuilder::with_config(&config).build().unwrap();
        tap.enable().unwrap();
        tap.set_mtu(1400).unwrap();
        tap
    }

    pub async fn default_quic() -> (QuicServer, QuicClient) {
        QuicBuilder::with_config(&default_config())
            .unwrap()
            .build()
            .await
            .unwrap()
    }
}
