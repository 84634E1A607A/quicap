use clap::Parser;
use core::net::SocketAddr;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Args {
    #[arg(short, long, default_value = "/etc/quicap/config.toml")]
    pub config: String,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Deserialize)]
pub struct Config {
    pub name: String,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    #[serde(default = "default_peer")]
    pub peer: SocketAddr,
    #[serde(default = "default_crt")]
    pub crt: PathBuf,
    #[serde(default = "default_key")]
    pub key: PathBuf,
    pub root: Option<PathBuf>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 2161))
}

fn default_peer() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 2162))
}

fn default_crt() -> PathBuf {
    PathBuf::from("/cert/tls.crt")
}

fn default_key() -> PathBuf {
    PathBuf::from("/cert/tls.key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn deserialize_configuration() {
        let toml = r#"
            name = "quicap"
            listen = "10.0.0.1:8000"
            peer = "10.0.0.3:8001"
            ipv4 = "10.0.0.2/16"
            ipv6 = "fe80::6a08/64"
            crt = "/cert/tls.crt"
            key = "/cert/tls.key"
        "#;
        let toml: Config = toml::from_str(toml).unwrap();
        let config = Config {
            name: "quicap".to_string(),
            listen: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8000)),
            ipv4: Some("10.0.0.2/16".to_string()),
            ipv6: Some("fe80::6a08/64".to_string()),
            peer: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 8001)),
            crt: PathBuf::from("/cert/tls.crt"),
            key: PathBuf::from("/cert/tls.key"),
            root: None,
        };
        assert_eq!(toml, config);
    }
}
