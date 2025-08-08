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
    pub listen: SocketAddr,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub peer: SocketAddr,
    pub crt: PathBuf,
    pub key: PathBuf,
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
            crt = "/etc/quicap/tls.crt"
            key = "/etc/quicap/tls.key"
        "#;
        let toml: Config = toml::from_str(toml).unwrap();
        let config = Config {
            name: "quicap".to_string(),
            listen: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8000)),
            ipv4: Some("10.0.0.2/16".to_string()),
            ipv6: Some("fe80::6a08/64".to_string()),
            peer: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 8001)),
            crt: PathBuf::from("/etc/quicap/tls.crt"),
            key: PathBuf::from("/etc/quicap/tls.key"),
        };
        assert_eq!(toml, config);
    }
}
