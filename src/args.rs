use clap::Parser;
use core::net::SocketAddr;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(version, about)]
pub(super) struct Args {
    #[arg(short, long, default_value = "/etc/quicap/quicap.toml")]
    pub config: String,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Deserialize)]
pub(super) struct Config {
    pub name: String,
    pub listen: SocketAddr,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
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
            ipv4 = "10.0.0.2/16"
            ipv6 = "fe80::6a08/64"
        "#;
        let toml: Config = toml::from_str(toml).unwrap();
        let config = Config {
            name: "quicap".to_string(),
            listen: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8000)),
            ipv4: Some("10.0.0.2/16".to_string()),
            ipv6: Some("fe80::6a08/64".to_string()),
        };
        assert_eq!(toml, config);
    }
}
