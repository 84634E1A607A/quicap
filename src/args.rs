use std::net::Ipv4Addr;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "quicap")]
#[command(about = "A QUIC-based packet capture tool using TUN interface")]
#[command(version)]
pub struct Config {
    /// TUN interface IP address
    #[arg(short = 'i', long = "ip", default_value = "10.20.30.40")]
    pub tun_ip: Ipv4Addr,

    /// TUN interface netmask
    #[arg(short = 'n', long = "netmask", default_value = "255.255.255.252")]
    pub tun_netmask: Ipv4Addr,

    /// TUN interface name
    #[arg(long = "name", default_value = "quicap0")]
    pub tun_name: String,

    /// Listen IP address for server
    #[arg(long, default_value = "127.0.0.1")]
    pub listen_ip: Ipv4Addr,
    
    /// Listen port for server
    #[arg(long, default_value = "4433")]
    pub listen_port: u16,
    
    /// Target server IP address for client
    #[arg(long, default_value = "127.0.0.1")]
    pub target_ip: Ipv4Addr,
    
    /// Target server port for client
    #[arg(long, default_value = "4433")]
    pub target_port: u16,
    
    /// Path to server certificate file
    #[arg(long, default_value = "certs/server.crt")]
    pub cert_file: String,
    
    /// Path to server private key file
    #[arg(long, default_value = "certs/server.key")]
    pub key_file: String,
    
    /// Path to CA certificate file for client trust verification
    #[arg(long, default_value = "certs/ca.crt")]
    pub ca_cert: Option<String>,
    
    /// Path to client certificate file for mutual TLS
    #[arg(long, default_value = "certs/client.crt")]
    pub client_cert: Option<String>,
    
    /// Path to client private key file for mutual TLS
    #[arg(long, default_value = "certs/client.key")]
    pub client_key: Option<String>,
    
    /// Connection ID length (4-20 bytes)
    #[arg(long, default_value = "16", value_parser = validate_conn_id_len)]
    pub conn_id_len: u8,
    
    /// Disable QUIC client mode (server only)
    #[arg(long)]
    pub server_only: bool,
    
    /// Disable auto-retry for client connections (auto-retry is enabled by default)
    #[arg(long, action = clap::ArgAction::SetFalse)]
    pub no_client_auto_retry: bool,

    /// Maximum retry attempts for client connections (0 = infinite)
    #[arg(long, default_value = "0")]
    pub client_max_retries: u32,
}

fn validate_conn_id_len(s: &str) -> Result<u8, String> {
    let len: u8 = s.parse().map_err(|_| "Connection ID length must be a number")?;
    if !(4..=20).contains(&len) {
        return Err("Connection ID length must be between 4 and 20 bytes".to_string());
    }
    Ok(len)
}
