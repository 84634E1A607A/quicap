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

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,
}
