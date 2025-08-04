use log::{debug, error, info, warn};
use std::io;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::{self, Sender, Receiver};
use tokio_tun::{Tun, TunBuilder};
use std::sync::Arc;

#[derive(Clone)]
pub struct TunDevice {
    name: String,
    rx_tun: Arc<Tun>, // for receiving
    tx: Sender<Vec<u8>>, // channel to send write packets
}

impl TunDevice {
    pub async fn new(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<Self> {
        let mut tuns = TunBuilder::new()
            .name(name)
            .address(ip)
            .netmask(netmask)
            .up()
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let tun = Arc::new(tuns.pop().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Failed to create TUN interface")
        })?);

        let rx_tun = tun.clone(); // for reading
        let tx_tun = tun;     // for writing

        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel(1024);

        tokio::spawn(async move {
            writer_loop(tx_tun, rx).await;
        });

        Ok(Self {
            name: name.to_string(),
            rx_tun,
            tx,
        })
    }

    pub async fn run(&self, verbose: bool) -> io::Result<()> {
        info!("TUN device {} is running. Press Ctrl+C to stop.", self.name);

        let tx = self.tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                info!("Injecting ping request to 172.30.12.5...");
                let ping_packet = create_ping_packet();
                if let Err(e) = tx.send(ping_packet).await {
                    error!("Failed to inject ping packet: {}", e);
                }
            }
        });

        let mut buffer = [0u8; 1500]; // MTU size buffer

        loop {
            match self.rx_tun.recv(&mut buffer).await {
                Ok(n) => {
                    if verbose {
                        debug!("Received {} bytes:", n);
                        print_packet_hex(&buffer[..n]);
                    }

                    self.parse_and_print_packet(&buffer[..n]).await;
                }
                Err(e) => {
                    error!("Error reading from TUN: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn parse_and_print_packet(&self, packet: &[u8]) {
        if packet.len() < 20 {
            warn!("Packet too short to be valid IP");
            return;
        }

        let version = (packet[0] >> 4) & 0x0F;
        let ihl = (packet[0] & 0x0F) * 4;
        let protocol = packet[9];
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        info!(
            "📦 IP Packet: {} -> {} (Protocol: {}, Version: {}, Length: {})",
            src_ip,
            dst_ip,
            protocol,
            version,
            packet.len()
        );

        match protocol {
            1 => self.parse_icmp_packet(packet, ihl as usize).await,
            6 => self.parse_tcp_packet(packet, ihl as usize).await,
            17 => self.parse_udp_packet(packet, ihl as usize).await,
            _ => info!("   Unknown protocol: {}", protocol),
        }
    }

    async fn parse_icmp_packet(&self, packet: &[u8], ip_header_len: usize) {
        if packet.len() < ip_header_len + 8 {
            return;
        }

        let icmp_type = packet[ip_header_len];
        let icmp_code = packet[ip_header_len + 1];

        match icmp_type {
            8 => info!("   🏓 ICMP Echo Request (Ping) - Code: {}", icmp_code),
            0 => info!("   🏓 ICMP Echo Reply (Pong) - Code: {}", icmp_code),
            _ => info!("   🔔 ICMP Type: {}, Code: {}", icmp_type, icmp_code),
        }
    }

    async fn parse_tcp_packet(&self, packet: &[u8], ip_header_len: usize) {
        if packet.len() < ip_header_len + 20 {
            return;
        }

        let src_port = u16::from_be_bytes([packet[ip_header_len], packet[ip_header_len + 1]]);
        let dst_port = u16::from_be_bytes([packet[ip_header_len + 2], packet[ip_header_len + 3]]);
        let flags = packet[ip_header_len + 13];

        let mut flag_str = String::new();
        if flags & 0x02 != 0 {
            flag_str.push_str("SYN ");
        }
        if flags & 0x10 != 0 {
            flag_str.push_str("ACK ");
        }
        if flags & 0x01 != 0 {
            flag_str.push_str("FIN ");
        }
        if flags & 0x04 != 0 {
            flag_str.push_str("RST ");
        }

        info!(
            "   🌐 TCP: {}:{} -> {}:{} [{}]",
            src_port,
            dst_port,
            src_port,
            dst_port,
            flag_str.trim()
        );
    }

    async fn parse_udp_packet(&self, packet: &[u8], ip_header_len: usize) {
        if packet.len() < ip_header_len + 8 {
            return;
        }

        let src_port = u16::from_be_bytes([packet[ip_header_len], packet[ip_header_len + 1]]);
        let dst_port = u16::from_be_bytes([packet[ip_header_len + 2], packet[ip_header_len + 3]]);
        let length = u16::from_be_bytes([packet[ip_header_len + 4], packet[ip_header_len + 5]]);

        info!(
            "   📡 UDP: {}:{} -> {}:{} (Length: {})",
            src_port, dst_port, src_port, dst_port, length
        );
    }
}

// Writer task
async fn writer_loop(tun: Arc<Tun>, mut rx: Receiver<Vec<u8>>) {
    while let Some(packet) = rx.recv().await {
        print_packet_hex(&packet);
        match tun.send(&packet).await {
            Ok(n) => debug!("Wrote {} bytes to TUN", n),
            Err(e) => error!("Failed to write to TUN: {}", e),
        }
    }
}

fn print_packet_hex(packet: &[u8]) {
    for (i, chunk) in packet.chunks(16).enumerate() {
        print!("{:04x}: ", i * 16);

        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        for j in chunk.len()..16 {
            print!("   ");
            if j == 7 {
                print!(" ");
            }
        }

        print!(" |");

        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }

        println!("|");
    }
    println!();
}

fn create_ping_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // IP Header
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&(28u16).to_be_bytes());
    packet.extend_from_slice(&(0x1234u16).to_be_bytes());
    packet.extend_from_slice(&(0x4000u16).to_be_bytes());
    packet.push(64);
    packet.push(1);
    packet.extend_from_slice(&(0u16).to_be_bytes());
    packet.extend_from_slice(&[10, 20, 30, 41]);
    packet.extend_from_slice(&[172, 30, 12, 5]);

    let checksum = calculate_checksum(&packet[0..20]);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;

    // ICMP Header
    packet.push(8);
    packet.push(0);
    packet.extend_from_slice(&(0u16).to_be_bytes());
    packet.extend_from_slice(&(0x1234u16).to_be_bytes());
    packet.extend_from_slice(&(0x0001u16).to_be_bytes());

    let icmp_checksum = calculate_checksum(&packet[20..]);
    packet[22] = (icmp_checksum >> 8) as u8;
    packet[23] = (icmp_checksum & 0xFF) as u8;

    packet
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
