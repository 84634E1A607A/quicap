use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_tun::{Tun, TunBuilder};
use tracing::{error, info};

#[derive(Clone)]
pub struct TunDevice {
    name: String,
    rx_tun: Arc<Tun>,                   // for receiving
    tx: Sender<Vec<u8>>,                // channel to send write packets
    packet_tx: Option<Sender<Vec<u8>>>, // channel to forward packets to QUIC
}

impl TunDevice {
    pub async fn new(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<Self> {
        let mut tuns = TunBuilder::new()
            .name(name)
            .address(ip)
            .netmask(netmask)
            .mtu(1350)
            .up()
            .build()
            .map_err(io::Error::other)?;

        let tun = Arc::new(
            tuns.pop()
                .ok_or_else(|| io::Error::other("Failed to create TUN interface"))?,
        );

        let rx_tun = tun.clone(); // for reading
        let tx_tun = tun; // for writing

        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel(1024);

        tokio::spawn(async move {
            writer_loop(tx_tun, rx).await;
        });

        Ok(Self {
            name: name.to_string(),
            rx_tun,
            tx,
            packet_tx: None,
        })
    }

    pub fn set_packet_forwarder(&mut self, packet_tx: Sender<Vec<u8>>) {
        self.packet_tx = Some(packet_tx);
    }

    pub fn get_packet_injector(&self) -> Sender<Vec<u8>> {
        self.tx.clone()
    }

    pub async fn run(&self) -> io::Result<()> {
        info!("TUN device {} is running. Press Ctrl+C to stop.", self.name);

        let mut buffer = [0u8; 1500]; // MTU size buffer

        loop {
            match self.rx_tun.recv(&mut buffer).await {
                Ok(n) => {
                    // Forward packet to QUIC if forwarder is available
                    if let Some(ref packet_tx) = self.packet_tx {
                        let packet = buffer[..n].to_vec();
                        if let Err(e) = packet_tx.send(packet).await {
                            error!("Failed to forward packet to QUIC: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from TUN: {e}");
                    break;
                }
            }
        }

        Ok(())
    }
}

// Writer task
async fn writer_loop(tun: Arc<Tun>, mut rx: Receiver<Vec<u8>>) {
    while let Some(packet) = rx.recv().await {
        if let Err(e) = tun.send(&packet).await {
            error!("Failed to write to TUN: {e}");
        }
    }
}
