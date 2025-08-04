use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time;
use rand::Rng;

pub struct QuicServer {
    socket: Arc<UdpSocket>,
    config: quiche::Config,
    connections: HashMap<quiche::ConnectionId<'static>, quiche::Connection>,
    conn_id_seed: u64,
}

impl QuicServer {
    pub async fn new(listen_addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("QUIC server listening on {}", listen_addr);

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        // Server configuration - try to load certificates
        if let Err(e) = config.load_cert_chain_from_pem_file("certs/server.crt") {
            warn!("Could not load certs/server.crt: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, 
                "Server certificate not found. Please ensure certs/server.crt exists."));
        }
        
        if let Err(e) = config.load_priv_key_from_pem_file("certs/server.key") {
            warn!("Could not load certs/server.key: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, 
                "Server private key not found. Please ensure certs/server.key exists."));
        }

        config.set_application_protos(&[b"quicap"])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        config.set_max_idle_timeout(30000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_dgram(true, 1000, 1000);

        Ok(Self {
            socket: Arc::new(socket),
            config,
            connections: HashMap::new(),
            conn_id_seed: 0,
        })
    }

    pub async fn run(&mut self) -> std::io::Result<()> {
        let mut buf = [0; 1500];
        let mut out_buf = [0; 1500];

        loop {
            tokio::select! {
                // Handle incoming packets
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from)) => {
                            self.handle_packet(&mut buf[..len], from, &mut out_buf).await?;
                        }
                        Err(e) => {
                            error!("Error receiving packet: {}", e);
                        }
                    }
                }

                // Handle connection timeouts and send periodic pings
                _ = time::sleep(Duration::from_millis(100)) => {
                    self.handle_timeouts(&mut out_buf).await?;
                }
            }
        }
    }

    async fn handle_packet(&mut self, packet: &mut [u8], from: SocketAddr, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        let hdr = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(e) => {
                debug!("Invalid packet header from {}: {}", from, e);
                return Ok(());
            }
        };

        let conn_id = hdr.dcid.clone().into_owned();

        if !self.connections.contains_key(&conn_id) {
            if hdr.ty != quiche::Type::Initial {
                debug!("Non-initial packet for unknown connection from {}", from);
                return Ok(());
            }

            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            let scid_len = 16;
            self.conn_id_seed += 1;
            scid[..8].copy_from_slice(&self.conn_id_seed.to_be_bytes());
            let scid = quiche::ConnectionId::from_ref(&scid[..scid_len]);
            
            let odcid = if !hdr.dcid.is_empty() {
                Some(&hdr.dcid)
            } else {
                None
            };

            let local_addr = self.socket.local_addr()?;
            let conn = match quiche::accept(&scid, odcid, local_addr, from, &mut self.config) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept connection from {}: {}", from, e);
                    return Ok(());
                }
            };

            info!("New QUIC connection from {}", from);
            self.connections.insert(conn_id.clone(), conn);
        }

        let conn = self.connections.get_mut(&conn_id).unwrap();

        let recv_info = quiche::RecvInfo { 
            to: self.socket.local_addr()?,
            from 
        };
        
        match conn.recv(packet, recv_info) {
            Ok(_) => {
                debug!("Processed packet from {}", from);
            }
            Err(quiche::Error::Done) => {
                debug!("No more data to process from {}", from);
            }
            Err(e) => {
                error!("Error processing packet from {}: {}", from, e);
                return Ok(());
            }
        }

        // Check for datagrams
        let mut dgram_buf = [0; 1500];
        loop {
            match conn.dgram_recv(&mut dgram_buf) {
                Ok(len) => {
                    info!("📨 Received DATAGRAM from {}: {} bytes", from, len);
                    print_datagram_hex(&dgram_buf[..len]);
                    
                    // Send ping response
                    let ping_data = b"PONG from server";
                    match conn.dgram_send(ping_data) {
                        Ok(_) => {
                            info!("🏓 Sent PONG datagram to {}", from);
                        }
                        Err(e) => {
                            error!("Failed to send PONG datagram: {}", e);
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Error receiving datagram: {}", e);
                    break;
                }
            }
        }

        // Send response packets
        loop {
            let (written, send_info) = match conn.send(out_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Error sending packet: {}", e);
                    break;
                }
            };

            if let Err(e) = self.socket.send_to(&out_buf[..written], send_info.to).await {
                error!("Error sending UDP packet to {}: {}", send_info.to, e);
            }
        }

        Ok(())
    }

    async fn send_ping_datagram(&self, conn: &mut quiche::Connection, from: SocketAddr) -> std::io::Result<()> {
        let ping_data = b"PONG from server";
        match conn.dgram_send(ping_data) {
            Ok(_) => {
                info!("🏓 Sent PONG datagram to {}", from);
            }
            Err(e) => {
                error!("Failed to send PONG datagram: {}", e);
            }
        }
        Ok(())
    }

    async fn handle_timeouts(&mut self, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        let mut to_remove = Vec::new();

        for (conn_id, conn) in &mut self.connections {
            conn.on_timeout();

            if conn.is_closed() {
                to_remove.push(conn_id.clone());
                continue;
            }

            // Send any pending packets
            loop {
                let (written, send_info) = match conn.send(out_buf) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("Error sending timeout packet: {}", e);
                        break;
                    }
                };

                if let Err(e) = self.socket.send_to(&out_buf[..written], send_info.to).await {
                    error!("Error sending timeout UDP packet: {}", e);
                }
            }
        }

        for conn_id in to_remove {
            info!("Removing closed connection");
            self.connections.remove(&conn_id);
        }

        Ok(())
    }

    fn print_datagram_hex(&self, data: &[u8]) {
        for (i, chunk) in data.chunks(16).enumerate() {
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
}

pub struct QuicClient {
    socket: Arc<UdpSocket>,
    connection: quiche::Connection,
    server_addr: SocketAddr,
}

impl QuicClient {
    pub async fn new(server_addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        info!("QUIC client connecting to {}", server_addr);

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        config.set_application_protos(&[b"quicap"])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        config.set_max_idle_timeout(30000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_dgram(true, 1000, 1000);
        config.verify_peer(false); // Allow cert errors for now

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let scid_len = 16;
        scid[..8].copy_from_slice(&rand::random::<u64>().to_be_bytes());
        let scid = quiche::ConnectionId::from_ref(&scid[..scid_len]);
        
        let local_addr = socket.local_addr()?;
        let connection = quiche::connect(None, &scid, local_addr, server_addr, &mut config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(Self {
            socket: Arc::new(socket),
            connection,
            server_addr,
        })
    }

    pub async fn run(&mut self) -> std::io::Result<()> {
        let mut buf = [0; 1500];
        let mut out_buf = [0; 1500];
        let mut ping_timer = time::interval(Duration::from_secs(5));

        // Initial handshake
        self.send_initial_packets(&mut out_buf).await?;

        loop {
            tokio::select! {
                // Handle incoming packets
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from)) => {
                            if from == self.server_addr {
                                self.handle_packet(&mut buf[..len], &mut out_buf).await?;
                            }
                        }
                        Err(e) => {
                            error!("Error receiving packet: {}", e);
                        }
                    }
                }

                // Send periodic pings
                _ = ping_timer.tick() => {
                    if self.connection.is_established() {
                        self.send_ping_datagram().await?;
                    }
                }

                // Handle connection timeouts
                _ = time::sleep(Duration::from_millis(100)) => {
                    self.handle_timeout(&mut out_buf).await?;
                }
            }

            if self.connection.is_closed() {
                info!("Connection closed");
                break;
            }
        }

        Ok(())
    }

    async fn send_initial_packets(&mut self, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        loop {
            let (written, send_info) = match self.connection.send(out_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Error sending initial packet: {}", e);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                }
            };

            self.socket.send_to(&out_buf[..written], send_info.to).await?;
        }
        Ok(())
    }

    async fn handle_packet(&mut self, packet: &mut [u8], out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        let recv_info = quiche::RecvInfo { 
            to: self.socket.local_addr()?,
            from: self.server_addr 
        };
        
        match self.connection.recv(packet, recv_info) {
            Ok(_) => {
                debug!("Processed packet from server");
            }
            Err(quiche::Error::Done) => {
                debug!("No more data to process");
            }
            Err(e) => {
                error!("Error processing packet: {}", e);
                return Ok(());
            }
        }

        if self.connection.is_established() && !self.connection.is_closed() {
            info!("🎉 QUIC connection established!");
        }

        // Check for datagrams
        let mut dgram_buf = [0; 1500];
        loop {
            match self.connection.dgram_recv(&mut dgram_buf) {
                Ok(len) => {
                    info!("📨 Received DATAGRAM from server: {} bytes", len);
                    print_datagram_hex(&dgram_buf[..len]);
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Error receiving datagram: {}", e);
                    break;
                }
            }
        }

        // Send response packets
        loop {
            let (written, send_info) = match self.connection.send(out_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Error sending packet: {}", e);
                    break;
                }
            };

            self.socket.send_to(&out_buf[..written], send_info.to).await?;
        }

        Ok(())
    }

    async fn send_ping_datagram(&mut self) -> std::io::Result<()> {
        let ping_data = b"PING from client";
        match self.connection.dgram_send(ping_data) {
            Ok(_) => {
                info!("🏓 Sent PING datagram to server");
            }
            Err(e) => {
                error!("Failed to send PING datagram: {}", e);
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        self.connection.on_timeout();

        // Send any pending packets
        loop {
            let (written, send_info) = match self.connection.send(out_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Error sending timeout packet: {}", e);
                    break;
                }
            };

            self.socket.send_to(&out_buf[..written], send_info.to).await?;
        }

        Ok(())
    }

    fn print_datagram_hex(&self, data: &[u8]) {
        for (i, chunk) in data.chunks(16).enumerate() {
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
}
