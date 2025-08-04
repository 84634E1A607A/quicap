use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;

pub struct QuicServer {
    socket: Arc<UdpSocket>,
    config: quiche::Config,
    connections: HashMap<SocketAddr, quiche::Connection>,
}

impl QuicServer {
    pub async fn new(listen_addr: SocketAddr, cert_file: &str, key_file: &str) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("[SERVER] QUIC server listening on {}", listen_addr);

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        // Server configuration - try to load certificates
        if let Err(e) = config.load_cert_chain_from_pem_file(cert_file) {
            warn!("[SERVER] Could not load {}: {}", cert_file, e);
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, 
                format!("Server certificate not found. Please ensure {} exists.", cert_file)));
        }
        
        if let Err(e) = config.load_priv_key_from_pem_file(key_file) {
            warn!("[SERVER] Could not load {}: {}", key_file, e);
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, 
                format!("Server private key not found. Please ensure {} exists.", key_file)));
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
                            error!("[SERVER] Error receiving packet: {}", e);
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
                debug!("[SERVER] Invalid packet header from {}: {}", from, e);
                return Ok(());
            }
        };

        // Check if we have an existing connection for this address
        if !self.connections.contains_key(&from) {
            // Only create new connections for Initial packets
            if hdr.ty != quiche::Type::Initial {
                debug!("[SERVER] Non-initial packet for unknown connection from {}", from);
                return Ok(());
            }

            // Create new connection for initial packet
            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            let scid_len = 16;
            // Generate a random SCID instead of using a predictable counter
            scid[..scid_len].iter_mut().for_each(|b| *b = rand::random::<u8>());
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
                    error!("[SERVER] Failed to accept connection from {}: {}", from, e);
                    return Ok(());
                }
            };

            info!("[SERVER] New QUIC connection from {}", from);
            self.connections.insert(from, conn);
        }

        let conn = self.connections.get_mut(&from).unwrap();

        let recv_info = quiche::RecvInfo { 
            to: self.socket.local_addr()?,
            from 
        };
        
        match conn.recv(packet, recv_info) {
            Ok(_) => {
                debug!("[SERVER] Processed packet from {}", from);
            }
            Err(quiche::Error::Done) => {
                debug!("[SERVER] No more data to process from {}", from);
            }
            Err(e) => {
                error!("[SERVER] Error processing packet from {}: {}", from, e);
                return Ok(());
            }
        }

        // Check for datagrams
        let mut dgram_buf = [0; 1500];
        loop {
            match conn.dgram_recv(&mut dgram_buf) {
                Ok(len) => {
                    info!("[SERVER] 📨 Received DATAGRAM from {}: {} bytes", from, len);
                    print_datagram_hex(&dgram_buf[..len]);
                    
                    // Send ping response
                    let ping_data = b"PONG from server";
                    match conn.dgram_send(ping_data) {
                        Ok(_) => {
                            info!("[SERVER] 🏓 Sent PONG datagram to {}", from);
                        }
                        Err(e) => {
                            error!("[SERVER] Failed to send PONG datagram: {}", e);
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("[SERVER] Error receiving datagram: {}", e);
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
                    error!("[SERVER] Error sending packet: {}", e);
                    break;
                }
            };

            if let Err(e) = self.socket.send_to(&out_buf[..written], send_info.to).await {
                error!("[SERVER] Error sending UDP packet to {}: {}", send_info.to, e);
            }
        }

        Ok(())
    }

    async fn handle_timeouts(&mut self, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        let mut to_remove = Vec::new();

        for (&addr, conn) in &mut self.connections {
            // Only call on_timeout if there's actually a timeout to handle
            if let Some(_timeout) = conn.timeout() {
                conn.on_timeout();
            }

            if conn.is_closed() {
                to_remove.push(addr);
                continue;
            }

            // Send any pending packets
            loop {
                let (written, send_info) = match conn.send(out_buf) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("[SERVER] Error sending timeout packet: {}", e);
                        break;
                    }
                };

                if let Err(e) = self.socket.send_to(&out_buf[..written], send_info.to).await {
                    error!("[SERVER] Error sending timeout UDP packet: {}", e);
                }
            }
        }

        for addr in to_remove {
            info!("[SERVER] Removing closed connection from {}", addr);
            self.connections.remove(&addr);
        }

        Ok(())
    }
}

pub struct QuicClient {
    socket: Arc<UdpSocket>,
    connection: quiche::Connection,
    server_addr: SocketAddr,
    connection_established_logged: bool,
}

impl QuicClient {
    pub async fn new(server_addr: SocketAddr, ca_cert: Option<&str>) -> std::io::Result<Self> {
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
        config.enable_dgram(true, 6000, 6000);
        
        // Configure certificate verification
        if let Some(ca_path) = ca_cert {
            if let Err(e) = config.load_verify_locations_from_file(ca_path) {
                warn!("Could not load CA certificate from {}: {}", ca_path, e);
                return Err(std::io::Error::new(std::io::ErrorKind::NotFound, 
                    format!("CA certificate not found. Please ensure {} exists.", ca_path)));
            }
            config.verify_peer(true);
            info!("Using CA certificate from {} for peer verification", ca_path);
        } else {
            config.verify_peer(false); // Allow cert errors when no CA is specified
            warn!("No CA certificate specified, disabling peer verification");
        }

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
            connection_established_logged: false,
        })
    }

    pub async fn run(&mut self) -> std::io::Result<()> {
        let mut buf = [0; 1500];
        let mut out_buf = [0; 1500];
        let mut ping_timer = time::interval(Duration::from_secs(5));

        // Initial handshake
        self.send_initial_packets(&mut out_buf).await?;

        loop {
            // Get the next timeout from the connection, or use a default
            let timeout_duration = self.connection.timeout()
                .unwrap_or(Duration::from_millis(25));

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
                _ = time::sleep(timeout_duration) => {
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

        if self.connection.is_established() && !self.connection_established_logged {
            info!("🎉 QUIC connection established!");
            self.connection_established_logged = true;
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
                
                // Actually send the packets containing the datagram
                let mut out_buf = [0; 1500];
                loop {
                    let (written, send_info) = match self.connection.send(&mut out_buf) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            error!("Error sending datagram packet: {}", e);
                            break;
                        }
                    };

                    self.socket.send_to(&out_buf[..written], send_info.to).await?;
                }
            }
            Err(e) => {
                error!("Failed to send PING datagram: {}", e);
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        // Only call on_timeout if there's actually a timeout to handle
        if let Some(_timeout) = self.connection.timeout() {
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
        }

        Ok(())
    }
}

fn print_datagram_hex(data: &[u8]) {
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
