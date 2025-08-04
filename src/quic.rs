use log::{error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time;

pub struct QuicServer {
    socket: Arc<UdpSocket>,
    config: quiche::Config,
    connections: HashMap<SocketAddr, quiche::Connection>,
    conn_id_len: u8,
    tun_injector: Option<Sender<Vec<u8>>>,
    packet_rx: Option<Receiver<Vec<u8>>>,
    last_activity: HashMap<SocketAddr, std::time::Instant>,
}

impl QuicServer {
    pub async fn new(
        listen_addr: SocketAddr,
        cert_file: &str,
        key_file: &str,
        ca_cert: Option<&str>,
        conn_id_len: u8,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("[SERVER] QUIC server listening on {listen_addr}");

        let mut config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(std::io::Error::other)?;

        // Server configuration - try to load certificates
        if let Err(e) = config.load_cert_chain_from_pem_file(cert_file) {
            warn!("[SERVER] Could not load {cert_file}: {e}");
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Server certificate not found. Please ensure {cert_file} exists."),
            ));
        }

        if let Err(e) = config.load_priv_key_from_pem_file(key_file) {
            warn!("[SERVER] Could not load {key_file}: {e}");
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Server private key not found. Please ensure {key_file} exists."),
            ));
        }

        config
            .set_application_protos(&[b"quicap"])
            .map_err(std::io::Error::other)?;

        // Configure mutual TLS if CA certificate is provided
        if let Some(ca_path) = ca_cert {
            if let Err(e) = config.load_verify_locations_from_file(ca_path) {
                warn!("[SERVER] Could not load CA certificate from {ca_path}: {e}");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("CA certificate not found. Please ensure {ca_path} exists."),
                ));
            }
            config.verify_peer(true);
            info!("[SERVER] Enabled mutual TLS with CA certificate from {ca_path}");
        } else {
            config.verify_peer(false);
            info!("[SERVER] Mutual TLS disabled - no CA certificate provided");
        }

        config.set_max_idle_timeout(30000);
        config.set_max_recv_udp_payload_size(1400);
        config.set_max_send_udp_payload_size(1400);
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
            conn_id_len,
            tun_injector: None,
            packet_rx: None,
            last_activity: HashMap::new(),
        })
    }

    pub fn set_tun_injector(&mut self, tun_injector: Sender<Vec<u8>>) {
        self.tun_injector = Some(tun_injector);
    }

    pub fn set_packet_receiver(&mut self, packet_rx: Receiver<Vec<u8>>) {
        self.packet_rx = Some(packet_rx);
    }

    pub async fn run(&mut self) -> std::io::Result<()> {
        let mut buf = [0; 1500];
        let mut out_buf = [0; 1500];
        let mut packet_rx = self.packet_rx.take();

        loop {
            tokio::select! {
                // Handle incoming packets
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from)) => {
                            self.handle_packet(&mut buf[..len], from, &mut out_buf).await?;
                        }
                        Err(e) => {
                            error!("[SERVER] Error receiving packet: {e}");
                        }
                    }
                }

                // Handle packets from TUN device to forward via QUIC
                packet = async {
                    match &mut packet_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(tun_packet) = packet {
                        self.forward_tun_packet_via_datagram(&tun_packet, &mut out_buf).await?;
                    }
                }

                // Handle connection timeouts and send periodic pings
                _ = time::sleep(Duration::from_millis(100)) => {
                    self.handle_timeouts(&mut out_buf).await?;
                }
            }
        }
    }

    async fn handle_packet(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        out_buf: &mut [u8; 1500],
    ) -> std::io::Result<()> {
        let hdr = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(_) => return Ok(()),
        };

        // Update activity timestamp for this connection
        self.last_activity.insert(from, std::time::Instant::now());

        // Check if we have an existing connection for this address
        if let std::collections::hash_map::Entry::Vacant(entry) = self.connections.entry(from) {
            // Only create new connections for Initial packets
            if hdr.ty != quiche::Type::Initial {
                warn!("[SERVER] Non-initial packet for unknown connection from {from}");
                return Ok(());
            }

            // Create new connection for initial packet
            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            let scid_len = self.conn_id_len.min(quiche::MAX_CONN_ID_LEN as u8) as usize;
            // Generate a random SCID with lowercase letters only
            scid.iter_mut()
                .take(scid_len)
                .for_each(|x| *x = b'a' + (rand::random::<u8>() % 26));
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
                    error!("[SERVER] Failed to accept connection from {from}: {e}");
                    return Ok(());
                }
            };

            info!("[SERVER] New QUIC connection from {from}");
            entry.insert(conn);
        }

        let conn = self.connections.get_mut(&from).unwrap();

        let recv_info = quiche::RecvInfo {
            to: self.socket.local_addr()?,
            from,
        };

        match conn.recv(packet, recv_info) {
            Ok(_) => {}
            Err(quiche::Error::Done) => {}
            Err(e) => {
                error!("[SERVER] Error processing packet from {from}: {e}");
                return Ok(());
            }
        }

        // Check for datagrams
        let mut dgram_buf = [0; 1500];
        loop {
            match conn.dgram_recv(&mut dgram_buf) {
                Ok(len) => {
                    info!("[SERVER] 📨 Received DATAGRAM from {from}: {len} bytes");
                    if self.tun_injector.is_some() {
                        // Inject datagram into TUN device
                        if let Some(ref tun_injector) = self.tun_injector {
                            let packet = dgram_buf[..len].to_vec();
                            if let Err(e) = tun_injector.send(packet).await {
                                error!("[SERVER] Failed to inject packet into TUN: {e}");
                            }
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("[SERVER] Error receiving datagram: {e}");
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
                    error!("[SERVER] Error sending packet: {e}");
                    break;
                }
            };

            if let Err(e) = self.socket.send_to(&out_buf[..written], send_info.to).await {
                error!(
                    "[SERVER] Error sending UDP packet to {}: {}",
                    send_info.to, e
                );
            }
        }

        Ok(())
    }

    async fn handle_timeouts(&mut self, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        let mut to_remove = Vec::new();
        let keep_alive_interval = Duration::from_secs(10); // Send PING every 10 seconds if idle

        for (&addr, conn) in &mut self.connections {
            // Only call on_timeout if there's actually a timeout to handle
            if let Some(_timeout) = conn.timeout() {
                conn.on_timeout();
            }

            if conn.is_closed() {
                to_remove.push(addr);
                continue;
            }

            // Send keep-alive PING if connection is established and has been idle
            if conn.is_established() {
                if let Some(last_activity) = self.last_activity.get(&addr) {
                    if last_activity.elapsed() >= keep_alive_interval
                        && conn.send_ack_eliciting().is_ok()
                    {
                        // Update activity time to prevent immediate resending
                        self.last_activity.insert(addr, std::time::Instant::now());
                    }
                }
            }

            // Send any pending packets
            loop {
                let (written, send_info) = match conn.send(out_buf) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("[SERVER] Error sending timeout packet: {e}");
                        break;
                    }
                };

                if let Err(e) = self.socket.send_to(&out_buf[..written], send_info.to).await {
                    error!("[SERVER] Error sending timeout UDP packet: {e}");
                }
            }
        }

        for addr in to_remove {
            info!("[SERVER] Removing closed connection from {addr}");
            self.connections.remove(&addr);
            self.last_activity.remove(&addr);
        }

        Ok(())
    }

    async fn forward_tun_packet_via_datagram(
        &mut self,
        packet: &[u8],
        out_buf: &mut [u8; 1500],
    ) -> std::io::Result<()> {
        let mut sent_any = false;

        // Try to send via all established connections
        for (&addr, conn) in &mut self.connections {
            if conn.is_established() {
                match conn.dgram_send(packet) {
                    Ok(_) => {
                        info!(
                            "[SERVER] 📤 Forwarded {} bytes via DATAGRAM to {}",
                            packet.len(),
                            addr
                        );
                        sent_any = true;

                        // Update activity timestamp since we're sending data
                        self.last_activity.insert(addr, std::time::Instant::now());

                        // Send any resulting packets
                        loop {
                            let (written, send_info) = match conn.send(out_buf) {
                                Ok(v) => v,
                                Err(quiche::Error::Done) => break,
                                Err(e) => {
                                    error!("[SERVER] Error sending datagram packet: {e}");
                                    break;
                                }
                            };

                            if let Err(e) =
                                self.socket.send_to(&out_buf[..written], send_info.to).await
                            {
                                error!("[SERVER] Error sending UDP packet: {e}");
                            }
                        }
                    }
                    Err(_) => {
                        // Cannot send datagram to this connection
                    }
                }
            }
        }

        if !sent_any {
            // No established connections available to forward packet
        }

        Ok(())
    }
}

pub struct QuicClient {
    socket: Arc<UdpSocket>,
    connection: quiche::Connection,
    server_addr: SocketAddr,
    connection_established_logged: bool,
    #[allow(dead_code)]
    conn_id_len: u8,
    tun_injector: Option<Sender<Vec<u8>>>,
    packet_rx: Option<Receiver<Vec<u8>>>,
}

impl QuicClient {
    pub async fn new(
        server_addr: SocketAddr,
        ca_cert: Option<&str>,
        client_cert: Option<&str>,
        client_key: Option<&str>,
        conn_id_len: u8,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        info!("QUIC client connecting to {server_addr}");

        let mut config =
            quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(std::io::Error::other)?;
        config
            .set_application_protos(&[b"quicap"])
            .map_err(std::io::Error::other)?;
        config.set_max_idle_timeout(30000);
        config.set_max_recv_udp_payload_size(1400);
        config.set_max_send_udp_payload_size(1400);
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
                warn!("Could not load CA certificate from {ca_path}: {e}");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("CA certificate not found. Please ensure {ca_path} exists."),
                ));
            }
            config.verify_peer(true);
            info!("Using CA certificate from {ca_path} for peer verification");
        } else {
            config.verify_peer(false); // Allow cert errors when no CA is specified
            warn!("No CA certificate specified, disabling peer verification");
        }

        // Configure client certificate for mutual TLS
        if let (Some(cert_path), Some(key_path)) = (client_cert, client_key) {
            if let Err(e) = config.load_cert_chain_from_pem_file(cert_path) {
                warn!("Could not load client certificate from {cert_path}: {e}");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Client certificate not found. Please ensure {cert_path} exists."),
                ));
            }

            if let Err(e) = config.load_priv_key_from_pem_file(key_path) {
                warn!("Could not load client private key from {key_path}: {e}");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Client private key not found. Please ensure {key_path} exists."),
                ));
            }

            info!("Configured client certificate for mutual TLS");
        } else {
            info!("No client certificate specified - using server-only TLS");
        }

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let scid_len = conn_id_len.min(quiche::MAX_CONN_ID_LEN as u8) as usize;
        // Generate a random SCID with lowercase letters only
        scid.iter_mut()
            .take(scid_len)
            .for_each(|x| *x = b'a' + (rand::random::<u8>() % 26));
        let scid = quiche::ConnectionId::from_ref(&scid[..scid_len]);

        let local_addr = socket.local_addr()?;
        let connection = quiche::connect(None, &scid, local_addr, server_addr, &mut config)
            .map_err(std::io::Error::other)?;
        Ok(Self {
            socket: Arc::new(socket),
            connection,
            server_addr,
            connection_established_logged: false,
            conn_id_len,
            tun_injector: None,
            packet_rx: None,
        })
    }

    pub fn set_tun_injector(&mut self, tun_injector: Sender<Vec<u8>>) {
        self.tun_injector = Some(tun_injector);
    }

    pub fn set_packet_receiver(&mut self, packet_rx: Receiver<Vec<u8>>) {
        self.packet_rx = Some(packet_rx);
    }

    pub async fn run(&mut self) -> std::io::Result<()> {
        let mut buf = [0; 1500];
        let mut out_buf = [0; 1500];
        let mut packet_rx = self.packet_rx.take();
        let mut last_activity = std::time::Instant::now();
        let keep_alive_interval = Duration::from_secs(10); // Send PING every 10 seconds if idle

        // Initial handshake
        self.send_initial_packets(&mut out_buf).await?;

        loop {
            // Get the next timeout from the connection, or use a default
            let timeout_duration = self
                .connection
                .timeout()
                .unwrap_or(Duration::from_millis(25));

            tokio::select! {
                // Handle incoming packets
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from)) => {
                            if from == self.server_addr {
                                last_activity = std::time::Instant::now();
                                self.handle_packet(&mut buf[..len], &mut out_buf).await?;
                            }
                        }
                        Err(e) => {
                            error!("Error receiving packet: {e}");
                        }
                    }
                }

                // Handle packets from TUN device to forward via QUIC (preferred path)
                packet = async {
                    match &mut packet_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(tun_packet) = packet {
                        last_activity = std::time::Instant::now();
                        self.forward_tun_packet_via_datagram(&tun_packet, &mut out_buf).await?;
                    }
                }

                // Handle connection timeouts and keep-alive pings
                _ = time::sleep(timeout_duration) => {
                    self.handle_timeout(&mut out_buf).await?;

                    // Send keep-alive PING if we've been idle too long
                    if self.connection.is_established() && last_activity.elapsed() >= keep_alive_interval {
                        self.send_ping_frame(&mut out_buf).await?;
                        last_activity = std::time::Instant::now();
                    }
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
                    error!("Error sending initial packet: {e}");
                    return Err(std::io::Error::other(e));
                }
            };

            self.socket
                .send_to(&out_buf[..written], send_info.to)
                .await?;
        }
        Ok(())
    }

    async fn handle_packet(
        &mut self,
        packet: &mut [u8],
        out_buf: &mut [u8; 1500],
    ) -> std::io::Result<()> {
        let recv_info = quiche::RecvInfo {
            to: self.socket.local_addr()?,
            from: self.server_addr,
        };

        match self.connection.recv(packet, recv_info) {
            Ok(_) => {}
            Err(quiche::Error::Done) => {}
            Err(e) => {
                error!("Error processing packet: {e}");
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
                    info!("[CLIENT] 📨 Received DATAGRAM from server: {len} bytes");
                    if self.tun_injector.is_some() {
                        // Inject datagram into TUN device
                        if let Some(ref tun_injector) = self.tun_injector {
                            let packet = dgram_buf[..len].to_vec();
                            if let Err(e) = tun_injector.send(packet).await {
                                error!("[CLIENT] Failed to inject packet into TUN: {e}");
                            }
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Error receiving datagram: {e}");
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
                    error!("Error sending packet: {e}");
                    break;
                }
            };

            self.socket
                .send_to(&out_buf[..written], send_info.to)
                .await?;
        }

        Ok(())
    }

    async fn send_ping_frame(&mut self, out_buf: &mut [u8; 1500]) -> std::io::Result<()> {
        match self.connection.send_ack_eliciting() {
            Ok(_) => {
                info!("🏓 Sent PING frame to server");

                // Send any resulting packets containing the PING frame
                loop {
                    let (written, send_info) = match self.connection.send(out_buf) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            error!("Error sending PING packet: {e}");
                            break;
                        }
                    };

                    self.socket
                        .send_to(&out_buf[..written], send_info.to)
                        .await?;
                }
            }
            Err(_) => {
                // Failed to send PING frame
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
                        error!("Error sending timeout packet: {e}");
                        break;
                    }
                };

                self.socket
                    .send_to(&out_buf[..written], send_info.to)
                    .await?;
            }
        }

        Ok(())
    }

    async fn forward_tun_packet_via_datagram(
        &mut self,
        packet: &[u8],
        out_buf: &mut [u8; 1500],
    ) -> std::io::Result<()> {
        if self.connection.is_established() {
            match self.connection.dgram_send(packet) {
                Ok(_) => {
                    info!(
                        "[CLIENT] 📤 Forwarded {} bytes via DATAGRAM to server",
                        packet.len()
                    );

                    // Send any resulting packets
                    loop {
                        let (written, send_info) = match self.connection.send(out_buf) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => break,
                            Err(e) => {
                                error!("[CLIENT] Error sending datagram packet: {e}");
                                break;
                            }
                        };

                        self.socket
                            .send_to(&out_buf[..written], send_info.to)
                            .await?;
                    }
                }
                Err(_) => {
                    // Cannot send datagram
                }
            }
        } else {
            // Connection not established, cannot forward packet
        }

        Ok(())
    }
}
