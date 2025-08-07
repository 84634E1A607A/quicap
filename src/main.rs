mod args;
mod quic;
mod tun_device;

use args::Config;
use clap::Parser;
use quic::{QuicClient, QuicServer};
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tun_device::TunDevice;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(debug_assertions)]
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::DEBUG.into())
        .from_env()?;
    #[cfg(not(debug_assertions))]
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();
    let config = Config::parse();

    debug!("Configuration: {config:?}");

    // Create channels for packet forwarding
    let (tun_to_quic_tx, tun_to_quic_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let (client_rx_tx, client_rx_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let (server_rx_tx, server_rx_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    // Start TUN device in background
    let mut tun_device =
        match TunDevice::new(&config.tun_name, config.tun_ip, config.tun_netmask).await {
            Ok(device) => device,
            Err(e) => {
                error!("Failed to create TUN device: {e}");
                error!("Note: You may need to run this program with sudo privileges");
                return Err(e.into());
            }
        };

    // Set up packet forwarding from TUN to QUIC
    tun_device.set_packet_forwarder(tun_to_quic_tx.clone());
    let tun_injector = tun_device.get_packet_injector();

    info!("✅ TUN device created successfully!");
    info!("TUN Interface: {}", config.tun_name);
    info!("IP Address: {}", config.tun_ip);
    info!("Netmask: {}", config.tun_netmask);

    // Start TUN device processing in background
    tokio::spawn(async move {
        if let Err(e) = tun_device.run().await {
            error!("Error running TUN device: {e}");
        }
    });

    // Start QUIC mode based on configuration
    let listen_addr = std::net::SocketAddr::new(config.listen_ip.into(), config.listen_port);
    let target_addr = std::net::SocketAddr::new(config.target_ip.into(), config.target_port);

    if config.server_only {
        info!("🚀 Starting QUIC in server-only mode");
        info!("   Server listening on: {listen_addr}");
    } else {
        info!("🚀 Starting QUIC in both server and client mode");
        info!("   Server listening on: {listen_addr}");
        info!("   Client connecting to: {target_addr}");
    }

    // Start server in background
    let server_task = {
        let mut server = QuicServer::new(
            listen_addr,
            &config.cert_file,
            &config.key_file,
            config.ca_cert.as_deref(),
            config.conn_id_len,
        )
        .await?;
        server.set_tun_injector(tun_injector.clone());
        server.set_packet_receiver(server_rx_rx);
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("Server error: {e}");
            }
        })
    };

    // Start client in background (only if not server-only mode)
    let client_task = if !config.server_only {
        let target_addr_clone = target_addr;
        let ca_cert_clone = config.ca_cert.clone();
        let client_cert_clone = config.cert_file.clone();
        let client_key_clone = config.key_file.clone();
        let conn_id_len = config.conn_id_len;
        let tun_injector_clone = tun_injector.clone();
        let max_retry_delay = Duration::from_secs(config.max_retry_delay);
        let auto_retry = config.no_client_auto_retry;
        let max_retries = config.client_max_retries;

        Some(tokio::spawn(async move {
            let mut retry_count = 0;
            let mut retry_delay = Duration::from_secs(1); // Start with 1 second delay
            let mut packet_rx = Some(client_rx_rx);

            loop {
                // Create a new client instance for each attempt
                match QuicClient::new(
                    target_addr_clone,
                    ca_cert_clone.as_deref(),
                    Some(client_cert_clone.as_str()),
                    Some(client_key_clone.as_str()),
                    conn_id_len,
                )
                .await
                {
                    Ok(mut client) => {
                        client.set_tun_injector(tun_injector_clone.clone());
                        if let Some(rx) = packet_rx.take() {
                            client.set_packet_receiver(rx);
                        }

                        if retry_count > 0 {
                            info!("🔄 Client reconnected successfully after {retry_count} retries");
                        }

                        // Run the client
                        match client.run().await {
                            Err(e) => {
                                error!("Client error: {e}");

                                if !auto_retry {
                                    error!("Auto-retry disabled, client will not reconnect");
                                    break;
                                }

                                retry_count += 1;

                                if max_retries > 0 && retry_count > max_retries {
                                    error!(
                                        "Maximum retry attempts ({max_retries}) exceeded, giving up"
                                    );
                                    break;
                                }

                                warn!(
                                    "🔄 Client connection failed (attempt {retry_count}), retrying in {retry_delay:?}..."
                                );
                                tokio::time::sleep(retry_delay).await;

                                // Exponential backoff with jitter, max MAX_RETRY_DELAY
                                retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
                            }
                            Ok(_) => {
                                // Client exited normally (connection closed gracefully)
                                if auto_retry {
                                    warn!("Client connection closed, attempting to reconnect...");
                                    retry_count += 1;

                                    if max_retries > 0 && retry_count > max_retries {
                                        error!(
                                            "Maximum retry attempts ({max_retries}) exceeded, giving up"
                                        );
                                        break;
                                    }

                                    tokio::time::sleep(retry_delay).await;
                                    retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to create client: {e}");

                        if !auto_retry {
                            break;
                        }

                        retry_count += 1;

                        if max_retries > 0 && retry_count > max_retries {
                            error!("Maximum retry attempts ({max_retries}) exceeded, giving up");
                            break;
                        }

                        warn!(
                            "🔄 Client creation failed (attempt {retry_count}), retrying in {retry_delay:?}..."
                        );
                        tokio::time::sleep(retry_delay).await;
                        retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
                    }
                }
            }
        }))
    } else {
        None
    };

    // Start packet forwarding task
    let forwarding_task = {
        let client_tx = client_rx_tx;
        let server_tx = server_rx_tx;
        let mut tun_rx = tun_to_quic_rx;
        let server_only = config.server_only;

        tokio::spawn(async move {
            while let Some(packet) = tun_rx.recv().await {
                if server_only {
                    // Server-only mode: send all packets to server
                    if let Err(e) = server_tx.try_send(packet) {
                        error!("Failed to forward packet to server: {e}");
                    } else {
                        debug!("✅ Forwarded packet via server (server-only mode)");
                    }
                } else {
                    // Both client and server mode: try client first (preferred path)
                    if client_tx.try_send(packet.clone()).is_err() {
                        // Client channel full or closed, try server
                        if let Err(e) = server_tx.try_send(packet) {
                            error!("Failed to forward packet to both client and server: {e}");
                        } else {
                            debug!("✅ Forwarded packet via server (client unavailable)");
                        }
                    } else {
                        debug!("✅ Forwarded packet via client (preferred)");
                    }
                }
            }
        })
    };

    // Wait for all tasks to complete (they should run indefinitely)
    if let Some(client_task) = client_task {
        tokio::select! {
            _ = server_task => {
                error!("Server task completed unexpectedly");
            }
            _ = client_task => {
                error!("Client task completed unexpectedly");
            }
            _ = forwarding_task => {
                error!("Forwarding task completed unexpectedly");
            }
        }
    } else {
        tokio::select! {
            _ = server_task => {
                error!("Server task completed unexpectedly");
            }
            _ = forwarding_task => {
                error!("Forwarding task completed unexpectedly");
            }
        }
    }

    Ok(())
}
