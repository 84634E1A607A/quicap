mod args;
mod tun_device;
mod quic;

use args::Config;
use tun_device::TunDevice;
use quic::{QuicServer, QuicClient};
use clap::Parser;
use log::{info, debug, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use env_logger for logging at DEBUG
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();
    
    let config = Config::parse();
    
    // Initialize logger based on verbosity
    if config.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    } else {
        log::set_max_level(log::LevelFilter::Info);
    }
    
    debug!("Configuration: {:?}", config);

    // Start TUN device in background
    let tun_device = match TunDevice::new(&config.tun_name, config.tun_ip, config.tun_netmask).await {
        Ok(device) => device,
        Err(e) => {
            error!("Failed to create TUN device: {}", e);
            error!("Note: You may need to run this program with sudo privileges");
            return Err(e.into());
        }
    };

    info!("✅ TUN device created successfully!");
    info!("TUN Interface: {}", config.tun_name);
    info!("IP Address: {}", config.tun_ip);
    info!("Netmask: {}", config.tun_netmask);

    // Start TUN device processing in background
    let tun_verbose = config.verbose;
    tokio::spawn(async move {
        if let Err(e) = tun_device.run(tun_verbose).await {
            error!("Error running TUN device: {}", e);
        }
    });

    // Start QUIC in both server and client mode
    let listen_addr = std::net::SocketAddr::new(config.listen_ip.into(), config.listen_port);
    let target_addr = std::net::SocketAddr::new(config.target_ip.into(), config.target_port);
    
    info!("🚀 Starting QUIC in both server and client mode");
    info!("   Server listening on: {}", listen_addr);
    info!("   Client connecting to: {}", target_addr);
    
    // Start server in background
    let server_task = {
        let mut server = QuicServer::new(listen_addr, &config.cert_file, &config.key_file, config.ca_cert.as_deref(), config.conn_id_len).await?;
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("Server error: {}", e);
            }
        })
    };
    
    // Start client in background
    let client_task = {
        let mut client = QuicClient::new(target_addr, config.ca_cert.as_deref(), config.client_cert.as_deref(), config.client_key.as_deref(), config.conn_id_len).await?;
        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                error!("Client error: {}", e);
            }
        })
    };
    
    // Wait for both tasks to complete (they should run indefinitely)
    tokio::select! {
        _ = server_task => {
            error!("Server task completed unexpectedly");
        }
        _ = client_task => {
            error!("Client task completed unexpectedly");
        }
    }

    Ok(())
}
