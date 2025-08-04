mod args;
mod tun_device;

use args::Config;
use tun_device::TunDevice;
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

    info!("Starting QUICAP TUN device...");
    info!("TUN Interface: {}", config.tun_name);
    info!("IP Address: {}", config.tun_ip);
    info!("Netmask: {}", config.tun_netmask);

    // Create and configure TUN device
    let tun_device = match TunDevice::new(&config.tun_name, config.tun_ip, config.tun_netmask).await {
        Ok(device) => device,
        Err(e) => {
            error!("Failed to create TUN device: {}", e);
            error!("Note: You may need to run this program with sudo privileges");
            return Err(e.into());
        }
    };

    info!("✅ TUN device created successfully!");
    info!("You can now send packets to {} to see them captured", config.tun_ip);
    info!("Try: ping {}", config.tun_ip);

    // Start packet processing
    if let Err(e) = tun_device.run(config.verbose).await {
        error!("Error running TUN device: {}", e);
        return Err(e.into());
    }

    Ok(())
}
