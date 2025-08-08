mod args;
mod quic;
mod tap;

use clap::Parser;
use log::info;

use args::{Args, Config};
use tap::TapBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(debug_assertions))]
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    #[cfg(debug_assertions)]
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    let tap = {
        let args = Args::parse();
        let config = std::path::Path::new(args.config.as_str());
        info!("reading from {config:?}");
        let config = std::fs::read_to_string(config)?;
        let config: Config = toml::from_str(config.as_str())?;
        TapBuilder::with_config(config)
    };
    tokio_uring::start(async move {
        let tap = tap.build()?;
        info!("registered tap device {}", tap.name()?);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
