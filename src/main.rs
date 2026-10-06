mod byte_buffer;
mod cache;
mod config;
mod dns;
mod errors;
mod server;

use std::path::PathBuf;

use config::Config;
use errors::TazuneError;
use log::{error, info};

fn run() -> Result<(), TazuneError> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let config = Config::load(&path)?;
    info!("loaded config from {}", path.display());

    server::proxy_server(config.upstreams, config.listen, config.cache_size)
}

fn main() {
    // log level comes from RUST_LOG env variable
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = run() {
        error!("{e}");
        std::process::exit(1);
    }
}
