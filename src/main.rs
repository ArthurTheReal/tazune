mod byte_buffer;
mod dns;
mod errors;
mod server;

use errors::TazuneError;
use server::{proxy_server};


fn main() -> Result<(), TazuneError> {
    let upstream_addr = ("8.8.8.8", 53);
    let listen_addr = ("0.0.0.0", 10053);

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    proxy_server(upstream_addr, listen_addr)?;
    Ok(())
}
