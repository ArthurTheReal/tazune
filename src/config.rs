use crate::errors::TazuneError;

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1053))
}

fn default_cache_size() -> usize {
    10_000
}

// Mirrors config.toml. Unknown keys are rejected so a typo like "upstream = [...]"
// fails loudly instead of being silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address and port the server listens on.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// Upstream resolvers, as IP:port. Queries are spread across them and a
    /// failing resolver is skipped in favour of the next one.
    pub upstreams: Vec<SocketAddr>,

    /// Most answers kept in the cache at once. 0 turns caching off.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, TazuneError> {
        let text = std::fs::read_to_string(path).map_err(|source| TazuneError::ConfigRead {
            path: path.display().to_string(),
            source,
        })?;

        let config: Config = toml::from_str(&text).map_err(|source| TazuneError::ConfigParse {
            path: path.display().to_string(),
            source,
        })?;

        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<(), TazuneError> {
        if self.upstreams.is_empty() {
            return Err(TazuneError::NoUpstreams);
        }

        Ok(())
    }
}