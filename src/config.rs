use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_cold_wait")]
    pub cold_wait_ms: u64,
    #[serde(default = "default_iranian_timeout")]
    pub iranian_timeout_ms: u64,
    #[serde(default = "default_recursion_timeout")]
    pub recursion_timeout_ms: u64,
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout_ms: u64,
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:53".parse().unwrap()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("data")
}
fn default_cold_wait() -> u64 {
    2500
}
fn default_iranian_timeout() -> u64 {
    800
}
fn default_recursion_timeout() -> u64 {
    2000
}
fn default_probe_timeout() -> u64 {
    800
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            data_dir: default_data_dir(),
            cold_wait_ms: default_cold_wait(),
            iranian_timeout_ms: default_iranian_timeout(),
            recursion_timeout_ms: default_recursion_timeout(),
            probe_timeout_ms: default_probe_timeout(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Self {
        let text = fs::read_to_string(path).unwrap_or_else(|error| {
            tracing::warn!(%error, path, "config file missing, using defaults");
            String::new()
        });
        if text.trim().is_empty() {
            return Self::default();
        }
        toml::from_str(&text).unwrap_or_else(|error| {
            tracing::warn!(%error, path, "config parse failed, using defaults");
            Self::default()
        })
    }

    pub fn cold_wait(&self) -> Duration {
        Duration::from_millis(self.cold_wait_ms)
    }

    pub fn probe_timeout(&self) -> Duration {
        Duration::from_millis(self.probe_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_listen_address_comes_from_the_file() {
        let config: Config = toml::from_str("listen = \"192.0.2.1:53\"\n").unwrap();
        assert_eq!(config.listen, "192.0.2.1:53".parse().unwrap());
        assert_eq!(config.recursion_timeout_ms, 2000);
    }
}
