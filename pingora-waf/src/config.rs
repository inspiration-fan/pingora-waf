use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub metrics_listen: Option<String>,
    pub http_listen: Option<String>,
    pub https_listen: Option<String>,

    /// Directory to write JSONL logs (access/events/app).
    /// Default: ./logs
    pub log_dir: Option<PathBuf>,

    pub upstream_config_path: PathBuf,
    pub upstream_hot_reload_secs: Option<u64>,

    pub rules_path: PathBuf,
    pub policy: PolicyConfig,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub certs_dir: PathBuf,
    pub mtls: Option<bool>,
    /// Hot reload interval for SNI cert cache (seconds)
    pub hot_reload_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub domain_map_path: PathBuf,
    pub policies_dir: PathBuf,
    pub hot_reload_secs: Option<u64>,
}

impl AppConfig {
    pub fn policy_hot_reload_interval_secs(&self) -> u64 {
        self.policy.hot_reload_secs.unwrap_or(3)
    }
}

impl AppConfig {
    pub fn metrics_addr(&self) -> String {
        self.metrics_listen
            .clone()
            .unwrap_or_else(|| "0.0.0.0:9100".to_string())
    }

    pub fn listen_addr(&self) -> String {
        self.https_listen
            .clone()
            .unwrap_or_else(|| "0.0.0.0:443".to_string())
    }

    pub fn listen_http_addr(&self) -> String {
        self.http_listen
            .clone()
            .unwrap_or_else(|| "0.0.0.0:80".to_string())
    }

    pub fn upstream_hot_reload_interval_secs(&self) -> u64 {
        self.upstream_hot_reload_secs.unwrap_or(3)
    }

    pub fn mtls_required(&self) -> bool {
        self.tls.mtls.unwrap_or(false)
    }

    pub fn log_dir_path(&self) -> PathBuf {
        self.log_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("logs"))
    }

    /// Resolve all relative paths in config based on the directory containing the config file.
    pub fn resolve_paths(&mut self, base_dir: &Path) {
        if let Some(p) = &self.log_dir {
            self.log_dir = Some(resolve_path(base_dir, p));
        }

        self.upstream_config_path = resolve_path(base_dir, &self.upstream_config_path);
        self.rules_path = resolve_path(base_dir, &self.rules_path);

        self.tls.certs_dir = resolve_path(base_dir, &self.tls.certs_dir);
        self.policy.domain_map_path = resolve_path(base_dir, &self.policy.domain_map_path);
        self.policy.policies_dir = resolve_path(base_dir, &self.policy.policies_dir);
    }
}

fn resolve_path(base_dir: &Path, p: &PathBuf) -> PathBuf {
    if p.is_absolute() {
        p.clone()
    } else {
        base_dir.join(p)
    }
}
