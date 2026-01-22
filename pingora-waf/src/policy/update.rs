use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;

use super::manager::{PolicyManager, PolicyState};

pub struct DomainMapUpdater {
    mgr: PolicyManager,
    domain_map_path: PathBuf,
    policies_dir: PathBuf,
    interval: Duration,
}

impl DomainMapUpdater {
    pub fn new(mgr: PolicyManager, domain_map_path: PathBuf, policies_dir: PathBuf, interval: Duration) -> Self {
        Self { mgr, domain_map_path, policies_dir, interval }
    }
}

#[async_trait]
impl BackgroundService for DomainMapUpdater {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut last_mtime: Option<std::time::SystemTime> = None;
        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("domain map updater shutdown");
                    return;
                }
                _ = ticker.tick() => {
                    let meta = match tokio::fs::metadata(&self.domain_map_path).await {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!("domain_map metadata error: {}", e);
                            continue;
                        }
                    };
                    let mtime = match meta.modified() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    if last_mtime.map(|x| x >= mtime).unwrap_or(false) {
                        continue;
                    }
                    last_mtime = Some(mtime);

                    match super::manager::PolicyManager::load_from_files(
                        Path::new(&self.domain_map_path),
                        Path::new(&self.policies_dir),
                    ) {
                        Ok(new_state) => {
                            // 保留旧 CC limiter（计数状态不丢）
                            let old = self.mgr.load();
                            let merged = PolicyState {
                                matcher: new_state.matcher,
                                policies: new_state.policies,
                                cc: old.cc.clone(),
                            };
                            self.mgr.swap(merged);
                            tracing::info!("domain_map reloaded");
                        }
                        Err(e) => {
                            tracing::error!("domain_map reload failed (keep old): {}", e);
                        }
                    }
                }
            }
        }
    }
}

pub struct PolicyDirUpdater {
    mgr: PolicyManager,
    domain_map_path: PathBuf,
    policies_dir: PathBuf,
    interval: Duration,
}

impl PolicyDirUpdater {
    pub fn new(mgr: PolicyManager, domain_map_path: PathBuf, policies_dir: PathBuf, interval: Duration) -> Self {
        Self { mgr, domain_map_path, policies_dir, interval }
    }
}

#[async_trait]
impl BackgroundService for PolicyDirUpdater {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut last_sig: Option<u64> = None;
        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("policy dir updater shutdown");
                    return;
                }
                _ = ticker.tick() => {
                    let sig = match dir_signature(&self.policies_dir).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("policy dir signature error: {}", e);
                            continue;
                        }
                    };

                    if last_sig.map(|x| x == sig).unwrap_or(false) {
                        continue;
                    }
                    last_sig = Some(sig);

                    match super::manager::PolicyManager::load_from_files(
                        Path::new(&self.domain_map_path),
                        Path::new(&self.policies_dir),
                    ) {
                        Ok(new_state) => {
                            // 保留旧 CC limiter
                            let old = self.mgr.load();
                            let merged = PolicyState {
                                matcher: new_state.matcher,
                                policies: new_state.policies,
                                cc: old.cc.clone(),
                            };
                            self.mgr.swap(merged);
                            tracing::info!("policies reloaded");
                        }
                        Err(e) => {
                            tracing::error!("policies reload failed (keep old): {}", e);
                        }
                    }
                }
            }
        }
    }
}

/// 计算目录签名：遍历 yaml 文件，组合 (文件名+mtime+size) 的 hash
async fn dir_signature(dir: &PathBuf) -> anyhow::Result<u64> {
    let mut h: u64 = 0xcbf29ce484222325;

    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        let p = ent.path();
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        let meta = ent.metadata().await?;
        let mtime = meta.modified().ok();
        let size = meta.len();

        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        h = fnv1a_mix(h, name.as_bytes());
        h = fnv1a_mix(h, &size.to_le_bytes());
        if let Some(t) = mtime {
            let nanos = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u128;
            h = fnv1a_mix(h, &nanos.to_le_bytes());
        }
    }

    Ok(h)
}

fn fnv1a_mix(mut h: u64, data: &[u8]) -> u64 {
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
