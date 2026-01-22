use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;

use super::manager::UpstreamManager;
use super::router::UpstreamRouter;
use super::types::UpstreamConfigFile;

pub struct UpstreamUpdater {
    mgr: UpstreamManager,
    upstream_path: PathBuf,
    interval: Duration,
}

impl UpstreamUpdater {
    pub fn new(mgr: UpstreamManager, upstream_path: PathBuf, interval: Duration) -> Self {
        Self {
            mgr,
            upstream_path,
            interval,
        }
    }
}

#[async_trait]
impl BackgroundService for UpstreamUpdater {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut last_mtime: Option<std::time::SystemTime> = None;
        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("upstream updater shutdown");
                    return;
                }
                _ = ticker.tick() => {
                    let meta = match tokio::fs::metadata(&self.upstream_path).await {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!("upstream metadata error: {}", e);
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

                    // 读取 + 解析 + 构建 router，成功则原子替换
                    match tokio::fs::read(&self.upstream_path).await {
                        Ok(bytes) => {
                            match serde_yaml::from_slice::<UpstreamConfigFile>(&bytes)
                                .map_err(|e| anyhow::anyhow!("parse upstream.yaml failed: {e}"))
                                .and_then(|cfg| UpstreamRouter::new(cfg))
                            {
                                Ok(router) => {
                                    self.mgr.swap(router);
                                    tracing::info!("upstream reloaded");
                                }
                                Err(e) => {
                                    tracing::error!("upstream reload failed (keep old): {}", e);
                                }
                            }
                        }
                        Err(e) => tracing::warn!("read upstream.yaml failed: {}", e),
                    }
                }
            }
        }
    }
}
