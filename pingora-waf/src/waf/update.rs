use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;

use super::engine::WafEngine;
use super::rules::compiler::compile_from_file;

pub struct RuleUpdater {
    engine: WafEngine,
    rules_path: PathBuf,
    interval: Duration,
}

impl RuleUpdater {
    pub fn new(engine: WafEngine, rules_path: PathBuf, interval: Duration) -> Self {
        Self {
            engine,
            rules_path,
            interval,
        }
    }
}

#[async_trait]
impl BackgroundService for RuleUpdater {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut last_mtime: Option<std::time::SystemTime> = None;
        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("rule updater shutdown");
                    return;
                }
                _ = ticker.tick() => {
                    let meta = match tokio::fs::metadata(&self.rules_path).await {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!("rules metadata error: {}", e);
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

                    match compile_from_file(&self.rules_path) {
                        Ok(new_rules) => {
                            self.engine.swap_rules(new_rules);
                            tracing::info!("rules reloaded");
                        }
                        Err(e) => {
                            tracing::error!("rules reload failed: {}", e);
                        }
                    }
                }
            }
        }
    }
}
