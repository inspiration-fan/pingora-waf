use std::path::PathBuf;
use std::time::Duration;

use tokio::time::sleep;

use super::manager::UpstreamManager;
use super::router::UpstreamRouter;
use super::types::UpstreamConfigFile;

pub async fn upstream_hot_reload_loop(mgr: UpstreamManager, path: PathBuf, interval: Duration) {
    let mut last_hash: Option<u64> = None;

    loop {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let h = fnv1a64(&bytes);
                let changed = last_hash.map(|x| x != h).unwrap_or(true);

                if changed {
                    match serde_yaml::from_slice::<UpstreamConfigFile>(&bytes)
                        .map_err(|e| anyhow::anyhow!("parse upstream.yaml failed: {e}"))
                        .and_then(|cfg| UpstreamRouter::new(cfg))
                    {
                        Ok(router) => {
                            mgr.swap(router);
                            last_hash = Some(h);
                            tracing::info!("upstream.yaml reloaded: {}", path.display());
                        },
                        Err(e) => {
                            tracing::error!("upstream.yaml reload failed (keep old): {}", e);
                        },
                    }
                }
            },
            Err(e) => tracing::error!("read upstream.yaml failed: {} err={}", path.display(), e),
        }

        sleep(interval).await;
    }
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
