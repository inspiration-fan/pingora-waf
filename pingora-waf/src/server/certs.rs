use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use pingora::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;

/// In-memory cert+key pair, used by TLS SNI callback.
#[derive(Clone)]
pub struct CertKeyPair {
    pub cert: X509,
    pub key: PKey<Private>,
}

#[derive(Clone)]
struct Snapshot {
    exact: HashMap<String, Arc<CertKeyPair>>,
    wildcard: HashMap<String, Arc<CertKeyPair>>,
    fingerprint: u64,
}

/// SNI certificate store with atomic snapshot swap.
///
/// Directory layout (under certs_dir):
///
/// certs/server/default/cert.pem
/// certs/server/default/key.pem
/// certs/server/sni/<domain>/cert.pem
/// certs/server/sni/<domain>/key.pem
/// certs/server/wildcard/<suffix>/cert.pem  (represents *.suffix)
/// certs/server/wildcard/<suffix>/key.pem
pub struct CertStore {
    snap: ArcSwap<Snapshot>,
}

pub type CertStoreHandle = Arc<CertStore>;

impl CertStore {
    pub fn load(certs_dir: &Path) -> anyhow::Result<CertStoreHandle> {
        let snapshot = load_snapshot(certs_dir)?;
        Ok(Arc::new(Self {
            snap: ArcSwap::from_pointee(snapshot),
        }))
    }

    #[inline]
    pub fn fingerprint(&self) -> u64 {
        self.snap.load().fingerprint
    }

    /// Lookup cert by SNI name. Supports exact and wildcard.
    pub fn lookup(&self, sni: &str) -> Option<Arc<CertKeyPair>> {
        let name = normalize_name(sni);
        let snap = self.snap.load();

        if let Some(v) = snap.exact.get(&name) {
            return Some(v.clone());
        }

        // Try wildcard: a.b.c.example.com => try b.c.example.com, c.example.com, example.com
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        for i in 1..parts.len() {
            let suffix = parts[i..].join(".");
            if let Some(v) = snap.wildcard.get(&suffix) {
                return Some(v.clone());
            }
        }

        None
    }

    fn reload(&self, certs_dir: &Path) -> anyhow::Result<Snapshot> {
        load_snapshot(certs_dir)
    }

    fn swap(&self, new_snap: Snapshot) {
        self.snap.store(Arc::new(new_snap));
    }
}

pub struct CertUpdater {
    store: CertStoreHandle,
    certs_dir: PathBuf,
    interval: Duration,
}

impl CertUpdater {
    pub fn new(store: CertStoreHandle, certs_dir: PathBuf, interval: Duration) -> Self {
        Self {
            store,
            certs_dir,
            interval,
        }
    }
}

#[async_trait]
impl BackgroundService for CertUpdater {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut last_fp = self.store.fingerprint();
        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("cert updater shutdown");
                    return;
                }
                _ = ticker.tick() => {
                    let dir = self.certs_dir.clone();
                    let fp = match tokio::task::spawn_blocking(move || compute_fingerprint(&dir)).await {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            tracing::warn!("cert fingerprint error: {}", e);
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!("cert fingerprint task error: {}", e);
                            continue;
                        }
                    };

                    if fp == last_fp {
                        continue;
                    }

                    let dir = self.certs_dir.clone();
                    let store = self.store.clone();
                    let store_for_task = store.clone();
                    match tokio::task::spawn_blocking(move || store_for_task.reload(&dir)).await {
                        Ok(Ok(new_snap)) => {
                            last_fp = new_snap.fingerprint;
                            store.swap(new_snap);
                            tracing::info!("sni certs reloaded");
                        }
                        Ok(Err(e)) => {
                            tracing::error!("sni cert reload failed (keep old): {}", e);
                        }
                        Err(e) => {
                            tracing::error!("sni cert reload task failed: {}", e);
                        }
                    }
                }
            }
        }
    }
}

fn load_snapshot(certs_dir: &Path) -> anyhow::Result<Snapshot> {
    let server_dir = certs_dir.join("server");

    let exact = load_pairs_from_subdirs(&server_dir.join("sni"), PairKind::Exact)?;
    let wildcard = load_pairs_from_subdirs(&server_dir.join("wildcard"), PairKind::WildcardSuffix)?;

    let fingerprint = compute_fingerprint(certs_dir)?;

    tracing::info!(
        exact = exact.len(),
        wildcard = wildcard.len(),
        "sni cert cache loaded"
    );

    Ok(Snapshot {
        exact,
        wildcard,
        fingerprint,
    })
}

#[derive(Copy, Clone)]
enum PairKind {
    Exact,
    /// The directory name is a suffix (example.com) representing *.example.com
    WildcardSuffix,
}

fn load_pairs_from_subdirs(base: &Path, kind: PairKind) -> anyhow::Result<HashMap<String, Arc<CertKeyPair>>> {
    let mut map = HashMap::new();
    if !base.exists() {
        return Ok(map);
    }

    for ent in std::fs::read_dir(base).with_context(|| format!("read dir failed: {}", base.display()))? {
        let ent = ent?;
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(v) => v,
            None => continue,
        };

    	let key = match kind {
            PairKind::Exact => normalize_name(name),
            PairKind::WildcardSuffix => normalize_name(name),
        };

        let cert_path = path.join("cert.pem");
        let key_path = path.join("key.pem");
        if !(cert_path.exists() && key_path.exists()) {
            continue;
        }

        let cert_pem = std::fs::read(&cert_path)
            .with_context(|| format!("read cert failed: {}", cert_path.display()))?;
        let key_pem = std::fs::read(&key_path)
            .with_context(|| format!("read key failed: {}", key_path.display()))?;

        let cert = X509::from_pem(&cert_pem)
            .with_context(|| format!("parse cert failed: {}", cert_path.display()))?;
        let pkey = PKey::private_key_from_pem(&key_pem)
            .with_context(|| format!("parse key failed: {}", key_path.display()))?;

        map.insert(
            key,
            Arc::new(CertKeyPair {
                cert,
                key: pkey,
            }),
        );
    }

    Ok(map)
}

fn normalize_name(s: &str) -> String {
    s.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn compute_fingerprint(certs_dir: &Path) -> anyhow::Result<u64> {
    let server_dir = certs_dir.join("server");

    let mut files = Vec::new();
    collect_files_recursive(&server_dir, &mut files)?;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for p in files {
        p.to_string_lossy().hash(&mut hasher);
        if let Ok(meta) = std::fs::metadata(&p) {
            meta.len().hash(&mut hasher);
            if let Ok(m) = meta.modified() {
                // Use nanos for better sensitivity.
                let nanos = m
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                nanos.hash(&mut hasher);
            }
        }
    }

    Ok(hasher.finish())
}

fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for ent in std::fs::read_dir(dir).with_context(|| format!("read dir failed: {}", dir.display()))? {
        let ent = ent?;
        let path = ent.path();
        if path.is_dir() {
            collect_files_recursive(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}
