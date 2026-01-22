use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use dashmap::DashMap;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind},
    proto::rr::{RData, RecordType},
    TokioAsyncResolver,
};
use http::Uri;
use pingora::prelude::HttpPeer;
use regex::Regex;
use tracing::warn;
use super::types::{ResolverConfig as MyResolverConfig, UpstreamConfigFile};

#[derive(Clone)]
pub struct UpstreamRouter {
    inner: Arc<Inner>,
}

struct Inner {
    // resolver
    resolver_mode: ResolverMode,

    // dns cache (only for Dns mode)
    cache_ttl: Duration,
    cname_chain_limit: usize,
    cname_cache: DashMap<String, (Instant, Option<String>)>,

    // tenant extract
    tenant_re: Regex,

    // tenant -> upstreams
    tenants: HashMap<String, Vec<String>>,
    default_upstreams: Vec<String>,

    // rr counter per tenant
    rr: DashMap<String, AtomicUsize>,
}

enum ResolverMode {
    Static {
        host_to_cname: HashMap<String, String>,
    },
    Dns {
        resolver: TokioAsyncResolver,
    },
}

impl UpstreamRouter {
    pub fn new(cfg: UpstreamConfigFile) -> anyhow::Result<Self> {
        let tenant_re = Regex::new(&cfg.cname_routing.tenant_from_cname_regex)
            .with_context(|| "bad tenant_from_cname_regex")?;

        let tenants = cfg
            .tenants
            .into_iter()
            .map(|(k, v)| (k, v.upstreams))
            .collect::<HashMap<_, _>>();

        let default_upstreams = cfg.default.upstreams;
        if default_upstreams.is_empty() {
            warn!("default.upstreams cannot be empty");
        }

        // build resolver，
        // todo 这地方有bug，逻辑这里应该是配置了源站域名的时候才需要dns
        let (resolver_mode, cache_ttl, cname_chain_limit) = match cfg.resolver {
            MyResolverConfig::Static { host_to_cname } => {
                (ResolverMode::Static { host_to_cname }, Duration::from_secs(0), 1)
            }
            MyResolverConfig::Dns {
                timeout_ms,
                cache_ttl_secs,
                cname_chain_limit,
            } => {
                // 0.24.x 正确用法：TokioAsyncResolver::tokio(config, opts)
                let mut opts = ResolverOpts::default();
                if let Some(ms) = timeout_ms {
                    opts.timeout = Duration::from_millis(ms);
                }
                let rconfig = ResolverConfig::default(); // system nameservers 等可用 from_system_conf，但这里保持简单
                let resolver = TokioAsyncResolver::tokio(rconfig, opts);

                (
                    ResolverMode::Dns { resolver },
                    Duration::from_secs(cache_ttl_secs.unwrap_or(30)),
                    cname_chain_limit.unwrap_or(5).max(1),
                )
            }
        };

        Ok(Self {
            inner: Arc::new(Inner {
                resolver_mode,
                cache_ttl,
                cname_chain_limit,
                cname_cache: DashMap::new(),
                tenant_re,
                tenants,
                default_upstreams,
                rr: DashMap::new(),
            }),
        })
    }
    pub async fn pick_endpoint_and_edge_key(&self, host: Option<&str>) -> (String, String) {
        let tenant = match host {
            Some(h) => self.tenant_from_request_host(h).await,
            None => None,
        };

        let (key, ups) = if let Some(t) = tenant {
            if let Some(list) = self.inner.tenants.get(&t) {
                (t, list.as_slice())
            } else {
                ("default".to_string(), self.inner.default_upstreams.as_slice())
            }
        } else {
            ("default".to_string(), self.inner.default_upstreams.as_slice())
        };

        let upstream = rr_pick(&self.inner.rr, &key, ups).unwrap_or_else(|| {
            self.inner
                .default_upstreams
                .get(0)
                .cloned()
                .unwrap_or_else(|| "".to_string())
        });

        (key, upstream)
    }

    pub async fn pick_endpoint(&self, host: Option<&str>) -> String {
        self.pick_endpoint_and_edge_key(host).await.1
    }

    async fn tenant_from_request_host(&self, host: &str) -> Option<String> {
        let host = strip_port(host);

        let cname = match self.resolve_cname(host).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("resolve cname failed host={} err={}", host, e);
                None
            }
        }?;

        let caps = self.inner.tenant_re.captures(&cname)?;
        Some(caps.get(1)?.as_str().to_string())
    }

    async fn resolve_cname(&self, host: &str) -> Result<Option<String>, ResolveError> {
        match &self.inner.resolver_mode {
            ResolverMode::Static { host_to_cname } => {
                tracing::debug!("host_to_cname {:?}",host_to_cname);
                tracing::debug!("host_to_cname.get(host) {:?}",host_to_cname.get(host));
                Ok(host_to_cname.get(host).cloned())
            },

            ResolverMode::Dns { resolver } => {
                // cache
                if self.inner.cache_ttl.as_secs() > 0 {
                    if let Some(v) = self.inner.cname_cache.get(host) {
                        if Instant::now() <= v.value().0 {
                            return Ok(v.value().1.clone());
                        }
                    }
                }

                let cname = self.resolve_cname_dns(resolver, host).await?;

                if self.inner.cache_ttl.as_secs() > 0 {
                    self.inner.cname_cache.insert(
                        host.to_string(),
                        (Instant::now() + self.inner.cache_ttl, cname.clone()),
                    );
                }

                Ok(cname)
            }
        }
    }

    async fn resolve_cname_dns(
        &self,
        resolver: &TokioAsyncResolver,
        host: &str,
    ) -> Result<Option<String>, ResolveError> {
        let mut cur = host.to_string();

        for _ in 0..self.inner.cname_chain_limit {
            let lookup = match resolver.lookup(cur.clone(), RecordType::CNAME).await {
                Ok(v) => v,
                Err(e) => {
                    if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                        return Ok(None);
                    }
                    return Err(e);
                }
            };

            // 从 Lookup 里找第一条 CNAME
            let mut next_cname: Option<String> = None;
            for rdata in lookup.iter() {
                if let RData::CNAME(name) = rdata {
                    next_cname = Some(name.to_utf8().trim_end_matches('.').to_string());
                    break;
                }
            }
            let Some(next) = next_cname else {
                return Ok(None);
            };

            if next.eq_ignore_ascii_case(&cur) {
                break;
            }
            cur = next;
        }

        Ok(Some(cur))
    }

    pub fn build_peer(upstream: &str) -> anyhow::Result<HttpPeer> {
        if let Ok(uri) = upstream.parse::<Uri>() {
            if let Some(auth) = uri.authority() {
                let tls = uri
                    .scheme_str()
                    .map(|s| s.eq_ignore_ascii_case("https"))
                    .unwrap_or(false);
                let host = auth.host();

                // Fill default ports for industrial usability.
                let mut addr = auth.as_str().to_string();
                if auth.port_u16().is_none() {
                    if tls {
                        addr.push_str(":443");
                    } else {
                        addr.push_str(":80");
                    }
                }

                // If upstream host is an IP literal, don't set SNI.
                let sni = match host.parse::<std::net::IpAddr>() {
                    Ok(_) => String::new(),
                    Err(_) => host.to_string(),
                };
                return Ok(HttpPeer::new(addr, tls, sni));
            }
        }
        Ok(HttpPeer::new(upstream.to_string(), false, String::new()))
    }
}

fn strip_port(host: &str) -> &str {
    if let Some(idx) = host.rfind(':') {
        let left = &host[..idx];
        let right = &host[idx + 1..];
        if right.chars().all(|c| c.is_ascii_digit()) {
            return left;
        }
    }
    host
}

fn rr_pick(rr: &DashMap<String, AtomicUsize>, key: &str, ups: &[String]) -> Option<String> {
    if ups.is_empty() {
        return None;
    }
    let counter = rr
        .entry(key.to_string())
        .or_insert_with(|| AtomicUsize::new(0));
    let i = counter.fetch_add(1, Ordering::Relaxed) % ups.len();
    Some(ups[i].clone())
}
