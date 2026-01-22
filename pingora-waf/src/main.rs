use crate::upstream::manager::UpstreamManager;
use crate::upstream::router::UpstreamRouter;
use crate::upstream::types::UpstreamConfigFile;
use clap::Parser;
use pingora::prelude::*;
use pingora_proxy::http_proxy_service;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod config;
mod metrics;
mod obs;
mod policy;
mod server;
mod telemetry;
mod upstream;
mod waf;

#[derive(Debug, Parser)]
#[command(name = "pingora-waf", version, about = "Industrial-grade WAF dataplane (Pingora based)")]
struct Args {
    /// Path to config.yaml (relative paths inside config will be resolved based on this file's directory)
    #[arg(long, default_value = "config.yaml")]
    config: PathBuf,
}

fn locate_config(p: PathBuf) -> PathBuf {
    if p.exists() {
        return p;
    }

    // If default config.yaml doesn't exist, try common fallbacks.
    if p == PathBuf::from("config.yaml") {
        if Path::new("aegis/config.yaml").exists() {
            return PathBuf::from("aegis/config.yaml");
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let cand1 = dir.join("config.yaml");
                if cand1.exists() {
                    return cand1;
                }
                let cand2 = dir.join("aegis/config.yaml");
                if cand2.exists() {
                    return cand2;
                }
            }
        }
    }

    p
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg_path = locate_config(args.config);
    let cfg_dir = cfg_path.parent().unwrap_or_else(|| Path::new("."));

    let cfg_text = fs::read_to_string(&cfg_path)?;
    let mut cfg: config::AppConfig = serde_yaml::from_str(&cfg_text)?;
    cfg.resolve_paths(cfg_dir);

    // Tracing + log files
    let log_dir = cfg.log_dir_path();
    telemetry::init_tracing("aegis", &log_dir)?;

    // Access/events sinks
    let obs = obs::ObsSink::new(&log_dir)?;

    // Upstream router
    let upstream_bytes = std::fs::read(&cfg.upstream_config_path)?;
    let upstream_cfg: UpstreamConfigFile = serde_yaml::from_slice(&upstream_bytes)?;
    let router = UpstreamRouter::new(upstream_cfg)?;
    let upstream_mgr = UpstreamManager::new(router);

    let mut my_server = Server::new(None)?;
    my_server.bootstrap();

    let metrics_listen = cfg
        .metrics_listen
        .clone()
        .unwrap_or_else(|| "0.0.0.0:9100".to_string());

    let metrics_svc = background_service(
        "metrics",
        crate::metrics::service::MetricsSvc::new(metrics_listen),
    );
    my_server.add_service(metrics_svc);

    // Background: upstream hot reload
    let updater_upstream = background_service(
        "upstream-updater",
        upstream::update::UpstreamUpdater::new(
            upstream_mgr.clone(),
            cfg.upstream_config_path.clone(),
            Duration::from_secs(cfg.upstream_hot_reload_interval_secs()),
        ),
    );
    my_server.add_service(updater_upstream);

    // domain_map + policies hot reload
    let policy_state = policy::manager::PolicyManager::load_from_files(
        &cfg.policy.domain_map_path,
        &cfg.policy.policies_dir,
    )?;
    let policy_mgr = policy::manager::PolicyManager::new(policy_state);

    let updater_domain = background_service(
        "domain-map-updater",
        policy::update::DomainMapUpdater::new(
            policy_mgr.clone(),
            cfg.policy.domain_map_path.clone(),
            cfg.policy.policies_dir.clone(),
            Duration::from_secs(cfg.policy_hot_reload_interval_secs()),
        ),
    );
    my_server.add_service(updater_domain);

    let updater_policies = background_service(
        "policies-updater",
        policy::update::PolicyDirUpdater::new(
            policy_mgr.clone(),
            cfg.policy.domain_map_path.clone(),
            cfg.policy.policies_dir.clone(),
            Duration::from_secs(cfg.policy_hot_reload_interval_secs()),
        ),
    );
    my_server.add_service(updater_policies);

    // WAF engine + proxy
    let ruleset = waf::rules::compiler::compile_from_file(&cfg.rules_path)?;
    let engine = waf::engine::WafEngine::new(ruleset);
    let proxy = server::proxy::WafProxy::new(
        engine.clone(),
        upstream_mgr.clone(),
        policy_mgr.clone(),
        obs,
    );

    // Background: rule hot reload
    let updater_rule = background_service(
        "rule-updater",
        waf::update::RuleUpdater::new(
            engine,
            cfg.rules_path.clone(),
            std::time::Duration::from_secs(3),
        ),
    );
    my_server.add_service(updater_rule);

    let mut svc = http_proxy_service(&my_server.configuration, proxy);

    // HTTP + HTTPS listeners (SNI cert hot reload)
    let cert_store = server::certs::CertStore::load(&cfg.tls.certs_dir)?;
    let cert_updater = background_service(
        "cert-updater",
        server::certs::CertUpdater::new(
            cert_store.clone(),
            cfg.tls.certs_dir.clone(),
            Duration::from_secs(cfg.tls.hot_reload_secs.unwrap_or(3)),
        ),
    );
    my_server.add_service(cert_updater);

    server::listener::add_http_listener(&mut svc, &cfg);
    server::listener::add_https_listener(&mut svc, &cfg, cert_store)?;

    my_server.add_service(svc);

    my_server.run_forever();
}
