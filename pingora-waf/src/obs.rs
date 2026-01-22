use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use once_cell::sync::OnceCell;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt::MakeWriter;

/// Two JSONL sinks: access + events
///
/// Active files:
/// - <log_dir>/access.jsonl
/// - <log_dir>/events.jsonl
///
/// Rolling:
/// - hourly rolling handled by tracing-appender
#[derive(Clone)]
pub struct ObsSink {
    log_dir: PathBuf,
    access: NonBlocking,
    events: NonBlocking,
}

// Keep guards alive for process lifetime, otherwise logs may drop.
static ACCESS_GUARD: OnceCell<WorkerGuard> = OnceCell::new();
static EVENTS_GUARD: OnceCell<WorkerGuard> = OnceCell::new();

#[derive(Debug, Clone)]
pub struct AccessLog {
    pub ts: DateTime<Utc>,
    pub request_id: String,
    pub edge_key: String,
    pub policy_id: String,
    pub action: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u64,
    pub upstream: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub ts: DateTime<Utc>,
    pub request_id: String,
    pub edge_key: String,
    pub policy_id: String,
    pub action: String,
    pub rule_id: String,
    pub reason: String,
    pub phase: String,
    pub status: u16,
    pub host: String,
    pub path: String,
    pub method: String,
    pub client_ip: Option<String>,
}

/// Internal serialized form for access lines (injects dataset)
#[derive(Serialize)]
struct AccessLine<'a> {
    #[serde(rename = "@timestamp")]
    ts: &'a DateTime<Utc>,
    dataset: &'static str,
    request_id: &'a str,
    edge_key: &'a str,
    policy_id: &'a str,
    action: &'a str,
    method: &'a str,
    host: &'a str,
    path: &'a str,
    status: u16,
    latency_ms: u64,
    upstream: &'a Option<String>,
    client_ip: &'a Option<String>,
    user_agent: &'a Option<String>,
    error: &'a Option<String>,
}

/// Internal serialized form for event lines (injects dataset)
#[derive(Serialize)]
struct EventLine<'a> {
    #[serde(rename = "@timestamp")]
    ts: &'a DateTime<Utc>,
    dataset: &'static str,
    request_id: &'a str,
    edge_key: &'a str,
    policy_id: &'a str,
    action: &'a str,
    rule_id: &'a str,
    reason: &'a str,
    phase: &'a str,
    status: u16,
    method: &'a str,
    host: &'a str,
    path: &'a str,
    client_ip: &'a Option<String>,
}

impl ObsSink {
    pub fn new(log_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(log_dir)
            .with_context(|| format!("create log_dir failed: {}", log_dir.display()))?;

        // hourly rolling appenders
        let access_appender = tracing_appender::rolling::hourly(log_dir, "access.jsonl");
        let events_appender = tracing_appender::rolling::hourly(log_dir, "events.jsonl");

        // non-blocking writers
        let (access, ag) = tracing_appender::non_blocking(access_appender);
        let (events, eg) = tracing_appender::non_blocking(events_appender);

        let _ = ACCESS_GUARD.set(ag);
        let _ = EVENTS_GUARD.set(eg);

        Ok(Self {
            log_dir: log_dir.to_path_buf(),
            access,
            events,
        })
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Write one access JSONL line. Caller does NOT provide dataset.
    pub fn write_access(&self, rec: &AccessLog) {
        let line = AccessLine {
            ts: &rec.ts,
            dataset: "access",
            request_id: &rec.request_id,
            edge_key: &rec.edge_key,
            policy_id: &rec.policy_id,
            action: &rec.action,
            method: &rec.method,
            host: &rec.host,
            path: &rec.path,
            status: rec.status,
            latency_ms: rec.latency_ms,
            upstream: &rec.upstream,
            client_ip: &rec.client_ip,
            user_agent: &rec.user_agent,
            error: &rec.error,
        };

        if let Ok(json) = serde_json::to_string(&line) {
            let mut w = self.access.make_writer();
            let _ = w.write_all(json.as_bytes());
            let _ = w.write_all(b"\n");
        }
    }

    /// Write one security event JSONL line. Caller does NOT provide dataset.
    pub fn write_event(&self, rec: &SecurityEvent) {
        let line = EventLine {
            ts: &rec.ts,
            dataset: "events",
            request_id: &rec.request_id,
            edge_key: &rec.edge_key,
            policy_id: &rec.policy_id,
            action: &rec.action,
            rule_id: &rec.rule_id,
            reason: &rec.reason,
            phase: &rec.phase,
            status: rec.status,
            method: &rec.method,
            host: &rec.host,
            path: &rec.path,
            client_ip: &rec.client_ip,
        };

        if let Ok(json) = serde_json::to_string(&line) {
            let mut w = self.events.make_writer();
            let _ = w.write_all(json.as_bytes());
            let _ = w.write_all(b"\n");
        }
    }
}
