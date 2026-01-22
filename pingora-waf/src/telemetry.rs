use anyhow::Result;
use once_cell::sync::OnceCell;
use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static TRACING_GUARD: OnceCell<WorkerGuard> = OnceCell::new();

/// Initialize tracing.
///
/// - stdout: human logs.
/// - file: JSONL logs (Vector tail), hourly rolling.
/// - env: RUST_LOG controls level (e.g. `info,ins_waf_engine=debug`).
///
/// Notes:
/// - Size-based rotation (100MB) + keep 24 is done by logrotate on VM.
/// - Guard must live for process lifetime, otherwise logs may be dropped.
pub fn init_tracing(service: &str, log_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(log_dir)?;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Hourly rolling: <log_dir>/<service>.jsonl.<timestamp> (implementation-defined suffix)
    // Active file is <log_dir>/<service>.jsonl
    let file_appender = tracing_appender::rolling::hourly(log_dir, format!("{service}.jsonl"));

    // Non-blocking writer for production
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    // Keep the guard forever (process lifetime)
    let _ = TRACING_GUARD.set(guard);

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(json_layer)
        .init();

    Ok(())
}
