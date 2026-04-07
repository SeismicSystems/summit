//! Custom telemetry initialization.
//!
//! Replaces `commonware_runtime::tokio::telemetry::init()` to support
//! an additional file-based layer for critical events.

use logroller::{LogRollerBuilder, Rotation, RotationSize};
use std::path::Path;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer as _, Registry, filter, fmt, layer::SubscriberExt, util::SubscriberInitExt as _,
};

/// Guard that must be held alive for the process lifetime.
/// Dropping it flushes and closes the critical log file writer.
pub struct CriticalLogGuard {
    _guard: Option<WorkerGuard>,
}

/// Initialize the tracing subscriber with an optional critical-event file layer.
///
/// Replicates the stdout logging behavior of `commonware_runtime::tokio::telemetry::init`
/// and adds an additional file layer filtered to `target: "critical"` events.
///
/// Returns a guard that MUST be held for the process lifetime to ensure
/// buffered critical events are flushed on shutdown.
pub fn init(level: Level, critical_log_dir: Option<&Path>) -> CriticalLogGuard {
    let env_filter = tracing_subscriber::EnvFilter::new(level.to_string());

    // Stdout fmt layer — same config as commonware telemetry::init
    let stdout_layer = fmt::layer()
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_span_events(fmt::format::FmtSpan::CLOSE)
        .compact();

    // Critical file layer (optional)
    let (file_layer, guard) = if let Some(dir) = critical_log_dir {
        let appender = LogRollerBuilder::new(dir, Path::new("critical.log"))
            .rotation(Rotation::SizeBased(RotationSize::MB(100)))
            .max_keep_files(5)
            .build()
            .expect("Failed to create critical log appender");

        let (non_blocking, guard) = tracing_appender::non_blocking(appender);

        let layer = fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_line_number(true)
            .with_file(true)
            .with_thread_ids(true)
            .json()
            .with_filter(filter::Targets::new().with_target("critical", Level::WARN))
            .boxed();

        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    // Use try_init so callers that already have a global subscriber (e.g. testnet
    // spawning multiple nodes in one process) don't panic.
    let _ = Registry::default()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .try_init();

    CriticalLogGuard { _guard: guard }
}
