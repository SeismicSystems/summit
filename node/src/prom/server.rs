use crate::prom::{
    hooks::{Hook, Hooks},
    recorder::install_prometheus_recorder,
};
use commonware_runtime::{Metrics as _, signal::Signal, tokio::Context};
use eyre::WrapErr;
use futures::FutureExt;
use http::{HeaderValue, Response, header::CONTENT_TYPE};
use metrics::describe_gauge;
use metrics_process::Collector;
use reth_metrics::metrics::Unit;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};

/// Configuration for the [`MetricServer`]
pub struct MetricServerConfig {
    listen_addr: SocketAddr,
    hooks: Hooks,
    /// Optional commonware runtime context for merging runtime metrics into the response.
    cw_context: Option<Context>,
}

impl MetricServerConfig {
    /// Create a new [`MetricServerConfig`] with the given configuration
    pub fn new(listen_addr: SocketAddr, hooks: Hooks, cw_context: Option<Context>) -> Self {
        Self {
            listen_addr,
            hooks,
            cw_context,
        }
    }
}

/// [`MetricServer`] responsible for serving the metrics endpoint
pub struct MetricServer {
    config: MetricServerConfig,
}

impl MetricServer {
    /// Create a new [`MetricServer`] with the given configuration
    pub fn new(config: MetricServerConfig) -> Self {
        Self { config }
    }

    /// Spawns the metrics server
    pub async fn serve(&self, stop_signal: Signal) -> eyre::Result<()> {
        let MetricServerConfig {
            listen_addr,
            hooks,
            cw_context,
        } = &self.config;

        // Install the global recorder before any metrics are emitted or described —
        // otherwise they hit the no-op recorder and are silently dropped.
        let recorder = install_prometheus_recorder();
        recorder.spawn_upkeep();

        let hooks = hooks.clone();
        let cw_context = cw_context.clone();
        self.start_endpoint(
            *listen_addr,
            Arc::new(move || hooks.iter().for_each(|hook| hook())),
            cw_context,
            stop_signal,
        )
        .await
        .wrap_err("Could not start Prometheus endpoint")?;

        // Describe metrics after recorder installation
        describe_db_metrics();
        describe_static_file_metrics();
        describe_ssz_metrics();
        describe_critical_error_metrics();
        Collector::default().describe();
        describe_memory_stats();
        describe_io_stats();
        describe_disk_stats();

        Ok(())
    }

    async fn start_endpoint<F: Hook + 'static>(
        &self,
        listen_addr: SocketAddr,
        hook: Arc<F>,
        cw_context: Option<Context>,
        stop_signal: Signal,
    ) -> eyre::Result<()> {
        let listener = tokio::net::TcpListener::bind(listen_addr)
            .await
            .wrap_err("Could not bind to address")?;

        let handle = install_prometheus_recorder();
        tokio::spawn(async move {
            let mut stop_signal = stop_signal.fuse();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((stream, _remote_addr)) = result else {
                            tracing::error!("failed to accept connection");
                            continue;
                        };

                        let hook = hook.clone();
                        let cw_context = cw_context.clone();
                        let service = tower::service_fn(move |_| {
                            (hook)();
                            let mut metrics = handle.handle().render();
                            if let Some(ref ctx) = cw_context {
                                metrics.push('\n');
                                metrics.push_str(&ctx.encode());
                            }
                            let mut response = Response::new(metrics);
                            response
                                .headers_mut()
                                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                            async move { Ok::<_, Infallible>(response) }
                        });

                        tokio::task::spawn(async move {
                            let _ = jsonrpsee_server::serve(stream, service)
                                .await
                                .inspect_err(|error| tracing::debug!(%error, "failed to serve request"));
                        });
                    }
                    sig = &mut stop_signal => {
                        tracing::info!("Metrics server shutting down: {}", sig.unwrap());
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

fn describe_db_metrics() {
    describe_gauge!(
        "db.table_size",
        Unit::Bytes,
        "The size of a database table (in bytes)"
    );
    describe_gauge!("db.table_pages", "The number of database pages for a table");
    describe_gauge!("db.table_entries", "The number of entries for a table");
    describe_gauge!("db.freelist", "The number of pages on the freelist");
    describe_gauge!(
        "db.page_size",
        Unit::Bytes,
        "The size of a database page (in bytes)"
    );
    describe_gauge!(
        "db.timed_out_not_aborted_transactions",
        "Number of timed out transactions that were not aborted by the user yet"
    );
}

fn describe_static_file_metrics() {
    describe_gauge!(
        "static_files.segment_size",
        Unit::Bytes,
        "The size of a static file segment"
    );
    describe_gauge!(
        "static_files.segment_files",
        "The number of files for a static file segment"
    );
    describe_gauge!(
        "static_files.segment_entries",
        "The number of entries for a static file segment"
    );
}

fn describe_ssz_metrics() {
    use metrics::describe_histogram;

    describe_histogram!(
        "ssz_rebuild_tree_micros",
        "Time to fully rebuild the SSZ state tree from scratch (microseconds)"
    );
    describe_histogram!(
        "ssz_set_account_micros",
        "Time to insert or update a validator account in the SSZ tree (microseconds)"
    );
    describe_histogram!(
        "ssz_remove_account_micros",
        "Time to remove a validator account from the SSZ tree (microseconds)"
    );
    describe_histogram!(
        "ssz_push_deposit_micros",
        "Time to push a deposit into the SSZ deposit subtree (microseconds)"
    );
    describe_histogram!(
        "ssz_pop_deposit_micros",
        "Time to pop a deposit and rebuild the SSZ deposit subtree (microseconds)"
    );
    describe_histogram!(
        "ssz_push_withdrawal_request_micros",
        "Time to push a withdrawal request into the SSZ withdrawal subtree (microseconds)"
    );
    describe_histogram!(
        "ssz_push_withdrawal_micros",
        "Time to push a withdrawal into the SSZ withdrawal subtree (microseconds)"
    );
    describe_histogram!(
        "ssz_pop_withdrawal_micros",
        "Time to pop a withdrawal from the SSZ withdrawal subtree (microseconds)"
    );
    describe_histogram!(
        "ssz_capture_state_root_micros",
        "Time to snapshot the SSZ tree for proof generation (microseconds)"
    );
}

fn describe_critical_error_metrics() {
    use metrics::describe_counter;

    describe_counter!(
        "critical_errors_total",
        "Critical errors requiring immediate attention (labelled by reason)"
    );
}

#[cfg(all(feature = "jemalloc", unix))]
fn describe_memory_stats() {
    describe_gauge!(
        "jemalloc.active",
        Unit::Bytes,
        "Total number of bytes in active pages allocated by the application"
    );
    describe_gauge!(
        "jemalloc.allocated",
        Unit::Bytes,
        "Total number of bytes allocated by the application"
    );
    describe_gauge!(
        "jemalloc.mapped",
        Unit::Bytes,
        "Total number of bytes in active extents mapped by the allocator"
    );
    describe_gauge!(
        "jemalloc.metadata",
        Unit::Bytes,
        "Total number of bytes dedicated to jemalloc metadata"
    );
    describe_gauge!(
        "jemalloc.resident",
        Unit::Bytes,
        "Total number of bytes in physically resident data pages mapped by the allocator"
    );
    describe_gauge!(
        "jemalloc.retained",
        Unit::Bytes,
        "Total number of bytes in virtual memory mappings that were retained rather than \
        being returned to the operating system via e.g. munmap(2)"
    );
}

#[cfg(not(all(feature = "jemalloc", unix)))]
const fn describe_memory_stats() {}

#[cfg(target_os = "linux")]
fn describe_io_stats() {
    use metrics::describe_counter;

    describe_counter!("io.rchar", "Characters read");
    describe_counter!("io.wchar", "Characters written");
    describe_counter!("io.syscr", "Read syscalls");
    describe_counter!("io.syscw", "Write syscalls");
    describe_counter!("io.read_bytes", Unit::Bytes, "Bytes read");
    describe_counter!("io.write_bytes", Unit::Bytes, "Bytes written");
    describe_counter!(
        "io.cancelled_write_bytes",
        Unit::Bytes,
        "Cancelled write bytes"
    );
}

#[cfg(not(target_os = "linux"))]
const fn describe_io_stats() {}

#[cfg(target_os = "linux")]
fn describe_disk_stats() {
    describe_gauge!(
        "disk.total_bytes",
        Unit::Bytes,
        "Total size of the filesystem"
    );
    describe_gauge!(
        "disk.free_bytes",
        Unit::Bytes,
        "Free bytes on the filesystem (including reserved)"
    );
    describe_gauge!(
        "disk.available_bytes",
        Unit::Bytes,
        "Bytes available to non-root users"
    );
    describe_gauge!(
        "disk.used_bytes",
        Unit::Bytes,
        "Used bytes on the filesystem"
    );
}

#[cfg(not(target_os = "linux"))]
const fn describe_disk_stats() {}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::signal::Stopper;
    use reqwest::Client;
    use socket2::{Domain, Socket, Type};
    use std::net::{SocketAddr, TcpListener};

    fn get_random_available_addr() -> SocketAddr {
        let addr = &"127.0.0.1:0".parse::<SocketAddr>().unwrap().into();
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket.bind(addr).unwrap();
        socket.listen(1).unwrap();
        let listener = TcpListener::from(socket);
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let hooks = Hooks::builder().build();

        let listen_addr = get_random_available_addr();
        let config = MetricServerConfig::new(listen_addr, hooks, None);

        let stopper = Stopper::new();
        let signal = stopper.stopped();

        MetricServer::new(config).serve(signal).await.unwrap();

        // Send request to the metrics endpoint
        let url = format!("http://{listen_addr}");
        let response = Client::new().get(&url).send().await.unwrap();
        assert!(response.status().is_success());

        // Check the response body
        let body = response.text().await.unwrap();
        let body_contains = [
            "summit_process_cpu_seconds_total",
            "summit_process_start_time_seconds",
        ];
        for key in body_contains {
            if !body.contains(key) {
                panic!("Metrics body does not contain {}. Body:\n{:#?}", key, body);
            }
        }
    }
}
