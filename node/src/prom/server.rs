use crate::prom::{
    hooks::{Hook, Hooks},
    recorder::install_prometheus_recorder,
};
use eyre::WrapErr;
use http::{HeaderValue, Response, header::CONTENT_TYPE};
use metrics::describe_gauge;
use metrics_process::Collector;
use reth_metrics::metrics::Unit;
use std::{convert::Infallible, net::SocketAddr, sync::Arc};

/// Configuration for the [`MetricServer`]
#[derive(Debug)]
pub struct MetricServerConfig {
    listen_addr: SocketAddr,
    hooks: Hooks,
}

impl MetricServerConfig {
    /// Create a new [`MetricServerConfig`] with the given configuration
    pub const fn new(listen_addr: SocketAddr, hooks: Hooks) -> Self {
        Self { listen_addr, hooks }
    }
}

/// [`MetricServer`] responsible for serving the metrics endpoint
#[derive(Debug)]
pub struct MetricServer {
    config: MetricServerConfig,
}

impl MetricServer {
    /// Create a new [`MetricServer`] with the given configuration
    pub const fn new(config: MetricServerConfig) -> Self {
        Self { config }
    }

    /// Spawns the metrics server
    pub async fn serve(&self) -> eyre::Result<()> {
        let MetricServerConfig { listen_addr, hooks } = &self.config;

        let hooks = hooks.clone();
        self.start_endpoint(
            *listen_addr,
            Arc::new(move || hooks.iter().for_each(|hook| hook())),
        )
        .await
        .wrap_err("Could not start Prometheus endpoint")?;

        // Describe metrics after recorder installation
        describe_db_metrics();
        describe_static_file_metrics();
        Collector::default().describe();
        describe_memory_stats();
        describe_io_stats();

        Ok(())
    }

    async fn start_endpoint<F: Hook + 'static>(
        &self,
        listen_addr: SocketAddr,
        hook: Arc<F>,
    ) -> eyre::Result<()> {
        let listener = tokio::net::TcpListener::bind(listen_addr)
            .await
            .wrap_err("Could not bind to address")?;

        //task_executor.spawn_with_graceful_shutdown_signal(|mut signal| async move {
        tokio::spawn(async move {
            loop {
                let Ok((stream, _remote_addr)) = listener.accept().await else {
                    tracing::error!("failed to accept connection");
                    continue;
                };

                let handle = install_prometheus_recorder();
                let hook = hook.clone();
                let service = tower::service_fn(move |_| {
                    (hook)();
                    let metrics = handle.handle().render();
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let config = MetricServerConfig::new(listen_addr, hooks);

        MetricServer::new(config).serve().await.unwrap();

        // Send request to the metrics endpoint
        let url = format!("http://{listen_addr}");
        let response = Client::new().get(&url).send().await.unwrap();
        assert!(response.status().is_success());

        // Check the response body
        let body = response.text().await.unwrap();
        let body_contains = [
            "seismic_bft_process_cpu_seconds_total",
            "seismic_bft_process_start_time_seconds",
        ];
        for key in body_contains {
            if !body.contains(key) {
                panic!("Metrics body does not contain {}. Body:\n{:#?}", key, body);
            }
        }
    }
}
