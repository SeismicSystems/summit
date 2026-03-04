//! IP resolution technique taken from https://github.com/SeismicSystems/seismic-reth/tree/seismic/crates/net/nat
use std::net::IpAddr;
use tracing::{debug, warn};

const EXTERNAL_IP_SERVICES: &[&str] = &[
    "https://ipinfo.io/ip",
    "https://icanhazip.com",
    "https://ifconfig.me",
];

/// Resolves the node's external IP by querying well-known services.
/// Returns the first successful result, or `None` if all fail.
pub async fn resolve_external_ip() -> Option<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    for &url in EXTERNAL_IP_SERVICES {
        match client.get(url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => match body.trim().parse::<IpAddr>() {
                    Ok(ip) => {
                        debug!(%ip, service = url, "resolved external IP");
                        return Some(ip);
                    }
                    Err(e) => warn!(service = url, error = %e, "failed to parse IP response"),
                },
                Err(e) => warn!(service = url, error = %e, "failed to read response body"),
            },
            Err(e) => warn!(service = url, error = %e, "failed to query IP service"),
        }
    }

    None
}
