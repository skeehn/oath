//! Shared HTTP client construction.
//!
//! Every outbound client Oath builds goes through [`client_builder`] so the
//! same trust store applies everywhere: the registry client, metadata lookups,
//! git tarball downloads, and publishing. Beyond the bundled WebPKI roots, the
//! builder trusts the PEM bundles npm users already configure for corporate
//! TLS inspection: `npm_config_cafile` (npm's `cafile` setting as an
//! environment override) and Node's `NODE_EXTRA_CA_CERTS`.

use anyhow::{Context, Result};
use std::path::Path;

/// A reqwest builder with Oath's user agent and extra CA bundles applied.
pub fn client_builder() -> Result<reqwest::ClientBuilder> {
    let mut builder =
        reqwest::Client::builder().user_agent(concat!("oath/", env!("CARGO_PKG_VERSION")));
    for certificate in extra_root_certificates()? {
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder)
}

/// Extra root certificates from `npm_config_cafile` and `NODE_EXTRA_CA_CERTS`.
/// A configured file that cannot be read or parsed is an error: silently
/// ignoring it would turn a misconfiguration into a confusing TLS failure.
pub fn extra_root_certificates() -> Result<Vec<reqwest::Certificate>> {
    let mut certificates = Vec::new();
    for variable in ["npm_config_cafile", "NODE_EXTRA_CA_CERTS"] {
        let Some(path) = std::env::var_os(variable) else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let path = Path::new(&path);
        let pem = std::fs::read(path).with_context(|| {
            format!(
                "{variable} points at an unreadable CA bundle {}",
                path.display()
            )
        })?;
        let parsed = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("{variable} is not a PEM certificate bundle"))?;
        certificates.extend(parsed);
    }
    Ok(certificates)
}
