//! oath-fetch: npm registry client
//!
//! Fetches packuments, resolves versions, downloads and verifies tarballs.
//! Fully compatible with the npm registry HTTP protocol.

pub mod cache;
pub mod client;
pub mod http;
pub mod metadata;
pub mod npmrc;
pub mod packument;
pub mod resolve;
pub mod tarball;

pub use metadata::{Maintainer, PackageMetadata, fetch_package_metadata};

pub use client::RegistryClient;
pub use npmrc::NpmrcConfig;
pub use packument::{DistInfo, Packument, VersionInfo};
pub use resolve::resolve_version;
