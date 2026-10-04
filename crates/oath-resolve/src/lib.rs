//! oath-resolve: dependency graph resolution
//!
//! Takes a package.json (or direct dependency list) and produces a complete
//! dependency graph with exact resolved versions and integrity hashes.
//!
//! Uses a simple BFS resolution strategy with deduplication (hoisting).
//! Future: upgrade to PubGrub for better conflict resolution.

pub mod git;
pub mod graph;
pub mod import;
pub mod lockfile;
pub mod npm_package_lock;
pub mod placement;
pub mod resolver;

pub use graph::{DepGraph, DepNode};
pub use import::import_npm_lockfile;
pub use lockfile::{LOCKFILE_VERSION, Lockfile};
pub use npm_package_lock::{PackageLockRoot, to_package_lock_json, to_package_lock_v3};
pub use resolver::Resolver;
