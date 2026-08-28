//! husk: a local-first developer security scanner.
//!
//! One binary that scans a developer machine for vulnerable packages, leaked
//! secrets, risky install scripts / git hooks / CI workflows, and unsafe
//! AI-agent/MCP configuration, surfaced through a CLI, a Ratatui TUI, an
//! optional localhost web UI, and an MCP server for AI agents. Scans are
//! strictly read-only: husk never executes package managers, install scripts,
//! git hooks, or any code it scans.
//!
//! Three pluggable registries do the extensible work:
//!
//! - [`scan::targets::ScanTarget`]: "files on disk → package coordinates";
//!   one module per ecosystem, registered in
//!   [`scan::targets::default_targets`].
//! - `providers::IntelSource`: "package coordinates → advisory findings";
//!   one public advisory/malware backend per source, registered in
//!   `providers::INTEL_SOURCES`.
//! - [`scan::checks::Check`]: file-content detectors (secrets, lifecycle
//!   scripts, agent configs, prompt injection), each owning its entries in the
//!   `Rule` catalog.
//!
//! [`model`] is the shared vocabulary every surface renders from; the
//! [`scan`] pipeline produces a [`model::ScanReport`] and streams progress
//! through [`model::LiveScan`].
//!
//! # Not a stable API
//!
//! This crate is primarily the `husk` *binary*. The library target exists for
//! the binary and husk's own integration tests; it is **not a semver-stable
//! API** and may change in any release. If you want to embed the scanner as a
//! library, please open an issue; a properly versioned core-library split is
//! on the roadmap for pre-1.0.

// Shipping code carries zero `unsafe`. The only exception is test-only setup
// that mutates process environment variables, which is `unsafe` under the 2024
// edition; those call sites are individually documented with SAFETY comments,
// so we forbid unsafe everywhere except the test build.
#![cfg_attr(not(test), forbid(unsafe_code))]

// The entire intended library surface; see the crate docs above for the
// stability caveat.
pub mod cli;
pub mod cloud;
pub mod history;
pub mod mcp;
pub mod model;
pub mod remediation;
// Public because the model is: `Finding.category`/`rule_id`/`confidence` are
// `rule::Category`/`RuleId`/`Confidence`, so consumers of `model` need to name
// these types.
pub mod rule;
pub mod scan;
pub mod score;
pub mod term;
pub mod tui;
pub mod version;

mod agent;
pub mod cache;
mod check;
mod context;
mod daemon;
mod export;
mod gitcmd;
pub mod guide;
mod hash;
pub mod highlight;
pub mod intel;
mod ledger;
mod paths;
mod policy;
mod prioritize;
mod project;
pub mod projects;
mod providers;
#[cfg(feature = "web")]
mod web;
