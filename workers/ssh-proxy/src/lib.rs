//! ssh-proxy worker library crate.
//!
//! The data-plane front door for jumpgate SSH sessions: an mTLS server that
//! accepts the gateway's connection (pinned to the gateway's mesh SPIFFE id),
//! reads the HTTP/1.1 CONNECT preamble, and (later) terminates the SSH session
//! and hops to the target. Exposed as a library so integration tests can reach
//! [`config`] and [`server`] directly.

pub mod config;
pub mod control;
pub mod server;
pub mod setup;
