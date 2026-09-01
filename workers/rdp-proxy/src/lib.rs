//! jumpgate rdp-proxy worker library crate.
//!
//! The data-plane front door for jumpgate RDP sessions: an mTLS server that
//! accepts the gateway's connection (pinned to the gateway's mesh SPIFFE id),
//! reads the HTTP/1.1 CONNECT preamble, redeems the session with warden, then runs
//! the RDCleanPath [`bridge`] — the worker does the TCP+X.224+TLS hop to the target
//! and relays plaintext RDP, injecting the vault credentials into the browser's
//! Client Info PDU (credentials never reach the browser, which runs the full
//! IronRDP connector + `ActiveStage`). Exposed as a library so integration tests
//! can reach [`config`] and [`server`] directly.

pub mod bridge;
pub mod config;
pub mod control;
pub mod record;
pub mod record_format;
pub mod server;
pub mod setup;
