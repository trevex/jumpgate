//! jumpgate rdp-proxy worker library crate.
//!
//! The data-plane front door for jumpgate RDP sessions: an mTLS server that
//! accepts the gateway's connection (pinned to the gateway's mesh SPIFFE id),
//! reads the HTTP/1.1 CONNECT preamble, redeems the session with warden, performs
//! the full IronRDP handshake with the injected password (credentials never reach
//! the browser), then relays `(action, payload)` PDUs to the browser's
//! `ActiveStage`. Exposed as a library so integration tests can reach [`config`]
//! and [`server`] directly.

pub mod bridge;
pub mod config;
pub mod control;
pub mod frame;
pub mod record_format;
pub mod server;
pub mod setup;
