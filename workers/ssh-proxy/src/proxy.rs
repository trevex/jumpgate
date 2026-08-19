//! Bidirectional bridge between the client's SSH channel and the target's.
//!
//! After the target channel is opened and the requested shell/exec is running,
//! this pumps bytes both ways, forwards the client's pty window-change to the
//! target, relays the target's exit-status back to the client, and closes both
//! sides when either end closes or a teardown is signalled.

use std::sync::Arc;

use russh::client;
use russh::server;
use russh::{Channel, ChannelMsg};
use tokio::sync::Notify;

/// How a [`bridge`] ended, so the caller can report the right `SessionEnded`
/// reason to warden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The control plane signalled `cancel` (a warden `Teardown`).
    Terminated,
    /// A channel closed / hit EOF naturally (the client or target ended it).
    Closed,
}

impl BridgeOutcome {
    /// The `SessionEnded.reason` string warden expects for this outcome.
    pub fn reason(self) -> &'static str {
        match self {
            BridgeOutcome::Terminated => "terminated",
            BridgeOutcome::Closed => "closed",
        }
    }
}

/// Bridge the client channel and the target channel until one closes or `cancel`
/// fires.
///
/// Data flows both directions. The client's `WindowChange` is forwarded to the
/// target so a remote pty resizes with the local terminal. The target's
/// `ExitStatus` is relayed to the client before teardown; an `ExitSignal` is
/// logged (the client channel API exposes exit-status but not exit-signal).
/// On `cancel`, both channels are closed and the bridge returns.
///
/// Returns the [`BridgeOutcome`] distinguishing a control-plane teardown from a
/// natural channel close, alongside any I/O error hit while pumping bytes.
pub async fn bridge(
    client_channel: Channel<server::Msg>,
    target_channel: Channel<client::Msg>,
    cancel: Arc<Notify>,
) -> anyhow::Result<BridgeOutcome> {
    let (mut client_read, client_write) = client_channel.split();
    let (mut target_read, target_write) = target_channel.split();

    // Why the loop exited: a control-plane teardown vs a natural channel close.
    let outcome;

    loop {
        tokio::select! {
            // Teardown requested by the control plane.
            _ = cancel.notified() => {
                outcome = BridgeOutcome::Terminated;
                break;
            }

            // Client -> target.
            msg = client_read.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        target_write.data_bytes(data).await?;
                    }
                    Some(ChannelMsg::Eof) => {
                        target_write.eof().await?;
                    }
                    Some(ChannelMsg::WindowChange {
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                    }) => {
                        target_write
                            .window_change(col_width, row_height, pix_width, pix_height)
                            .await?;
                    }
                    Some(ChannelMsg::Close) | None => {
                        outcome = BridgeOutcome::Closed;
                        break;
                    }
                    // pty/shell/exec requests are handled before the bridge starts;
                    // anything else in this direction is not proxied.
                    Some(_) => {}
                }
            }

            // Target -> client.
            msg = target_read.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        client_write.data_bytes(data).await?;
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        client_write.extended_data_bytes(ext, data).await?;
                    }
                    Some(ChannelMsg::Eof) => {
                        client_write.eof().await?;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        client_write.exit_status(exit_status).await?;
                    }
                    Some(ChannelMsg::ExitSignal {
                        signal_name,
                        core_dumped,
                        error_message,
                        ..
                    }) => {
                        tracing::info!(
                            signal = ?signal_name,
                            core_dumped,
                            error_message = %error_message,
                            "target process exited via signal",
                        );
                    }
                    Some(ChannelMsg::Close) | None => {
                        outcome = BridgeOutcome::Closed;
                        break;
                    }
                    Some(_) => {}
                }
            }
        }
    }

    tracing::debug!(?outcome, "channel bridge finished; closing both sides");
    // Best-effort close of both directions; the peer may already be gone.
    let _ = client_write.eof().await;
    let _ = client_write.close().await;
    let _ = target_write.eof().await;
    let _ = target_write.close().await;

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_maps_to_session_ended_reason() {
        assert_eq!(BridgeOutcome::Terminated.reason(), "terminated");
        assert_eq!(BridgeOutcome::Closed.reason(), "closed");
    }
}
