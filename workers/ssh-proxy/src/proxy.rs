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

/// Bridge the client channel and the target channel until one closes or `cancel`
/// fires.
///
/// Data flows both directions. The client's `WindowChange` is forwarded to the
/// target so a remote pty resizes with the local terminal. The target's
/// `ExitStatus` is relayed to the client before teardown; an `ExitSignal` is
/// logged (the client channel API exposes exit-status but not exit-signal).
/// On `cancel`, both channels are closed and the bridge returns.
pub async fn bridge(
    client_channel: Channel<server::Msg>,
    target_channel: Channel<client::Msg>,
    cancel: Arc<Notify>,
) -> anyhow::Result<()> {
    let (mut client_read, client_write) = client_channel.split();
    let (mut target_read, target_write) = target_channel.split();

    // Reason recorded only for the trailing debug log; the bridge always tries
    // to close both sides cleanly regardless.
    let reason;

    loop {
        tokio::select! {
            // Teardown requested by the control plane.
            _ = cancel.notified() => {
                reason = "cancelled";
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
                        reason = "client closed";
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
                        reason = "target closed";
                        break;
                    }
                    Some(_) => {}
                }
            }
        }
    }

    tracing::debug!(reason, "channel bridge finished; closing both sides");
    // Best-effort close of both directions; the peer may already be gone.
    let _ = client_write.eof().await;
    let _ = client_write.close().await;
    let _ = target_write.eof().await;
    let _ = target_write.close().await;

    Ok(())
}
