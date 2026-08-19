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

use crate::asciicast::EventKind;
use crate::record::RecorderHandle;

/// How a [`bridge`] ended, so the caller can report the right `SessionEnded`
/// reason to warden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The control plane signalled `cancel` (a warden `Teardown`).
    Terminated,
    /// A channel closed / hit EOF naturally (the client or target ended it).
    Closed,
    /// A required recording could not keep up (its channel overflowed/closed):
    /// fail closed — the session is torn down rather than run unrecorded.
    RecordingFailed,
}

impl BridgeOutcome {
    /// The `SessionEnded.reason` string warden expects for this outcome.
    pub fn reason(self) -> &'static str {
        match self {
            BridgeOutcome::Terminated => "terminated",
            BridgeOutcome::Closed => "closed",
            BridgeOutcome::RecordingFailed => "recording_failed",
        }
    }
}

/// Record one bridged frame into the session recording, if recording is active.
///
/// Returns `true` when recording is healthy (no recorder, or the event was
/// accepted) and `false` when a present recorder's channel overflowed/closed —
/// the fail-closed signal the bridge turns into [`BridgeOutcome::RecordingFailed`].
/// `start` anchors the event's session-relative timestamp.
fn tap_event(
    recorder: Option<&RecorderHandle>,
    start: std::time::Instant,
    kind: EventKind,
    data: Vec<u8>,
) -> bool {
    match recorder {
        Some(h) => h
            .try_event(start.elapsed().as_secs_f64(), kind, data)
            .is_ok(),
        None => true,
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
    recorder: Option<RecorderHandle>,
) -> anyhow::Result<BridgeOutcome> {
    let (mut client_read, client_write) = client_channel.split();
    let (mut target_read, target_write) = target_channel.split();

    // Session-relative event timestamps for the asciicast stream.
    let start = std::time::Instant::now();

    // A required recording that can't keep up (channel overflow/closed) fails the
    // whole session. `feed` records the event and, on overflow, flags fail-closed.
    let mut recording_failed = false;
    macro_rules! feed {
        ($kind:expr, $data:expr) => {
            if !tap_event(recorder.as_ref(), start, $kind, $data) {
                recording_failed = true;
            }
        };
    }

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
                        feed!(EventKind::Input, data.to_vec());
                        if recording_failed { outcome = BridgeOutcome::RecordingFailed; break; }
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
                        feed!(EventKind::Resize, format!("{col_width}x{row_height}").into_bytes());
                        if recording_failed { outcome = BridgeOutcome::RecordingFailed; break; }
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
                        feed!(EventKind::Output, data.to_vec());
                        if recording_failed { outcome = BridgeOutcome::RecordingFailed; break; }
                        client_write.data_bytes(data).await?;
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        feed!(EventKind::Output, data.to_vec());
                        if recording_failed { outcome = BridgeOutcome::RecordingFailed; break; }
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
    use crate::record::RecMsg;

    #[test]
    fn outcome_maps_to_session_ended_reason() {
        assert_eq!(BridgeOutcome::Terminated.reason(), "terminated");
        assert_eq!(BridgeOutcome::Closed.reason(), "closed");
        assert_eq!(BridgeOutcome::RecordingFailed.reason(), "recording_failed");
    }

    #[test]
    fn tap_without_recorder_is_always_healthy() {
        // No recorder → the frame is not recorded but the bridge stays healthy.
        assert!(tap_event(
            None,
            std::time::Instant::now(),
            EventKind::Output,
            b"x".to_vec(),
        ));
    }

    /// The bridge tap maps each direction/frame kind to the right asciicast event:
    /// client input → `i`, target output → `o`, window-change → `r` (`WxH`).
    #[tokio::test]
    async fn tap_maps_input_output_and_resize_events() {
        let (handle, mut rx) = RecorderHandle::for_test(16);
        let start = std::time::Instant::now();

        assert!(tap_event(
            Some(&handle),
            start,
            EventKind::Input,
            b"ls\n".to_vec()
        ));
        assert!(tap_event(
            Some(&handle),
            start,
            EventKind::Output,
            b"file\n".to_vec()
        ));
        assert!(tap_event(
            Some(&handle),
            start,
            EventKind::Resize,
            b"120x40".to_vec()
        ));

        let want = [
            (EventKind::Input, b"ls\n".to_vec()),
            (EventKind::Output, b"file\n".to_vec()),
            (EventKind::Resize, b"120x40".to_vec()),
        ];
        for (want_kind, want_data) in want {
            match rx.recv().await.expect("event present") {
                RecMsg::Event { kind, data, .. } => {
                    assert_eq!(kind, want_kind);
                    assert_eq!(data, want_data);
                }
                _ => panic!("expected an Event message"),
            }
        }
    }

    /// A recorder whose channel has overflowed (receiver gone / full) makes the
    /// tap report unhealthy — the fail-closed signal for the bridge.
    #[test]
    fn tap_overflow_is_unhealthy() {
        let (handle, rx) = RecorderHandle::for_test(1);
        drop(rx); // closed channel → try_event errors
        assert!(!tap_event(
            Some(&handle),
            std::time::Instant::now(),
            EventKind::Output,
            b"x".to_vec(),
        ));
    }
}
