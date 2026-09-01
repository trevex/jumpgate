//! Streaming session recorder: consumes recorded `(millis, action, payload)`
//! graphics frames, encodes them as `rdp-graphics-v1` (a [`record_format::Header`]
//! written first, then a stream of `record_format::write_frame` records), and
//! buffers them into multipart-upload parts. A part is uploaded to object storage
//! once it reaches the part-size floor ([`MIN_PART_SIZE`], 5 MiB — S3's minimum
//! for a non-final part), so a session buffers up to one part in memory and
//! uploads per part rather than streaming continuously; a low-traffic session's
//! bytes are not durable until it accumulates a full part. A rolling SHA-256 is
//! kept over the exact bytes written. On finish it completes the multipart upload
//! (or on failure aborts it) and returns a [`RecordingReport`].
//!
//! This is ssh-proxy's `record.rs` with ONLY the encoding swapped
//! (asciicast → rdp-graphics); the S3/uploader/fail-closed machinery is identical.
//! The multipart backend is abstracted behind [`PartUploader`] so the recorder
//! can be unit-tested without a real object store; [`S3Uploader`] is the
//! production implementation: it signs S3 multipart requests with `rusty-s3` and
//! issues them over a `reqwest` client whose rustls TLS uses the ring crypto
//! provider (so no `aws-lc-rs` is pulled into the workspace).

use rusty_s3::actions::{CreateMultipartUpload, S3Action};
use rusty_s3::{Bucket, Credentials, UrlStyle};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::record_format;

/// Presigned-URL lifetime for each signed S3 request. Requests are issued
/// immediately after signing, so a short window is ample.
const URL_TTL: Duration = Duration::from_secs(15 * 60);

/// The minimum size (5 MiB) for any multipart-upload part except the last, per
/// the S3 multipart contract. The recorder only flushes a part early once the
/// buffer reaches at least this much; the final flush may be smaller.
pub const MIN_PART_SIZE: usize = 5 * 1024 * 1024;

/// Abstraction over an in-progress multipart upload, so the recorder is
/// testable without a real object store.
#[async_trait::async_trait]
pub trait PartUploader: Send + Sync {
    /// Upload one part (1-indexed `part_number`). Parts except the last must be
    /// >= 5 MiB.
    async fn upload_part(&self, part_number: i32, bytes: Vec<u8>) -> anyhow::Result<()>;
    /// Finalize the multipart upload (assemble all uploaded parts).
    async fn complete(&self) -> anyhow::Result<()>;
    /// Abort the multipart upload, discarding parts.
    async fn abort(&self);
}

/// Forward the trait through a boxed uploader so `server.rs` can create the
/// (non-generic) `S3Uploader` up front, hand `bridge::run` an
/// `Option<Box<dyn PartUploader>>`, and still feed it to the generic
/// [`spawn_recorder`].
#[async_trait::async_trait]
impl PartUploader for Box<dyn PartUploader> {
    async fn upload_part(&self, part_number: i32, bytes: Vec<u8>) -> anyhow::Result<()> {
        (**self).upload_part(part_number, bytes).await
    }
    async fn complete(&self) -> anyhow::Result<()> {
        (**self).complete().await
    }
    async fn abort(&self) {
        (**self).abort().await
    }
}

/// Build a rustls client config that uses the ring crypto provider explicitly,
/// with Mozilla's webpki trust anchors. Selecting the provider by hand keeps
/// `aws-lc-rs` out of the dependency tree and avoids relying on a process-wide
/// default provider (the mesh installs ring; this stays consistent).
fn ring_rustls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider supports default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth()
}

/// Production [`PartUploader`] backed by an S3 multipart upload. Requests are
/// signed by `rusty-s3` and sent over a ring-backed rustls `reqwest::Client`.
pub struct S3Uploader {
    bucket: Bucket,
    creds: Credentials,
    http: reqwest::Client,
    key: String,
    upload_id: String,
    parts: tokio::sync::Mutex<Vec<(u16, String)>>,
}

impl S3Uploader {
    /// Begin a multipart upload against `bucket`/`key` and capture its
    /// `upload_id`. Credentials are read from `AWS_ACCESS_KEY_ID` /
    /// `AWS_SECRET_ACCESS_KEY`. An empty `endpoint` is rejected; a non-empty
    /// custom endpoint enables path-style addressing for self-hosted stores.
    pub async fn create(
        endpoint: &str,
        region: &str,
        bucket: &str,
        key: String,
    ) -> anyhow::Result<S3Uploader> {
        if endpoint.is_empty() {
            anyhow::bail!("recording endpoint not configured");
        }
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(ring_rustls_config())
            .build()?;
        let endpoint_url = url::Url::parse(endpoint)
            .map_err(|e| anyhow::anyhow!("invalid recording endpoint {endpoint:?}: {e}"))?;
        let bucket = Bucket::new(
            endpoint_url,
            UrlStyle::Path,
            bucket.to_string(),
            region.to_string(),
        )
        .map_err(|e| anyhow::anyhow!("invalid bucket config: {e}"))?;
        let access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| anyhow::anyhow!("AWS_ACCESS_KEY_ID not set"))?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| anyhow::anyhow!("AWS_SECRET_ACCESS_KEY not set"))?;
        let creds = Credentials::new(access_key, secret_key);

        let action = bucket.create_multipart_upload(Some(&creds), &key);
        let url = action.sign(URL_TTL);
        let resp = http.post(url).send().await?;
        let resp = resp.error_for_status()?;
        let body = resp.text().await?;
        let parsed = CreateMultipartUpload::parse_response(&body)
            .map_err(|e| anyhow::anyhow!("parse create_multipart_upload response: {e}"))?;
        let upload_id = parsed.upload_id().to_string();

        Ok(S3Uploader {
            bucket,
            creds,
            http,
            key,
            upload_id,
            parts: tokio::sync::Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl PartUploader for S3Uploader {
    async fn upload_part(&self, part_number: i32, bytes: Vec<u8>) -> anyhow::Result<()> {
        let part_number = u16::try_from(part_number)
            .map_err(|_| anyhow::anyhow!("part number {part_number} out of range"))?;
        let action =
            self.bucket
                .upload_part(Some(&self.creds), &self.key, part_number, &self.upload_id);
        let url = action.sign(URL_TTL);
        let resp = self.http.put(url).body(bytes).send().await?;
        let resp = resp.error_for_status()?;
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .ok_or_else(|| anyhow::anyhow!("upload_part response missing ETag header"))?
            .to_str()
            .map_err(|e| anyhow::anyhow!("upload_part ETag not valid text: {e}"))?
            .to_string();
        self.parts.lock().await.push((part_number, etag));
        Ok(())
    }

    async fn complete(&self) -> anyhow::Result<()> {
        let mut parts = self.parts.lock().await.clone();
        parts.sort_by_key(|(n, _)| *n);
        let etags: Vec<String> = parts.into_iter().map(|(_, etag)| etag).collect();
        let action = self.bucket.complete_multipart_upload(
            Some(&self.creds),
            &self.key,
            &self.upload_id,
            etags.iter().map(String::as_str),
        );
        let url = action.sign(URL_TTL);
        let body = action.body();
        let resp = self.http.post(url).body(body).send().await?;
        resp.error_for_status()?;
        Ok(())
    }

    async fn abort(&self) {
        let action =
            self.bucket
                .abort_multipart_upload(Some(&self.creds), &self.key, &self.upload_id);
        let url = action.sign(URL_TTL);
        if let Err(err) = self
            .http
            .delete(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            tracing::warn!(error = %err, key = %self.key, "failed to abort multipart upload");
        }
    }
}

/// Terminal state of a recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordStatus {
    Completed,
    Failed,
}

/// Summary of a finished recording, returned by the recorder task. The caller
/// (server.rs) stamps wall-clock timestamps; this crate keeps wall-clock out of
/// the encoder.
#[derive(Debug, Clone)]
pub struct RecordingReport {
    pub size_bytes: i64,
    pub sha256_hex: String,
    pub status: RecordStatus,
}

/// Recorder tuning.
#[derive(Debug, Clone, Copy)]
pub struct RecorderConfig {
    /// Flush threshold in bytes; the buffer is flushed as a part once it reaches
    /// this size. Defaults to [`MIN_PART_SIZE`].
    pub part_size: usize,
    /// Bounded mpsc channel capacity.
    pub channel_bound: usize,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            part_size: MIN_PART_SIZE,
            channel_bound: 256,
        }
    }
}

/// A message consumed by the recorder task.
pub enum RecMsg {
    /// A single recorded graphics frame to encode and append.
    Frame {
        millis: u64,
        action: u8,
        data: Vec<u8>,
    },
    /// Flush the remaining buffer and complete the upload.
    Finish,
    /// Abort the upload; the recording failed.
    Fail,
}

/// Handle used by the session to feed frames into the recorder task. Cheaply
/// cloneable (an mpsc sender): the bridge tap holds one clone while the finalize
/// path keeps another to `finish`/`fail` the recording after the pump returns.
#[derive(Clone)]
pub struct RecorderHandle {
    tx: mpsc::Sender<RecMsg>,
}

impl RecorderHandle {
    /// Non-blocking send of a graphics frame. `Err(())` means the channel is full
    /// or closed — a fail-closed trigger for the caller. The unit error is
    /// deliberate: the caller only needs the fail-closed signal, not a reason.
    #[allow(clippy::result_unit_err)]
    pub fn try_frame(&self, millis: u64, action: u8, data: Vec<u8>) -> Result<(), ()> {
        self.tx
            .try_send(RecMsg::Frame {
                millis,
                action,
                data,
            })
            .map_err(|_| ())
    }

    /// Signal the recorder to flush and complete. Ignores the error if the task
    /// is already gone.
    pub async fn finish(&self) {
        let _ = self.tx.send(RecMsg::Finish).await;
    }

    /// Signal the recorder to abort. Ignores the error if the task is already
    /// gone.
    pub async fn fail(&self) {
        let _ = self.tx.send(RecMsg::Fail).await;
    }

    /// Test-only: build a handle over a raw channel so a test can observe the
    /// exact [`RecMsg`]s a producer (e.g. the bridge tap) emits.
    #[cfg(test)]
    pub(crate) fn for_test(bound: usize) -> (RecorderHandle, mpsc::Receiver<RecMsg>) {
        let (tx, rx) = mpsc::channel(bound);
        (RecorderHandle { tx }, rx)
    }
}

/// Internal recorder state driving the consume loop.
struct Recorder<U: PartUploader> {
    uploader: U,
    part_size: usize,
    buffer: Vec<u8>,
    hasher: Sha256,
    size_bytes: i64,
    next_part_number: i32,
}

impl<U: PartUploader> Recorder<U> {
    fn new(uploader: U, part_size: usize) -> Self {
        Self {
            uploader,
            part_size,
            buffer: Vec::new(),
            hasher: Sha256::new(),
            size_bytes: 0,
            next_part_number: 1,
        }
    }

    /// Append encoded bytes to the buffer and roll them into the hash + counter.
    fn append(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.size_bytes += bytes.len() as i64;
        self.buffer.extend_from_slice(bytes);
    }

    /// Flush the current buffer as the next part. `final_flush` allows a part
    /// smaller than 5 MiB (the last part); a non-final flush only runs when the
    /// buffer already reached the threshold.
    async fn flush(&mut self, final_flush: bool) -> anyhow::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if !final_flush && self.buffer.len() < MIN_PART_SIZE {
            return Ok(());
        }
        let part_number = self.next_part_number;
        self.next_part_number += 1;
        let bytes = std::mem::take(&mut self.buffer);
        self.uploader.upload_part(part_number, bytes).await
    }

    fn report(&mut self, status: RecordStatus) -> RecordingReport {
        RecordingReport {
            size_bytes: self.size_bytes,
            sha256_hex: hex::encode(self.hasher.clone().finalize()),
            status,
        }
    }

    /// Run the consume loop until a terminal message or channel close, and
    /// produce the report. `header` is written as the first bytes.
    async fn run(
        mut self,
        header: record_format::Header,
        mut rx: mpsc::Receiver<RecMsg>,
    ) -> RecordingReport {
        // The header is the first bytes of the recording (writing into a Vec is
        // infallible; the io::Result only matters for real writers).
        let mut header_bytes = Vec::new();
        let _ = header.write(&mut header_bytes);
        self.append(&header_bytes);

        while let Some(msg) = rx.recv().await {
            match msg {
                RecMsg::Frame {
                    millis,
                    action,
                    data,
                } => {
                    let mut frame_bytes = Vec::new();
                    let _ = record_format::write_frame(&mut frame_bytes, millis, action, &data);
                    self.append(&frame_bytes);
                    if self.buffer.len() >= self.part_size {
                        if let Err(err) = self.flush(false).await {
                            tracing::warn!(error = %err, "recorder part upload failed; aborting");
                            self.uploader.abort().await;
                            return self.report(RecordStatus::Failed);
                        }
                    }
                }
                RecMsg::Finish => {
                    if let Err(err) = self.flush(true).await {
                        tracing::warn!(error = %err, "recorder final flush failed; aborting");
                        self.uploader.abort().await;
                        return self.report(RecordStatus::Failed);
                    }
                    if let Err(err) = self.uploader.complete().await {
                        tracing::warn!(error = %err, "recorder complete failed; aborting");
                        self.uploader.abort().await;
                        return self.report(RecordStatus::Failed);
                    }
                    return self.report(RecordStatus::Completed);
                }
                RecMsg::Fail => {
                    self.uploader.abort().await;
                    return self.report(RecordStatus::Failed);
                }
            }
        }

        // The channel closed without an explicit Finish/Fail (all handles
        // dropped): treat it as a failure and abort so no dangling multipart
        // upload is left behind.
        self.uploader.abort().await;
        self.report(RecordStatus::Failed)
    }
}

/// Spawn the recorder task. Returns the handle plus a [`tokio::task::JoinHandle`]
/// producing the [`RecordingReport`].
pub fn spawn_recorder<U: PartUploader + 'static>(
    uploader: U,
    header: record_format::Header,
    cfg: RecorderConfig,
) -> (RecorderHandle, tokio::task::JoinHandle<RecordingReport>) {
    let (tx, rx) = mpsc::channel(cfg.channel_bound);
    let recorder = Recorder::new(uploader, cfg.part_size);
    let join = tokio::spawn(recorder.run(header, rx));
    (RecorderHandle { tx }, join)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record_format::{compression, write_frame, Header, ACTION_FASTPATH, ACTION_X224};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    fn test_header() -> Header {
        Header {
            width: 1280,
            height: 1024,
            user_channel_id: 1004,
            io_channel_id: 1003,
            message_channel_id: Some(1005),
            share_id: 0x1234_5678,
            compression: compression::RDP61,
            enable_server_pointer: false,
            pointer_software_rendering: true,
        }
    }

    /// In-memory [`PartUploader`] recording every call for assertions.
    struct MockUploader {
        parts: Mutex<Vec<(i32, Vec<u8>)>>,
        completed: AtomicBool,
        aborted: AtomicBool,
        fail_on_part: Option<i32>,
    }

    impl MockUploader {
        fn new(fail_on_part: Option<i32>) -> Self {
            Self {
                parts: Mutex::new(Vec::new()),
                completed: AtomicBool::new(false),
                aborted: AtomicBool::new(false),
                fail_on_part,
            }
        }
    }

    #[async_trait::async_trait]
    impl PartUploader for MockUploader {
        async fn upload_part(&self, part_number: i32, bytes: Vec<u8>) -> anyhow::Result<()> {
            if self.fail_on_part == Some(part_number) {
                anyhow::bail!("injected upload_part failure on part {part_number}");
            }
            self.parts.lock().unwrap().push((part_number, bytes));
            Ok(())
        }

        async fn complete(&self) -> anyhow::Result<()> {
            self.completed.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn abort(&self) {
            self.aborted.store(true, Ordering::SeqCst);
        }
    }

    /// A [`PartUploader`] that shares its recorded state via an `Arc` so a test
    /// can inspect it after the recorder task has consumed the value.
    struct MockUploaderShared {
        inner: std::sync::Arc<MockUploader>,
    }

    impl MockUploaderShared {
        fn new(fail_on_part: Option<i32>) -> Self {
            Self {
                inner: std::sync::Arc::new(MockUploader::new(fail_on_part)),
            }
        }
    }

    #[async_trait::async_trait]
    impl PartUploader for MockUploaderShared {
        async fn upload_part(&self, part_number: i32, bytes: Vec<u8>) -> anyhow::Result<()> {
            self.inner.upload_part(part_number, bytes).await
        }
        async fn complete(&self) -> anyhow::Result<()> {
            self.inner.complete().await
        }
        async fn abort(&self) {
            self.inner.abort().await
        }
    }

    /// HAPPY PATH: a header + N frames complete, the report carries a non-empty
    /// sha256 and a size equal to header+frames bytes, and the concatenation of
    /// uploaded parts equals the independently-encoded byte stream.
    #[tokio::test]
    async fn completes_and_hashes() {
        let header = test_header();
        let uploader = std::sync::Arc::new(MockUploader::new(None));
        let cfg = RecorderConfig {
            part_size: 1024,
            channel_bound: 64,
        };

        // Independently recompute the expected recording bytes/hash.
        let frames: Vec<(u64, u8, Vec<u8>)> = (0..64u64)
            .map(|i| {
                let action = if i % 2 == 0 {
                    ACTION_FASTPATH
                } else {
                    ACTION_X224
                };
                (
                    i * 10,
                    action,
                    format!("graphics frame {i} with some padding payload").into_bytes(),
                )
            })
            .collect();

        let mut expected = Vec::new();
        header.write(&mut expected).unwrap();
        for (millis, action, data) in &frames {
            write_frame(&mut expected, *millis, *action, data).unwrap();
        }
        assert!(
            expected.len() > cfg.part_size,
            "test must exceed part_size to force a flush"
        );
        let expected_hash = hex::encode(Sha256::digest(&expected));

        // Wrap the Arc so the spawned task holds one clone while the test keeps
        // another for assertions.
        struct ArcUploader(std::sync::Arc<MockUploader>);
        #[async_trait::async_trait]
        impl PartUploader for ArcUploader {
            async fn upload_part(&self, part_number: i32, bytes: Vec<u8>) -> anyhow::Result<()> {
                self.0.upload_part(part_number, bytes).await
            }
            async fn complete(&self) -> anyhow::Result<()> {
                self.0.complete().await
            }
            async fn abort(&self) {
                self.0.abort().await
            }
        }

        let (handle, join) = spawn_recorder(ArcUploader(uploader.clone()), header, cfg);
        for (millis, action, data) in &frames {
            handle.try_frame(*millis, *action, data.clone()).expect("send");
        }
        handle.finish().await;
        let report = join.await.expect("join");

        assert_eq!(report.status, RecordStatus::Completed);
        assert!(uploader.completed.load(Ordering::SeqCst));
        assert!(!uploader.aborted.load(Ordering::SeqCst));
        assert!(!report.sha256_hex.is_empty(), "digest must be present");
        assert_eq!(report.sha256_hex, expected_hash);
        assert_eq!(report.size_bytes, expected.len() as i64);

        // At least one part was flushed, and the concatenation of all parts
        // equals the expected byte stream (header first, then frames).
        let parts = uploader.parts.lock().unwrap();
        assert!(!parts.is_empty(), "expected at least one uploaded part");
        let mut sorted: Vec<_> = parts.clone();
        sorted.sort_by_key(|(n, _)| *n);
        let mut assembled = Vec::new();
        for (_, bytes) in sorted {
            assembled.extend_from_slice(&bytes);
        }
        assert_eq!(assembled, expected);
    }

    /// FAIL CLOSED: when `upload_part` errors, the recorder task aborts the
    /// multipart upload and reports `Failed` (never `Completed`).
    #[tokio::test]
    async fn aborts_on_uploader_error() {
        let uploader = MockUploaderShared::new(Some(1));
        let inner = uploader.inner.clone();
        let cfg = RecorderConfig {
            part_size: 1024,
            channel_bound: 64,
        };

        let (handle, join) = spawn_recorder(uploader, test_header(), cfg);
        // Feed more than part_size to force a (failing) flush of part 1.
        let big = vec![b'x'; 4096];
        handle.try_frame(0, ACTION_FASTPATH, big).expect("send");
        handle.finish().await;
        let report = join.await.expect("join");

        assert_eq!(report.status, RecordStatus::Failed);
        assert!(inner.aborted.load(Ordering::SeqCst));
        assert!(!inner.completed.load(Ordering::SeqCst));
    }

    /// An explicit `fail()` signal aborts the upload and reports `Failed`.
    #[tokio::test]
    async fn fail_signal_aborts() {
        let uploader = MockUploaderShared::new(None);
        let inner = uploader.inner.clone();
        let cfg = RecorderConfig {
            part_size: 1024,
            channel_bound: 64,
        };

        let (handle, join) = spawn_recorder(uploader, test_header(), cfg);
        handle.try_frame(0, ACTION_FASTPATH, b"hi".to_vec()).expect("send");
        handle.fail().await;
        let report = join.await.expect("join");

        assert_eq!(report.status, RecordStatus::Failed);
        assert!(inner.aborted.load(Ordering::SeqCst));
        assert!(!inner.completed.load(Ordering::SeqCst));
    }

    /// A closed channel (receiver dropped) makes `try_frame` fail-closed.
    #[tokio::test]
    async fn try_send_overflow_maps_to_err() {
        let (tx, rx) = mpsc::channel::<RecMsg>(1);
        drop(rx);
        let handle = RecorderHandle { tx };
        assert_eq!(handle.try_frame(0, ACTION_FASTPATH, b"x".to_vec()), Err(()));
    }
}
