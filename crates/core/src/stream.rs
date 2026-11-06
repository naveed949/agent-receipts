use std::fmt;
use std::io;
use std::num::NonZeroUsize;

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

pub const DEFAULT_STREAM_CAPACITY: usize = 32;
pub const DEFAULT_MAX_LINE_LEN: usize = 1_048_576;

const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(DEFAULT_STREAM_CAPACITY) {
    Some(value) => value,
    None => panic!("DEFAULT_STREAM_CAPACITY is zero"),
};
const DEFAULT_MAX_LINE: NonZeroUsize = match NonZeroUsize::new(DEFAULT_MAX_LINE_LEN) {
    Some(value) => value,
    None => panic!("DEFAULT_MAX_LINE_LEN is zero"),
};

const _: () = assert!(DEFAULT_STREAM_CAPACITY > 0 && DEFAULT_MAX_LINE_LEN > 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamLimits {
    capacity: NonZeroUsize,
    max_line_len: NonZeroUsize,
}

impl StreamLimits {
    pub const fn with_capacity(mut self, capacity: usize) -> Result<Self, LimitsError> {
        match NonZeroUsize::new(capacity) {
            Some(capacity) => {
                self.capacity = capacity;
                Ok(self)
            }
            None => Err(LimitsError::ZeroCapacity),
        }
    }

    pub const fn with_max_line_len(mut self, max_line_len: usize) -> Result<Self, LimitsError> {
        match NonZeroUsize::new(max_line_len) {
            Some(max_line_len) => {
                self.max_line_len = max_line_len;
                Ok(self)
            }
            None => Err(LimitsError::ZeroMaxLineLen),
        }
    }

    pub const fn capacity(self) -> usize {
        self.capacity.get()
    }

    pub const fn max_line_len(self) -> usize {
        self.max_line_len.get()
    }

    pub const fn max_retained_line_bytes(self) -> usize {
        retained_line_bytes(self.capacity(), self.max_line_len())
    }
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            max_line_len: DEFAULT_MAX_LINE,
        }
    }
}

const fn retained_line_bytes(capacity: usize, max_line_len: usize) -> usize {
    let slots = match capacity.checked_add(2) {
        Some(slots) => slots,
        None => panic!("retained line bytes overflowed usize"),
    };
    let lines = match slots.checked_mul(max_line_len) {
        Some(lines) => lines,
        None => panic!("retained line bytes overflowed usize"),
    };
    match lines.checked_add(READ_CHUNK) {
        Some(total) => total,
        None => panic!("retained line bytes overflowed usize"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsError {
    ZeroCapacity,
    ZeroMaxLineLen,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            LimitsError::ZeroCapacity => "capacity must be greater than zero",
            LimitsError::ZeroMaxLineLen => "max_line_len must be greater than zero",
        })
    }
}

impl std::error::Error for LimitsError {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditReceiptCounts {
    pub ok: u64,
    pub invalid: u64,
    pub malformed: u64,
}

impl AuditReceiptCounts {
    pub const fn lines(self) -> u128 {
        self.ok as u128 + self.invalid as u128 + self.malformed as u128
    }

    fn add(&mut self, class: LineClass) {
        let field = match class {
            LineClass::Ok => &mut self.ok,
            LineClass::Invalid => &mut self.invalid,
            LineClass::Malformed => &mut self.malformed,
        };
        *field = field
            .checked_add(1)
            .expect("audit line counter overflowed u64");
    }
}

enum LineClass {
    Ok,
    Invalid,
    Malformed,
}

fn classify_line(body: &[u8], key: &[u8]) -> LineClass {
    if crate::verify_audit_receipt_bytes(body, key) {
        LineClass::Ok
    } else if crate::parse::parse(body).is_ok() {
        LineClass::Invalid
    } else {
        LineClass::Malformed
    }
}

const READ_CHUNK: usize = 8192;

enum FrameItem {
    Line(Vec<u8>),
    Malformed,
}

enum Scan {
    Body(Vec<u8>),
    Discard,
}

fn push_byte(scan: &mut Scan, byte: u8, max_line_len: usize) -> Option<FrameItem> {
    let overflow = match scan {
        Scan::Discard => {
            if byte != b'\n' {
                return None;
            }
            *scan = Scan::Body(Vec::new());
            return Some(FrameItem::Malformed);
        }
        Scan::Body(body) if byte == b'\n' => {
            let line = std::mem::take(body);
            return Some(FrameItem::Line(line));
        }
        Scan::Body(body) => body.len() == max_line_len,
    };
    if overflow {
        *scan = Scan::Discard;
    } else if let Scan::Body(body) = scan {
        body.push(byte);
    }
    None
}

fn finish_scan(scan: Scan) -> Option<FrameItem> {
    match scan {
        Scan::Discard => Some(FrameItem::Malformed),
        Scan::Body(body) if body.is_empty() => None,
        Scan::Body(_) => Some(FrameItem::Malformed),
    }
}

async fn emit(tx: &mpsc::Sender<FrameItem>, item: FrameItem) -> io::Result<()> {
    if tx.send(item).await.is_err() {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "verifier dropped",
        ));
    }
    tokio::task::coop::consume_budget().await;
    Ok(())
}

async fn read_frames<R>(
    mut reader: R,
    tx: mpsc::Sender<FrameItem>,
    max_line_len: usize,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut scratch = [0u8; READ_CHUNK];
    let mut scan = Scan::Body(Vec::new());
    loop {
        let n = reader.read(&mut scratch).await?;
        if n == 0 {
            if let Some(item) = finish_scan(scan) {
                emit(&tx, item).await?;
            }
            return Ok(());
        }
        let mut index = 0;
        while index < n {
            let byte = scratch[index];
            index += 1;
            if let Some(item) = push_byte(&mut scan, byte, max_line_len) {
                emit(&tx, item).await?;
            }
        }
    }
}

async fn verify_frames(mut rx: mpsc::Receiver<FrameItem>, key: &[u8]) -> AuditReceiptCounts {
    let mut counts = AuditReceiptCounts::default();
    while let Some(item) = rx.recv().await {
        let class = match item {
            FrameItem::Line(body) => classify_line(&body, key),
            FrameItem::Malformed => LineClass::Malformed,
        };
        counts.add(class);
        tokio::task::coop::consume_budget().await;
    }
    counts
}

#[must_use = "dropping the future cancels verification and yields no counts"]
pub async fn verify_audit_receipt_lines<R>(
    reader: R,
    key: &[u8],
    limits: StreamLimits,
) -> Result<AuditReceiptCounts, io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let (tx, rx) = mpsc::channel(limits.capacity());
    let read = read_frames(reader, tx, limits.max_line_len());
    let verify = async move { Ok(verify_frames(rx, key).await) };
    let ((), counts) = tokio::try_join!(read, verify)?;
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::task::{Context, Poll};

    use super::{
        classify_line, read_frames, verify_audit_receipt_lines, AuditReceiptCounts, LimitsError,
        LineClass, StreamLimits, DEFAULT_MAX_LINE_LEN, DEFAULT_STREAM_CAPACITY, READ_CHUNK,
    };
    use crate::{parse::parse, Json, Wtf16};
    use tokio::io::{AsyncRead, ReadBuf};

    #[test]
    fn limits_reject_zero_and_name_the_ceiling() {
        let limits = StreamLimits::default();
        assert_eq!(limits.capacity(), DEFAULT_STREAM_CAPACITY);
        assert_eq!(limits.max_line_len(), DEFAULT_MAX_LINE_LEN);
        assert_eq!(
            limits.max_retained_line_bytes(),
            (DEFAULT_STREAM_CAPACITY + 2) * DEFAULT_MAX_LINE_LEN + READ_CHUNK
        );
        assert_eq!(
            limits.with_capacity(0).unwrap_err(),
            LimitsError::ZeroCapacity
        );
        assert_eq!(
            limits.with_max_line_len(0).unwrap_err(),
            LimitsError::ZeroMaxLineLen
        );
        let tight = limits
            .with_capacity(1)
            .expect("capacity")
            .with_max_line_len(4)
            .expect("max line");
        assert_eq!(tight.capacity(), 1);
        assert_eq!(tight.max_line_len(), 4);
        assert_eq!(
            LimitsError::ZeroCapacity.to_string(),
            "capacity must be greater than zero"
        );
        assert_eq!(
            LimitsError::ZeroMaxLineLen.to_string(),
            "max_line_len must be greater than zero"
        );
        let counts = AuditReceiptCounts {
            ok: 1,
            invalid: 2,
            malformed: 3,
        };
        assert_eq!(counts.lines(), 6);
    }

    #[test]
    fn classify_line_matches_bytes_verify_on_compact_v1() {
        let (body, key) = v1_body_and_key();
        assert!(crate::verify_audit_receipt_bytes(&body, &key));
        assert!(matches!(classify_line(&body, &key), LineClass::Ok));
        let mut tampered = body.clone();
        flip_signature_hex(&mut tampered);
        assert!(!crate::verify_audit_receipt_bytes(&tampered, &key));
        assert!(parse(&tampered).is_ok());
        assert!(matches!(classify_line(&tampered, &key), LineClass::Invalid));
    }

    #[test]
    fn classify_line_marks_empty_whitespace_and_bad_json_malformed() {
        let (_body, key) = v1_body_and_key();
        let malformed: &[&[u8]] = &[
            b"",
            b" ",
            b"\t",
            b"\r",
            b" \t\r",
            b"{\"a\":1,\"a\":2}",
            b"{}{}",
            b"1 2",
            b"\xff",
        ];
        for body in malformed {
            assert!(
                matches!(classify_line(body, &key), LineClass::Malformed),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        assert!(matches!(
            classify_line(&nested_arrays(129), &key),
            LineClass::Malformed
        ));
        assert!(matches!(
            classify_line(&nested_arrays(128), &key),
            LineClass::Invalid
        ));
    }

    #[tokio::test]
    async fn identity_compact_v1_receipt_matches_bytes_verify() {
        let (body, key) = v1_body_and_key();
        assert!(crate::verify_audit_receipt_bytes(&body, &key));
        let mut line = body.clone();
        line.push(b'\n');
        let counts = count_bytes(&line, &key, StreamLimits::default()).await;
        assert_eq!(counts.ok, 1);
        assert_eq!(counts.invalid, 0);
        assert_eq!(counts.malformed, 0);
        assert_eq!(counts.lines(), 1);

        let mut crlf = body;
        crlf.extend_from_slice(b"\r\n");
        let kept = count_bytes(&crlf, &key, StreamLimits::default()).await;
        assert_eq!(kept.ok, 1);
        assert_eq!(kept.malformed, 0);
    }

    #[tokio::test]
    async fn invalid_versus_malformed_lines() {
        let (body, key) = v1_body_and_key();
        let mut bad = body.clone();
        flip_signature_hex(&mut bad);
        let mut file = Vec::new();
        push_line(&mut file, &bad);
        file.push(b'\n');
        file.extend_from_slice(b" \t\n");
        file.extend_from_slice(b"\r\n");
        file.extend_from_slice(b"{\"a\":1,\"a\":2}\n");
        file.extend_from_slice(b"{}{}\n");
        file.extend_from_slice(b"\xff\n");
        push_line(&mut file, &nested_arrays(129));
        file.extend_from_slice(&body);
        let limits = StreamLimits::default().with_capacity(1).expect("capacity");
        let counts = count_bytes(&file, &key, limits).await;
        assert_eq!(counts.ok, 0);
        assert_eq!(counts.invalid, 1);
        assert_eq!(counts.malformed, 8);
        assert_eq!(counts.lines(), 9);
        assert!(crate::verify_audit_receipt_bytes(&body, &key));
    }

    #[tokio::test]
    async fn oversized_line_counts_once_and_stays_unverified() {
        let (body, key) = v1_body_and_key();
        assert!(crate::verify_audit_receipt_bytes(&body, &key));
        let mut file = body.clone();
        file.push(b'\n');
        file.extend_from_slice(b"{}\n");
        let limits = StreamLimits::default()
            .with_max_line_len(8)
            .expect("max line");
        let counts = count_bytes(&file, &key, limits).await;
        assert_eq!(counts.ok, 0);
        assert_eq!(counts.invalid, 1);
        assert_eq!(counts.malformed, 1);

        let exact = count_bytes(b"{}\n", &key, limits).await;
        assert_eq!(exact.invalid, 1);
        assert_eq!(exact.malformed, 0);
        let over = count_bytes(b"{}\n", &key, limits.with_max_line_len(1).expect("one")).await;
        assert_eq!(over.invalid, 0);
        assert_eq!(over.malformed, 1);
    }

    #[tokio::test]
    async fn truncated_tail_is_malformed_and_unverified() {
        let (body, key) = v1_body_and_key();
        assert!(crate::verify_audit_receipt_bytes(&body, &key));
        let counts = count_bytes(&body, &key, StreamLimits::default()).await;
        assert_eq!(counts.ok, 0);
        assert_eq!(counts.invalid, 0);
        assert_eq!(counts.malformed, 1);
        let empty = count_bytes(b"", &key, StreamLimits::default()).await;
        assert_eq!(empty, AuditReceiptCounts::default());
        let newline = count_bytes(b"\n", &key, StreamLimits::default()).await;
        assert_eq!(newline.malformed, 1);
        assert_eq!(newline.lines(), 1);
    }

    #[tokio::test]
    async fn io_error_after_a_good_line_returns_err_without_counts() {
        let (body, key) = v1_body_and_key();
        let mut line = body;
        line.push(b'\n');
        let reader = FailAfter {
            pending: line,
            failed: false,
        };
        let err = verify_audit_receipt_lines(reader, &key, StreamLimits::default())
            .await
            .expect_err("io");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn backpressure_stops_poll_read() {
        let polls = Arc::new(AtomicUsize::new(0));
        let capacity = 4;
        let reader = LineReader {
            polls: Arc::clone(&polls),
            left: 100,
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(capacity);
        let read = tokio::task::coop::unconstrained(read_frames(reader, tx, 64));
        tokio::pin!(read);
        poll_until_pending(&mut read).await;
        assert_eq!(polls.load(Ordering::SeqCst), capacity + 1);
        poll_until_pending(&mut read).await;
        assert_eq!(polls.load(Ordering::SeqCst), capacity + 1);
    }

    #[tokio::test]
    async fn cancel_drops_reader_without_counts() {
        let before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let dropped = Arc::new(AtomicBool::new(false));
        let reader = PendingReader {
            dropped: Arc::clone(&dropped),
        };
        {
            let fut = verify_audit_receipt_lines(reader, b"k", StreamLimits::default());
            tokio::pin!(fut);
            poll_until_pending(&mut fut).await;
            assert!(!dropped.load(Ordering::SeqCst));
        }
        assert!(dropped.load(Ordering::SeqCst));
        let after = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        assert_eq!(before, after);
    }

    async fn count_bytes(bytes: &[u8], key: &[u8], limits: StreamLimits) -> AuditReceiptCounts {
        verify_audit_receipt_lines(std::io::Cursor::new(bytes.to_vec()), key, limits)
            .await
            .expect("read")
    }

    fn push_line(file: &mut Vec<u8>, body: &[u8]) {
        file.extend_from_slice(body);
        file.push(b'\n');
    }

    async fn poll_until_pending<F: Future + Unpin>(fut: &mut F) {
        std::future::poll_fn(|cx| match Pin::new(&mut *fut).poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("future finished"),
        })
        .await;
    }

    struct LineReader {
        polls: Arc<AtomicUsize>,
        left: usize,
    }

    impl AsyncRead for LineReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            if this.left == 0 {
                return Poll::Ready(Ok(()));
            }
            this.left -= 1;
            buf.put_slice(b"x\n");
            Poll::Ready(Ok(()))
        }
    }

    struct PendingReader {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for PendingReader {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    struct FailAfter {
        pending: Vec<u8>,
        failed: bool,
    }

    impl AsyncRead for FailAfter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if !this.pending.is_empty() {
                let n = buf.remaining().min(this.pending.len());
                let rest = this.pending.split_off(n);
                buf.put_slice(&this.pending);
                this.pending = rest;
                Poll::Ready(Ok(()))
            } else if !this.failed {
                this.failed = true;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "read failed",
                )))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(depth * 2 + 1);
        bytes.extend(std::iter::repeat(b'[').take(depth));
        bytes.push(b'0');
        bytes.extend(std::iter::repeat(b']').take(depth));
        bytes
    }

    fn vectors_root() -> &'static Json {
        static ROOT: OnceLock<Json> = OnceLock::new();
        ROOT.get_or_init(|| {
            let raw = include_bytes!("../../../vectors/reference/vectors.json");
            parse(raw).expect("vectors.json")
        })
    }

    fn v1_body_and_key() -> (Vec<u8>, Vec<u8>) {
        let root = vectors_root();
        let rows = field(root, "vectors").as_array().expect("vectors");
        for row in rows {
            if json_str(field(row, "name")) == "hmac-audit-receipt-valid" {
                let input = field(row, "input");
                let key = json_str(field(input, "signingKeyUtf8")).into_bytes();
                let body = crate::canonical_json_value(field(input, "receipt")).expect("canonical");
                return (body, key);
            }
        }
        panic!("missing hmac-audit-receipt-valid");
    }

    fn field<'a>(value: &'a Json, name: &str) -> &'a Json {
        let want = Wtf16::from_str(name);
        value
            .as_object()
            .expect("object")
            .iter()
            .find(|(key, _)| key == &want)
            .map(|(_, item)| item)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    fn json_str(value: &Json) -> String {
        String::from_utf16(value.as_string().expect("string").units()).expect("utf-16")
    }

    fn flip_signature_hex(bytes: &mut [u8]) {
        let marker = b"\"signature\":\"";
        let start = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("signature")
            + marker.len();
        bytes[start] = if bytes[start] == b'a' { b'b' } else { b'a' };
    }

    struct ChunkedFile {
        file: std::io::BufReader<std::fs::File>,
    }

    impl AsyncRead for ChunkedFile {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let n = std::io::Read::read(&mut this.file, buf.initialize_unfilled())?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    fn proc_kib(label: &str) -> u64 {
        let text = std::fs::read_to_string("/proc/self/status").expect("status");
        let prefix = format!("{label}:");
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(&prefix) {
                return rest
                    .split_whitespace()
                    .next()
                    .expect("kib")
                    .parse()
                    .expect("kib");
            }
        }
        panic!("missing {label}");
    }

    fn cpu_ticks() -> (u64, u64) {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("stat");
        let rest = stat.rsplit_once(')').expect("comm").1;
        let fields: Vec<&str> = rest.split_whitespace().collect();
        (
            fields[11].parse().expect("utime"),
            fields[12].parse().expect("stime"),
        )
    }

    #[ignore = "writes and verifies 1000000 lines"]
    #[tokio::test]
    async fn million_line_receipts_per_sec() {
        let (body, key) = v1_body_and_key();
        assert!(body.len() < 64 * 1024);
        let path = std::env::temp_dir().join(format!(
            "agent-receipts-million-{}.jsonl",
            std::process::id()
        ));
        let _remove = RemoveFile(path.clone());
        {
            let mut out = std::io::BufWriter::new(std::fs::File::create(&path).expect("create"));
            for _ in 0..1_000_000 {
                std::io::Write::write_all(&mut out, &body).expect("write");
                std::io::Write::write_all(&mut out, b"\n").expect("newline");
            }
            std::io::Write::flush(&mut out).expect("flush");
        }
        let (utime_before, stime_before) = cpu_ticks();
        let started = std::time::Instant::now();
        let limits = StreamLimits::default();
        let file = ChunkedFile {
            file: std::io::BufReader::new(std::fs::File::open(&path).expect("open")),
        };
        let counts = verify_audit_receipt_lines(file, &key, limits)
            .await
            .expect("verify");
        let elapsed = started.elapsed();
        let (utime_after, stime_after) = cpu_ticks();
        std::hint::black_box(counts.ok);
        std::hint::black_box(counts.invalid);
        std::hint::black_box(counts.malformed);
        assert_eq!(counts.ok, 1_000_000);
        assert_eq!(counts.invalid, 0);
        assert_eq!(counts.malformed, 0);
        assert_eq!(counts.lines(), 1_000_000);
        let secs = elapsed.as_secs_f64();
        println!(
            "method limiter=(capacity+2)*max_line_len+8192={} plus one Json tree; results consumed; line count asserted",
            limits.max_retained_line_bytes()
        );
        println!(
            "ok={} invalid={} malformed={} lines={}",
            counts.ok,
            counts.invalid,
            counts.malformed,
            counts.lines()
        );
        println!("elapsed_sec={secs:.6}");
        println!("receipts_per_sec={:.1}", 1_000_000.0 / secs);
        println!("VmHWM_kB={}", proc_kib("VmHWM"));
        println!("VmRSS_kB={}", proc_kib("VmRSS"));
        println!("utime_ticks={}", utime_after - utime_before);
        println!("stime_ticks={}", stime_after - stime_before);
        println!("line_bytes={}", body.len() + 1);
    }

    struct RemoveFile(std::path::PathBuf);

    impl Drop for RemoveFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
