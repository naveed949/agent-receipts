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
        match check_limits(capacity, self.max_line_len()) {
            Ok(()) => {
                self.capacity = match NonZeroUsize::new(capacity) {
                    Some(capacity) => capacity,
                    None => return Err(LimitsError::ZeroCapacity),
                };
                Ok(self)
            }
            Err(err) => Err(err),
        }
    }

    pub const fn with_max_line_len(mut self, max_line_len: usize) -> Result<Self, LimitsError> {
        match check_limits(self.capacity(), max_line_len) {
            Ok(()) => {
                self.max_line_len = match NonZeroUsize::new(max_line_len) {
                    Some(max_line_len) => max_line_len,
                    None => return Err(LimitsError::ZeroMaxLineLen),
                };
                Ok(self)
            }
            Err(err) => Err(err),
        }
    }

    pub const fn capacity(self) -> usize {
        self.capacity.get()
    }

    pub const fn max_line_len(self) -> usize {
        self.max_line_len.get()
    }

    pub const fn max_retained_line_bytes(self) -> usize {
        match retained_line_bytes(self.capacity(), self.max_line_len()) {
            Some(total) => total,
            None => panic!("retained line bytes overflowed usize"),
        }
    }

    pub const fn max_parse_tree_bytes(self) -> usize {
        match parse_tree_bytes(self.max_line_len()) {
            Some(total) => total,
            None => panic!("parse tree bytes overflowed usize"),
        }
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

const MAX_CHANNEL_CAPACITY: usize = usize::MAX >> 3;
const JSON_NODE_BYTES: usize = std::mem::size_of::<crate::Json>();

const fn retained_line_bytes(capacity: usize, max_line_len: usize) -> Option<usize> {
    let slots = match capacity.checked_add(2) {
        Some(slots) => slots,
        None => return None,
    };
    let lines = match slots.checked_mul(max_line_len) {
        Some(lines) => lines,
        None => return None,
    };
    lines.checked_add(READ_CHUNK)
}

const MIN_JSON_VEC_CAP: usize = 4;

const fn json_vec_cap(n: usize) -> Option<usize> {
    if n == 0 {
        return Some(0);
    }
    if n > (usize::MAX >> 1) {
        return None;
    }
    let grown = n.next_power_of_two();
    Some(if grown < MIN_JSON_VEC_CAP {
        MIN_JSON_VEC_CAP
    } else {
        grown
    })
}

const fn parse_tree_bytes(max_line_len: usize) -> Option<usize> {
    // Number array `[0,0,...,0]`: (max_line_len-1)/2 nodes, Vec next power of two.
    // A 1-element array chain of depth d (`[[[0]]]`) is 2d+1 bytes and retains
    // d * MIN_JSON_VEC_CAP * JSON_NODE_BYTES. Packing n copies of a d-deep chain
    // in one outer array is n*(2d+2)+1 bytes (n items, n-1 commas, 2 brackets),
    // so n = (max_line_len-1)/(2d+2). Using max_line_len-2 drops n=1, the lone
    // chain with no comma, at every max_line_len = 2d+1.
    let n = max_line_len.saturating_sub(1) / 2;
    let cap = match json_vec_cap(n) {
        Some(cap) => cap,
        None => return None,
    };
    let mut best = match cap.checked_mul(JSON_NODE_BYTES) {
        Some(bytes) => bytes,
        None => return None,
    };
    let mut depth = 1usize;
    while depth <= crate::MAX_DEPTH {
        let two = match depth.checked_mul(2) {
            Some(two) => two,
            None => return None,
        };
        let chain_len = match two.checked_add(1) {
            Some(len) => len,
            None => return None,
        };
        if chain_len <= max_line_len {
            let slots = match depth.checked_mul(MIN_JSON_VEC_CAP) {
                Some(slots) => slots,
                None => return None,
            };
            let bytes = match slots.checked_mul(JSON_NODE_BYTES) {
                Some(bytes) => bytes,
                None => return None,
            };
            if bytes > best {
                best = bytes;
            }
        }
        let item = match two.checked_add(2) {
            Some(item) => item,
            None => return None,
        };
        if item < max_line_len {
            let n = (max_line_len - 1) / item;
            if n > 0 {
                let cap = match json_vec_cap(n) {
                    Some(cap) => cap,
                    None => return None,
                };
                let outer = match cap.checked_mul(JSON_NODE_BYTES) {
                    Some(bytes) => bytes,
                    None => return None,
                };
                let inner_nodes = match n.checked_mul(depth) {
                    Some(nodes) => nodes,
                    None => return None,
                };
                let inner_slots = match inner_nodes.checked_mul(MIN_JSON_VEC_CAP) {
                    Some(slots) => slots,
                    None => return None,
                };
                let inner = match inner_slots.checked_mul(JSON_NODE_BYTES) {
                    Some(bytes) => bytes,
                    None => return None,
                };
                let total = match outer.checked_add(inner) {
                    Some(total) => total,
                    None => return None,
                };
                if total > best {
                    best = total;
                }
            }
        }
        depth += 1;
    }
    Some(best)
}

const fn check_limits(capacity: usize, max_line_len: usize) -> Result<(), LimitsError> {
    if capacity == 0 {
        return Err(LimitsError::ZeroCapacity);
    }
    if max_line_len == 0 {
        return Err(LimitsError::ZeroMaxLineLen);
    }
    if capacity > MAX_CHANNEL_CAPACITY {
        return Err(LimitsError::CapacityTooLarge);
    }
    let Some(line_buffers) = retained_line_bytes(capacity, max_line_len) else {
        return Err(LimitsError::Overflow);
    };
    let Some(trees) = parse_tree_bytes(max_line_len) else {
        return Err(LimitsError::Overflow);
    };
    if line_buffers.checked_add(trees).is_none() {
        return Err(LimitsError::Overflow);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsError {
    ZeroCapacity,
    ZeroMaxLineLen,
    CapacityTooLarge,
    Overflow,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            LimitsError::ZeroCapacity => "capacity must be greater than zero",
            LimitsError::ZeroMaxLineLen => "max_line_len must be greater than zero",
            LimitsError::CapacityTooLarge => "capacity exceeds the channel permit limit",
            LimitsError::Overflow => "retained line bytes overflowed usize",
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

const RECEIPT_TOP_LEVEL: &[&str] = &[
    "artifacts",
    "authority",
    "authorityPolicyVersion",
    "decision",
    "executionDigest",
    "gondolinHttps",
    "id",
    "integrity",
    "outcome",
    "recordedAt",
    "requestHash",
    "tool",
    "version",
];

fn extra_top_level_key(value: &crate::Json) -> bool {
    let Some(entries) = value.as_object() else {
        return false;
    };
    entries.iter().any(|(key, _)| {
        !RECEIPT_TOP_LEVEL
            .iter()
            .any(|name| key.units().iter().copied().eq(name.encode_utf16()))
    })
}

fn classify_line(body: &[u8], key: &[u8]) -> LineClass {
    match crate::parse::parse(body) {
        Err(_) => LineClass::Malformed,
        Ok(value) => {
            if extra_top_level_key(&value) {
                // extra JSON key does not reach HMAC
                LineClass::Malformed
            } else if crate::verify_audit_receipt(&value, key) {
                LineClass::Ok
            } else {
                LineClass::Invalid
            }
        }
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
        tokio::task::coop::consume_budget().await;
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
        classify_line, json_vec_cap, parse_tree_bytes, read_frames, verify_audit_receipt_lines,
        AuditReceiptCounts, LimitsError, LineClass, StreamLimits, DEFAULT_MAX_LINE_LEN,
        DEFAULT_STREAM_CAPACITY, JSON_NODE_BYTES, MAX_CHANNEL_CAPACITY, MIN_JSON_VEC_CAP,
        READ_CHUNK,
    };
    use crate::{parse::parse, Json, Wtf16};
    use tokio::io::{AsyncRead, ReadBuf};

    #[test]
    fn limits_reject_zero_and_name_the_ceiling() {
        let limits = StreamLimits::default();
        assert_eq!(limits.capacity(), DEFAULT_STREAM_CAPACITY);
        assert_eq!(limits.max_line_len(), DEFAULT_MAX_LINE_LEN);
        let line_buffers = (DEFAULT_STREAM_CAPACITY + 2)
            .checked_mul(DEFAULT_MAX_LINE_LEN)
            .expect("line buffers")
            .checked_add(READ_CHUNK)
            .expect("scratch");
        assert_eq!(limits.max_retained_line_bytes(), line_buffers);
        assert_eq!(
            limits.max_parse_tree_bytes(),
            parse_tree_bytes(DEFAULT_MAX_LINE_LEN).expect("trees")
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
        assert_eq!(
            LimitsError::CapacityTooLarge.to_string(),
            "capacity exceeds the channel permit limit"
        );
        assert_eq!(
            LimitsError::Overflow.to_string(),
            "retained line bytes overflowed usize"
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

    #[test]
    fn extra_top_level_field_is_malformed_and_does_not_reach_hmac() {
        let (body, key) = v1_body_and_key();
        let extra = with_extra_top_level(&body);
        assert!(parse(&extra).is_ok());
        assert!(!crate::verify_audit_receipt_bytes(&extra, &key));
        assert!(matches!(classify_line(&extra, &key), LineClass::Malformed));
    }

    #[test]
    fn foreign_object_with_unknown_fields_is_malformed() {
        let (_body, key) = v1_body_and_key();
        let foreign = br#"{"foo":1,"bar":2}"#;
        assert!(parse(foreign).is_ok());
        assert!(!crate::verify_audit_receipt_bytes(foreign, &key));
        assert!(matches!(classify_line(foreign, &key), LineClass::Malformed));
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

        let mut extra_file = Vec::new();
        push_line(&mut extra_file, &with_extra_top_level(&body));
        push_line(&mut extra_file, br#"{"foo":1,"bar":2}"#);
        extra_file.extend_from_slice(b" \t\n");
        extra_file.extend_from_slice(b"\n");
        let mixed = count_bytes(&extra_file, &key, StreamLimits::default()).await;
        assert_eq!(mixed.ok, 0);
        assert_eq!(mixed.invalid, 0);
        assert_eq!(mixed.malformed, 4);
        assert_eq!(mixed.lines(), 4);
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

    #[tokio::test]
    async fn oversized_discard_cancel() {
        let polls = Arc::new(AtomicUsize::new(0));
        let body = 2 * 1024 * 1024;
        let reader = OversizedDiscardReader {
            polls: Arc::clone(&polls),
            remaining: body,
        };
        let limits = StreamLimits::default()
            .with_max_line_len(8)
            .expect("max line");
        let after_first = {
            let fut = verify_audit_receipt_lines(reader, b"k", limits);
            tokio::pin!(fut);
            poll_until_pending(&mut fut).await;
            let after_first = polls.load(Ordering::SeqCst);
            assert!(after_first > 0);
            let full_reads = body.div_ceil(READ_CHUNK);
            assert!(
                after_first < full_reads,
                "ready discard consumed the whole file in one poll: {after_first} >= {full_reads}"
            );
            after_first
        };
        assert_eq!(after_first, polls.load(Ordering::SeqCst));

        let handle = tokio::spawn(verify_audit_receipt_lines(
            std::io::Cursor::new(vec![b'x'; body]),
            b"k",
            limits,
        ));
        tokio::task::yield_now().await;
        handle.abort();
        let join = handle.await;
        assert!(join.unwrap_err().is_cancelled());
    }

    #[test]
    fn stream_limits_panic() {
        let limits = StreamLimits::default();
        assert_eq!(
            limits.with_capacity(usize::MAX).unwrap_err(),
            LimitsError::CapacityTooLarge
        );
        assert_eq!(
            limits.with_max_line_len(usize::MAX).unwrap_err(),
            LimitsError::Overflow
        );
        assert_eq!(
            limits
                .with_capacity(MAX_CHANNEL_CAPACITY.saturating_add(1))
                .unwrap_err(),
            LimitsError::CapacityTooLarge
        );
        let ceiling = std::panic::catch_unwind(|| limits.max_retained_line_bytes());
        assert_eq!(
            ceiling.expect("default ceiling"),
            (DEFAULT_STREAM_CAPACITY + 2) * DEFAULT_MAX_LINE_LEN + READ_CHUNK
        );
        let trees = std::panic::catch_unwind(|| limits.max_parse_tree_bytes());
        assert_eq!(
            trees.expect("default trees"),
            parse_tree_bytes(DEFAULT_MAX_LINE_LEN).expect("trees")
        );
    }

    #[tokio::test]
    async fn memory_ceiling_understatement() {
        let max_line_len = 8191;
        let limits = StreamLimits::default()
            .with_capacity(1)
            .expect("capacity")
            .with_max_line_len(max_line_len)
            .expect("max line");
        let bound = limits.max_parse_tree_bytes();
        assert_eq!(bound, parse_tree_bytes(max_line_len).expect("trees"));
        let old_factor = max_line_len.checked_mul(4).expect("old 4x");
        let number_line = dense_number_array_line(max_line_len);
        let number_tree = crate::json_retained_bytes(&parse(&number_line).expect("number array"));
        assert!(
            number_tree > old_factor,
            "number tree {number_tree} must exceed 4*max_line_len {old_factor}"
        );
        assert!(
            number_tree <= bound,
            "number tree {number_tree} exceeds max_parse_tree_bytes {bound}"
        );
        let nested_line = dense_nested_singleton_line(max_line_len);
        let nested_tree =
            crate::json_retained_bytes(&parse(&nested_line).expect("nested singletons"));
        let number_only = json_vec_cap((max_line_len - 1) / 2)
            .and_then(|cap| cap.checked_mul(JSON_NODE_BYTES))
            .expect("number-only");
        assert!(
            nested_tree > number_only,
            "nested tree {nested_tree} must exceed the number-array bound {number_only}"
        );
        assert!(
            nested_tree <= bound,
            "nested tree {nested_tree} exceeds max_parse_tree_bytes {bound}"
        );
        let mut file = nested_line;
        file.push(b'\n');
        let counts = count_bytes(&file, b"k", limits).await;
        assert_eq!(counts.ok, 0);
        assert_eq!(counts.invalid, 1);
        assert_eq!(counts.malformed, 0);
    }

    #[tokio::test]
    async fn nested_chain_bound_covers_small_lines() {
        let mut chain_fail = 0usize;
        let mut depth = 2usize;
        while depth <= crate::MAX_DEPTH {
            let max_line_len = depth
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(1))
                .expect("chain length");
            let limits = StreamLimits::default()
                .with_max_line_len(max_line_len)
                .expect("max line");
            let bound = limits.max_parse_tree_bytes();
            let old = comma_inclusive_spine_bound(max_line_len).expect("old bound");
            let line = dense_nested_chain_line(depth);
            let tree = crate::json_retained_bytes(&parse(&line).expect("chain"));
            assert!(
                tree > old,
                "chain depth {depth} tree {tree} must exceed comma-inclusive bound {old}"
            );
            assert!(
                tree <= bound,
                "chain depth {depth} tree {tree} exceeds max_parse_tree_bytes {bound}"
            );
            if tree > old {
                chain_fail += 1;
            }
            let mut file = line;
            file.push(b'\n');
            let counts = count_bytes(&file, b"k", limits).await;
            assert_eq!(counts.ok, 0);
            assert_eq!(counts.invalid, 1);
            assert_eq!(counts.malformed, 0);
            depth += 1;
        }
        assert_eq!(chain_fail, crate::MAX_DEPTH - 1);

        for max_line_len in [5usize, 7, 9, 11] {
            let limits = StreamLimits::default()
                .with_max_line_len(max_line_len)
                .expect("max line");
            let bound = limits.max_parse_tree_bytes();
            let old = comma_inclusive_spine_bound(max_line_len).expect("old bound");
            let line = dense_nested_singleton_line(max_line_len);
            let tree = crate::json_retained_bytes(&parse(&line).expect("packed"));
            assert!(
                tree <= bound,
                "packed line_len={max_line_len} tree {tree} exceeds max_parse_tree_bytes {bound}"
            );
            if max_line_len == 5 {
                assert!(
                    tree > old,
                    "packed line_len=5 tree {tree} must exceed comma-inclusive bound {old}"
                );
            }
        }
    }

    fn comma_inclusive_spine_bound(max_line_len: usize) -> Option<usize> {
        let n = max_line_len.saturating_sub(1) / 2;
        let cap = json_vec_cap(n)?;
        let mut best = cap.checked_mul(JSON_NODE_BYTES)?;
        let mut depth = 1usize;
        while depth <= crate::MAX_DEPTH {
            let item = depth.checked_mul(2)?.checked_add(2)?;
            if item < max_line_len {
                let n = (max_line_len - 2) / item;
                let cap = json_vec_cap(n)?;
                let outer = cap.checked_mul(JSON_NODE_BYTES)?;
                let inner = n
                    .checked_mul(depth)?
                    .checked_mul(MIN_JSON_VEC_CAP)?
                    .checked_mul(JSON_NODE_BYTES)?;
                let total = outer.checked_add(inner)?;
                if total > best {
                    best = total;
                }
            }
            depth += 1;
        }
        Some(best)
    }

    fn dense_nested_chain_line(depth: usize) -> Vec<u8> {
        let mut line = vec![b'['; depth];
        line.push(b'0');
        line.resize(depth * 2 + 1, b']');
        assert_eq!(line.len(), depth * 2 + 1);
        line
    }

    fn dense_nested_singleton_line(max_line_len: usize) -> Vec<u8> {
        let mut line = Vec::with_capacity(max_line_len);
        line.push(b'[');
        let mut first = true;
        loop {
            let extra = if first { 3 } else { 4 };
            if line.len() + extra + 1 > max_line_len {
                break;
            }
            if !first {
                line.push(b',');
            }
            first = false;
            line.extend_from_slice(b"[0]");
        }
        while line.len() + 1 < max_line_len {
            line.push(b' ');
        }
        line.push(b']');
        assert_eq!(line.len(), max_line_len);
        line
    }

    fn dense_number_array_line(max_line_len: usize) -> Vec<u8> {
        let mut line = Vec::with_capacity(max_line_len);
        line.push(b'[');
        while line.len() + 2 < max_line_len {
            line.push(b'0');
            line.push(b',');
        }
        if line.len() + 1 < max_line_len {
            line.push(b'0');
        }
        while line.len() + 1 < max_line_len {
            line.push(b' ');
        }
        line.push(b']');
        assert_eq!(line.len(), max_line_len);
        line
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

    struct OversizedDiscardReader {
        polls: Arc<AtomicUsize>,
        remaining: usize,
    }

    impl AsyncRead for OversizedDiscardReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            if this.remaining == 0 {
                return Poll::Ready(Ok(()));
            }
            let n = buf.remaining().min(this.remaining);
            buf.initialize_unfilled()[..n].fill(b'x');
            buf.advance(n);
            this.remaining -= n;
            Poll::Ready(Ok(()))
        }
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

    fn with_extra_top_level(body: &[u8]) -> Vec<u8> {
        let value = parse(body).expect("json");
        let mut entries = value.as_object().expect("object").to_vec();
        entries.push((Wtf16::from_str("zzz_extra"), Json::bool(true)));
        crate::canonical_json_value(&Json::object(entries).expect("object")).expect("canonical")
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
            "method line_buffer_ceiling=(capacity+2)*max_line_len+READ_CHUNK={} parse_trees=max(number_array, nested_singleton_spines)={} process_rss_bound={}; results consumed; line count asserted; line-buffer ceiling is computed from StreamLimits, not a 4 MB product bound; this run's lines were {} B so RSS is not that ceiling",
            limits.max_retained_line_bytes(),
            limits.max_parse_tree_bytes(),
            limits
                .max_retained_line_bytes()
                .checked_add(limits.max_parse_tree_bytes())
                .expect("rss"),
            body.len() + 1
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
