use std::fs;
use std::path::PathBuf;

use super::{
    audit_mac_input_ascii, audit_signing_key, canonical_json, canonical_json_value,
    controlled_signing_key, parse::parse, resign_audit_receipt, sign_controlled_integrity,
    stable_hash, stable_hash_value, verify_audit_receipt, verify_controlled_integrity, Error, Json,
    Node, SignerError, SigningKey, Wtf16, AUDIT_RECEIPT_V2_VERSION, AUDIT_RECEIPT_VERSION,
};

#[test]
fn reference_vectors() {
    if let Err(err) = run() {
        panic!("{err}");
    }
}

fn run() -> Result<(), String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/reference");
    let allow = read_allowlist(&dir.join("pending-kinds.txt"))?;
    let bytes =
        fs::read(dir.join("vectors.json")).map_err(|err| format!("read vectors.json: {err}"))?;
    if bytes.is_empty() {
        return Err("vectors.json is empty".into());
    }
    let root = parse(&bytes).map_err(|err| format!("vectors.json {}", err.code()))?;
    let count = expect_count(field(&root, "count")?)?;
    let rows = expect_array(field(&root, "vectors")?)?;
    if count != rows.len() || rows.len() != 23 {
        return Err(format!("count {count} len {}", rows.len()));
    }

    let catalog = Catalog::load(rows)?;
    let mut pending_lines = Vec::new();
    let mut seen = Vec::new();
    let mut failures = Vec::new();
    let mut canonical_ok = 0usize;
    let mut hmac_ok = 0usize;
    for row in rows {
        let name = row_string(row, "name")?;
        let kind = row_string(row, "kind")?;
        if kind == "canonicalize" {
            match check_canonicalize(row, &name) {
                Ok(()) => canonical_ok += 1,
                Err(err) => failures.push(err),
            }
            continue;
        }
        if kind == "controlled-integrity" || kind == "audit.verifyAuditReceipt" {
            match check_hmac_row(row, &name, &kind, &catalog) {
                Ok(()) => hmac_ok += 1,
                Err(err) => failures.push(err),
            }
            continue;
        }
        if !allow.iter().any(|line| line == &kind) {
            failures.push(format!("unknown kind {kind}"));
            continue;
        }
        if !seen.iter().any(|line| line == &kind) {
            seen.push(kind.clone());
        }
        pending_lines.push(format!("pending {kind} {name}"));
    }
    for line in &allow {
        if !seen.iter().any(|kind| kind == line) {
            failures.push(format!("unused pending kind {line}"));
        }
    }
    if canonical_ok != 8
        || hmac_ok != 8
        || pending_lines.len() != 7
        || canonical_ok + hmac_ok + pending_lines.len() != 23
    {
        failures.push(format!(
            "counts canonicalize {canonical_ok} hmac {hmac_ok} pending {}",
            pending_lines.len()
        ));
    }
    for line in &pending_lines {
        println!("{line}");
    }
    if !failures.is_empty() {
        return Err(failures.join("\n"));
    }
    println!("pending {}", pending_lines.len());
    println!("canonicalize {canonical_ok} ok");
    println!("hmac {hmac_ok} ok");
    Ok(())
}

fn check_canonicalize(row: &Json, name: &str) -> Result<(), String> {
    let expected = field(row, "expected");
    let expected_error = field(row, "expectedError");
    match (expected, expected_error) {
        (Ok(_), Ok(_)) | (Err(_), Err(_)) => Err(format!("{name} needs expected or expectedError")),
        (Ok(expected), Err(_)) => check_success(row, name, expected),
        (Err(_), Ok(expected_error)) => check_rejections(row, name, expected_error),
    }
}

fn check_success(row: &Json, name: &str, expected: &Json) -> Result<(), String> {
    let input = field(row, "input")?;
    let value = match decode(input)? {
        Decoded::Value(value) => value,
        Decoded::Rejected => return Err(format!("{name} rejected a success row")),
    };
    let bytes = canonical_json_value(&value)
        .map_err(|err| format!("{name} canonical_json_value {}", err.code()))?;
    let hash = stable_hash_value(&value)
        .map_err(|err| format!("{name} stable_hash_value {}", err.code()))?;
    let want_hex = json_text(field(expected, "canonicalUtf8Hex")?)?;
    let want_hash = json_text(field(expected, "stableHash")?)?;
    let want_bytes = decode_hex(&want_hex)?;
    if bytes != want_bytes {
        return Err(format!(
            "{name} bytes\n got {}\n want {want_hex}",
            to_hex(&bytes)
        ));
    }
    if hash != want_hash {
        return Err(format!("{name} hash {hash} != {want_hash}"));
    }
    let again =
        canonical_json(&bytes).map_err(|err| format!("{name} second pass {}", err.code()))?;
    if again != bytes {
        return Err(format!("{name} is not stable"));
    }
    let again_hash =
        stable_hash(&bytes).map_err(|err| format!("{name} second hash {}", err.code()))?;
    if again_hash != hash {
        return Err(format!("{name} second hash {again_hash} != {hash}"));
    }
    Ok(())
}

fn check_rejections(row: &Json, name: &str, expected_error: &Json) -> Result<(), String> {
    let input = field(row, "input")?;
    let cases = expect_object(field(input, "cases")?)?;
    let errors = expect_object(expected_error)?;
    if cases.is_empty() {
        return Err(format!("{name} has no rejection cases"));
    }
    if cases.len() != errors.len() {
        return Err(format!("{name} rejection key count"));
    }
    for (key, child) in cases {
        let label = key_text(key)?;
        let Some(spec) = lookup(errors, key) else {
            return Err(format!("{name} missing expected error for {label}"));
        };
        let type_name = json_text(field(spec, "type")?)?;
        if type_name != "TypeError" {
            return Err(format!("{name} {label} type {type_name}"));
        }
        match decode(child)? {
            Decoded::Rejected => {}
            Decoded::Value(_) => return Err(format!("{name} {label} accepted")),
        }
    }
    for (key, _) in errors {
        if lookup(cases, key).is_none() {
            return Err(format!("{name} extra expected error {}", key_text(key)?));
        }
    }
    Ok(())
}

enum Decoded {
    Value(Json),
    Rejected,
}

fn decode(value: &Json) -> Result<Decoded, String> {
    match &value.node {
        Node::Null | Node::Bool(_) | Node::Number(_) | Node::String(_) => {
            Ok(Decoded::Value(value.clone()))
        }
        Node::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match decode(item)? {
                    Decoded::Rejected => return Ok(Decoded::Rejected),
                    Decoded::Value(child) => out.push(child),
                }
            }
            Ok(Decoded::Value(Json::array(out)))
        }
        Node::Object(entries) => {
            if let Some(tag) = sole_js_tag(entries) {
                return decode_tag(tag);
            }
            let mut out = Vec::with_capacity(entries.len());
            for (key, child) in entries {
                match decode(child)? {
                    Decoded::Rejected => return Ok(Decoded::Rejected),
                    Decoded::Value(decoded) => out.push((key.clone(), decoded)),
                }
            }
            Json::object(out)
                .map(Decoded::Value)
                .map_err(|err| format!("object rebuild {}", err.code()))
        }
    }
}

fn sole_js_tag(entries: &[(Wtf16, Json)]) -> Option<&Json> {
    if entries.len() != 1
        || entries[0].0.units() != [u16::from(b'$'), u16::from(b'j'), u16::from(b's')]
    {
        return None;
    }
    Some(&entries[0].1)
}

fn decode_tag(value: &Json) -> Result<Decoded, String> {
    let text = json_text(value)?;
    match text.as_str() {
        "-0" => Ok(Decoded::Value(
            Json::number(-0.0).map_err(|err| format!("-0 {}", err.code()))?,
        )),
        "NaN" => reject_non_finite(f64::NAN),
        "Infinity" => reject_non_finite(f64::INFINITY),
        "-Infinity" => reject_non_finite(f64::NEG_INFINITY),
        "undefined" => Ok(Decoded::Rejected),
        _ => decode_prefixed_tag(&text),
    }
}

fn decode_prefixed_tag(text: &str) -> Result<Decoded, String> {
    if let Some(rest) = text.strip_prefix("bigint:") {
        if is_digits(rest) {
            return Ok(Decoded::Rejected);
        }
        return Err(format!("unknown tag {text}"));
    }
    if let Some(rest) = text.strip_prefix("number:") {
        return decode_number_tag(rest);
    }
    Err(format!("unknown tag {text}"))
}

fn decode_number_tag(token: &str) -> Result<Decoded, String> {
    if token.is_empty()
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
        || !(token.starts_with('-') || token.as_bytes()[0].is_ascii_digit())
    {
        return Err(format!("unknown tag number:{token}"));
    }
    let value = parse(token.as_bytes()).map_err(|_| format!("unknown tag number:{token}"))?;
    if !matches!(value.node, Node::Number(_)) {
        return Err(format!("unknown tag number:{token}"));
    }
    Ok(Decoded::Value(value))
}

fn reject_non_finite(value: f64) -> Result<Decoded, String> {
    match Json::number(value) {
        Err(Error::TypeError) => Ok(Decoded::Rejected),
        Err(err) => Err(format!("non-finite {}", err.code())),
        Ok(_) => Err("non-finite number was accepted".into()),
    }
}

fn is_digits(text: &str) -> bool {
    let mut bytes = text.bytes();
    match bytes.next() {
        Some(byte) if byte.is_ascii_digit() => bytes.all(|byte| byte.is_ascii_digit()),
        _ => false,
    }
}

fn read_allowlist(path: &std::path::Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read pending kinds: {err}"))?;
    let mut lines = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line == "canonicalize" {
            return Err("allowlist contains canonicalize".into());
        }
        if lines.iter().any(|existing: &String| existing == line) {
            return Err(format!("duplicate pending kind {line}"));
        }
        lines.push(line.to_string());
    }
    Ok(lines)
}

fn field<'a>(value: &'a Json, name: &str) -> Result<&'a Json, String> {
    let entries = expect_object(value)?;
    let want = Wtf16::from_str(name);
    lookup(entries, &want).ok_or_else(|| format!("missing {name}"))
}

fn lookup<'a>(entries: &'a [(Wtf16, Json)], key: &Wtf16) -> Option<&'a Json> {
    entries
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
}

fn expect_object(value: &Json) -> Result<&[(Wtf16, Json)], String> {
    match &value.node {
        Node::Object(entries) => Ok(entries),
        _ => Err("expected object".into()),
    }
}

fn expect_array(value: &Json) -> Result<&[Json], String> {
    match &value.node {
        Node::Array(items) => Ok(items),
        _ => Err("expected array".into()),
    }
}

fn expect_count(value: &Json) -> Result<usize, String> {
    match &value.node {
        Node::Number(number) if number.get() == 23.0 => Ok(23),
        Node::Number(number) => Err(format!("count {}", number.get())),
        _ => Err("count is not a number".into()),
    }
}

fn row_string(row: &Json, name: &str) -> Result<String, String> {
    json_text(field(row, name)?)
}

fn json_text(value: &Json) -> Result<String, String> {
    match &value.node {
        Node::String(text) => {
            String::from_utf16(text.units()).map_err(|_| "string is not unicode".into())
        }
        _ => Err("expected string".into()),
    }
}

fn key_text(key: &Wtf16) -> Result<String, String> {
    String::from_utf16(key.units()).map_err(|_| "key is not unicode".into())
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_nibble(bytes[index]).ok_or("bad hex")?;
        let lo = hex_nibble(bytes[index + 1]).ok_or("bad hex")?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    out
}

struct Catalog {
    v1_receipt: Json,
    v1_key: Vec<u8>,
    v2_allowed: Json,
    v2_denied: Json,
    v2_key: Vec<u8>,
}

impl Catalog {
    fn load(rows: &[Json]) -> Result<Self, String> {
        let mut v1_receipt = None;
        let mut v1_key = None;
        let mut v2_allowed = None;
        let mut v2_denied = None;
        let mut v2_key = None;
        for row in rows {
            let name = row_string(row, "name")?;
            let input = field(row, "input")?;
            match name.as_str() {
                "hmac-audit-receipt-valid" => {
                    v1_receipt = Some(field(input, "receipt")?.clone());
                    v1_key = Some(utf8_key(input)?);
                }
                "linkage-version-rules" => {
                    v2_allowed = Some(field(input, "v2AllowedReceipt")?.clone());
                    v2_denied = Some(field(input, "v2DeniedReceipt")?.clone());
                    v2_key = Some(utf8_key(input)?);
                }
                _ => {}
            }
        }
        Ok(Self {
            v1_receipt: v1_receipt.ok_or("missing hmac-audit-receipt-valid")?,
            v1_key: v1_key.ok_or("missing v1 key")?,
            v2_allowed: v2_allowed.ok_or("missing v2 allowed")?,
            v2_denied: v2_denied.ok_or("missing v2 denied")?,
            v2_key: v2_key.ok_or("missing v2 key")?,
        })
    }
}

fn utf8_key(input: &Json) -> Result<Vec<u8>, String> {
    Ok(json_text(field(input, "signingKeyUtf8")?)?.into_bytes())
}

fn check_hmac_row(row: &Json, name: &str, kind: &str, catalog: &Catalog) -> Result<(), String> {
    match name {
        "hmac-controlled-sign-and-verify" => check_controlled(row, name),
        "hmac-audit-receipt-valid" => check_audit_valid(row, name),
        "hmac-audit-receipt-failures" => check_audit_failures(row, name, catalog),
        "hmac-audit-keyid-swap" => check_keyid_swap(row, name, catalog),
        "hmac-audit-v1-artifact-hash-mismatch" => check_v1_hash_mismatch(row, name, catalog),
        "hmac-key-encoding-and-length" => check_key_encoding(row, name, catalog),
        "linkage-version-rules" => check_linkage(row, name, catalog),
        "hmac-audit-pre124-restamp" => check_restamp(row, name),
        _ => Err(format!("{name} unimplemented {kind}")),
    }
}

fn check_controlled(row: &Json, name: &str) -> Result<(), String> {
    let input = field(row, "input")?;
    let expected = field(row, "expected")?;
    let key = utf8_key(input)?;
    let key_id = json_text(field(input, "keyId")?)?;
    let value = match decode(field(input, "value")?)? {
        Decoded::Value(value) => value,
        Decoded::Rejected => return Err(format!("{name} value rejected")),
    };
    let evidence = sign_controlled_integrity(&value, &key, &key_id)
        .map_err(|err| format!("{name} sign {}", err.code()))?;
    let want = field(field(expected, "sign")?, "evidence")?;
    if json_text(field(&evidence, "integrityDigest")?)?
        != json_text(field(want, "integrityDigest")?)?
    {
        return Err(format!("{name} digest"));
    }
    let cases = expect_object(field(input, "verifyCases")?)?;
    let results = expect_object(field(expected, "verify")?)?;
    for (key_name, case) in cases {
        let label = key_text(key_name)?;
        let want =
            expect_bool(lookup(results, key_name).ok_or_else(|| format!("{name} {label}"))?)?;
        let (target, evidence) = if label == "tamperedValue" {
            let tampered = Json::object(vec![
                (Wtf16::from_str("a"), Json::string(Wtf16::from_str("y"))),
                (
                    Wtf16::from_str("b"),
                    Json::array(vec![Json::number(1.0).unwrap(), Json::number(2.0).unwrap()]),
                ),
            ])
            .map_err(|err| format!("{name} tamper {}", err.code()))?;
            (
                tampered,
                lookup(cases, &Wtf16::from_str("valid")).ok_or("missing valid case")?,
            )
        } else {
            (value.clone(), case)
        };
        let got = verify_controlled_integrity(&target, &key, &key_id, evidence);
        if got != want {
            return Err(format!("{name} {label} got {got} want {want}"));
        }
    }
    Ok(())
}

fn check_audit_valid(row: &Json, name: &str) -> Result<(), String> {
    let input = field(row, "input")?;
    let expected = field(row, "expected")?;
    let key = utf8_key(input)?;
    let receipt = field(input, "receipt")?;
    let got = verify_audit_receipt(receipt, &key);
    let want = expect_bool(field(expected, "result")?)?;
    if got != want {
        return Err(format!("{name} result {got} want {want}"));
    }
    let mac = audit_mac_input_ascii(receipt).ok_or(format!("{name} mac input"))?;
    let want_mac = json_text(field(expected, "macInputAscii")?)?;
    if mac != want_mac {
        return Err(format!("{name} mac {mac} != {want_mac}"));
    }
    let resigned = resign_audit_receipt(receipt, &key)
        .map_err(|err| format!("{name} resign {}", err.code()))?;
    let got_sig = json_text(field(field(&resigned, "integrity")?, "signature")?)?;
    let want_sig = json_text(field(field(receipt, "integrity")?, "signature")?)?;
    if got_sig != want_sig {
        return Err(format!(
            "{name} resign changed a current-preimage signature"
        ));
    }
    Ok(())
}

fn check_audit_failures(row: &Json, name: &str, catalog: &Catalog) -> Result<(), String> {
    let expected = expect_object(field(row, "expected")?)?;
    let key = &catalog.v1_key;
    let receipt = &catalog.v1_receipt;
    let cases = [
        (
            "tamperedOutcome",
            verify_audit_receipt(
                &set_field(receipt, "outcome", json_string("allowed")?)?,
                key,
            ),
        ),
        (
            "wrongKey",
            verify_audit_receipt(receipt, b"synthetic-audit-key-WRONG-0000000"),
        ),
        (
            "uppercaseSignature",
            verify_audit_receipt(&uppercase_signature(receipt)?, key),
        ),
        (
            "v2DiscriminatorResigned",
            verify_audit_receipt(
                &resign(
                    &set_field(receipt, "authorityPolicyVersion", json_string("2")?)?,
                    key,
                )?,
                key,
            ),
        ),
        ("nullReceipt", verify_audit_receipt(&Json::null(), key)),
        (
            "missingIntegrity",
            verify_audit_receipt(&remove_field(receipt, "integrity")?, key),
        ),
    ];
    for (label, got) in cases {
        let want = expect_bool(lookup_str(expected, label)?)?;
        if got != want {
            return Err(format!("{name} {label} got {got} want {want}"));
        }
    }
    Ok(())
}

fn check_keyid_swap(row: &Json, name: &str, catalog: &Catalog) -> Result<(), String> {
    let expected = field(row, "expected")?;
    let receipt = &catalog.v1_receipt;
    let key = &catalog.v1_key;
    let swapped = set_path(
        receipt,
        &["integrity", "keyId"],
        json_string("synthetic-key-b")?,
    )?;
    let got = verify_audit_receipt(&swapped, key);
    let want = expect_bool(field(expected, "swappedKeyIdOldSignature")?)?;
    if got != want {
        return Err(format!("{name} swapped {got} want {want}"));
    }
    let control = expect_bool(field(expected, "control_unchanged")?)?;
    if verify_audit_receipt(receipt, key) != control {
        return Err(format!("{name} control"));
    }
    Ok(())
}

fn check_v1_hash_mismatch(row: &Json, name: &str, catalog: &Catalog) -> Result<(), String> {
    let expected = field(row, "expected")?;
    let key = &catalog.v1_key;
    let zeros = "0".repeat(64);
    let mismatched = resign(
        &set_path(
            &catalog.v1_receipt,
            &["artifacts", "request", "hash"],
            json_string(&zeros)?,
        )?,
        key,
    )?;
    let got = verify_audit_receipt(&mismatched, key);
    let want = expect_bool(field(expected, "mismatchReMaced")?)?;
    if got != want {
        return Err(format!("{name} mismatch {got} want {want}"));
    }
    let control = resign(&catalog.v1_receipt, key)?;
    if verify_audit_receipt(&control, key)
        != expect_bool(field(expected, "control_reMacedUnchanged")?)?
    {
        return Err(format!("{name} control"));
    }
    Ok(())
}

fn check_key_encoding(row: &Json, name: &str, catalog: &Catalog) -> Result<(), String> {
    let expected = field(row, "expected")?;
    let key = catalog.v1_key.as_slice();
    if verify_audit_receipt(&catalog.v1_receipt, key)
        != expect_bool(field(expected, "keyAsUtf8Bytes")?)?
    {
        return Err(format!("{name} keyAsUtf8Bytes"));
    }
    let short = b"short";
    let resigned = resign(&catalog.v1_receipt, short)?;
    if verify_audit_receipt(&resigned, short) != expect_bool(field(expected, "fiveCharKey")?)? {
        return Err(format!("{name} fiveCharKey"));
    }
    match audit_signing_key(SigningKey::Text {
        utf8: short,
        utf16_len: 5,
    }) {
        Err(SignerError::ShortAuditKey) => {}
        other => return Err(format!("{name} runtimeRejectsShortKey {other:?}")),
    }
    let eight = "é".repeat(8);
    let eight_utf8 = eight.as_bytes();
    match audit_signing_key(SigningKey::Text {
        utf8: eight_utf8,
        utf16_len: 8,
    }) {
        Err(SignerError::ShortAuditKey) => {}
        other => return Err(format!("{name} runtimeEightNonAsciiChars {other:?}")),
    }
    match controlled_signing_key(eight_utf8) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "{name} controlledEightNonAsciiChars {}",
                err.code()
            ))
        }
    }
    match controlled_signing_key(&[b'a'; 15]) {
        Err(SignerError::ShortControlledKey) => {}
        other => return Err(format!("{name} controlledFifteenByteKey {other:?}")),
    }
    Ok(())
}

fn check_linkage(row: &Json, name: &str, catalog: &Catalog) -> Result<(), String> {
    let expected = field(row, "expected")?;
    let key = catalog.v2_key.as_slice();
    if verify_audit_receipt(&catalog.v2_allowed, key)
        != expect_bool(field(expected, "v2AllowedReceipt")?)?
    {
        return Err(format!("{name} v2AllowedReceipt"));
    }
    if verify_audit_receipt(&catalog.v2_denied, key)
        != expect_bool(field(expected, "v2DeniedReceipt")?)?
    {
        return Err(format!("{name} v2DeniedReceipt"));
    }
    let v2_cases = expect_object(field(expected, "v2Mutations")?)?;
    for (key_name, want_value) in v2_cases {
        let label = key_text(key_name)?;
        let want = expect_bool(want_value)?;
        let mutated = apply_v2_mutation(&catalog.v2_allowed, &label)?;
        let resigned = resign(&mutated, key)?;
        let got = verify_audit_receipt(&resigned, key);
        if got != want {
            return Err(format!("{name} v2 {label} got {got} want {want}"));
        }
    }
    let v1_cases = expect_object(field(expected, "v1Mutations")?)?;
    let v1_key = catalog.v1_key.as_slice();
    for (key_name, want_value) in v1_cases {
        let label = key_text(key_name)?;
        let want = expect_bool(want_value)?;
        let mutated = apply_v1_mutation(&catalog.v1_receipt, &label)?;
        let resigned = resign(&mutated, v1_key)?;
        let got = verify_audit_receipt(&resigned, v1_key);
        if got != want {
            return Err(format!("{name} v1 {label} got {got} want {want}"));
        }
    }
    Ok(())
}

fn check_restamp(row: &Json, name: &str) -> Result<(), String> {
    let input = field(row, "input")?;
    let expected = field(row, "expected")?;
    check_restamp_case(name, "v1", field(input, "v1")?, expected)?;
    check_restamp_case(name, "v2", field(input, "v2")?, expected)?;
    Ok(())
}

fn check_restamp_case(name: &str, label: &str, case: &Json, expected: &Json) -> Result<(), String> {
    let key = utf8_key(case)?;
    let receipt = field(case, "receipt")?;
    let issued = verify_audit_receipt(receipt, &key);
    let want_issued = expect_bool(field(expected, &format!("{label}AsIssued"))?)?;
    if issued != want_issued {
        return Err(format!(
            "{name} {label}AsIssued {issued} want {want_issued}"
        ));
    }
    let restamped = resign(receipt, &key)?;
    let got = verify_audit_receipt(&restamped, &key);
    let want = expect_bool(field(expected, &format!("{label}Restamped"))?)?;
    if got != want {
        return Err(format!("{name} {label}Restamped {got} want {want}"));
    }
    let sig = json_text(field(field(&restamped, "integrity")?, "signature")?)?;
    let want_sig = json_text(field(expected, &format!("{label}RestampedSignature"))?)?;
    if sig != want_sig {
        return Err(format!("{name} {label} signature {sig} != {want_sig}"));
    }
    Ok(())
}

fn apply_v2_mutation(receipt: &Json, label: &str) -> Result<Json, String> {
    match label {
        "resignedUnchanged_control" => Ok(receipt.clone()),
        "versionTagV1WithMarker2" => {
            set_field(receipt, "version", json_string(AUDIT_RECEIPT_VERSION)?)
        }
        "markerRemovedV2Tag" => remove_field(receipt, "authorityPolicyVersion"),
        "marker3" => set_field(receipt, "authorityPolicyVersion", json_string("3")?),
        "policyArtifactVersionLabel1" => set_path(
            receipt,
            &["artifacts", "policy", "version"],
            json_string("1")?,
        ),
        "planEnvelopeVersion1" => refresh_hashes(&set_path(
            receipt,
            &["artifacts", "plan", "value", "authority", "version"],
            json_string("1")?,
        )?),
        "planAuthorityHashUppercase" => {
            let hash = json_text(field_path(
                receipt,
                &["artifacts", "plan", "value", "authorityHash"],
            )?)?;
            set_path(
                receipt,
                &["artifacts", "plan", "value", "authorityHash"],
                json_string(&hash.to_ascii_uppercase())?,
            )
        }
        "artifactHashMismatch" => set_path(
            receipt,
            &["artifacts", "policy", "hash"],
            json_string(&"0".repeat(64))?,
        ),
        "argumentAuthorityVersion1" => refresh_hashes(&set_path(
            receipt,
            &["artifacts", "plan", "value", "argumentAuthority", "version"],
            json_string("1")?,
        )?),
        "backendMarker1" => refresh_hashes(&set_path(
            receipt,
            &["artifacts", "backend", "value", "authorityPolicyVersion"],
            json_string("1")?,
        )?),
        "backendAuthorityVersion1" => refresh_hashes(&set_path(
            receipt,
            &["artifacts", "backend", "value", "authority", "version"],
            json_string("1")?,
        )?),
        "policyLayer_outer_version1"
        | "policyLayer_agent_version1"
        | "policyLayer_session_version1"
        | "policyLayer_state_version1" => {
            let layer = label
                .strip_prefix("policyLayer_")
                .and_then(|rest| rest.strip_suffix("_version1"))
                .ok_or_else(|| format!("bad layer {label}"))?;
            refresh_hashes(&set_path(
                receipt,
                &["artifacts", "policy", "value", layer, "version"],
                json_string("1")?,
            )?)
        }
        "contractGrantsVersion1" => refresh_hashes(&set_path(
            receipt,
            &[
                "artifacts",
                "contract",
                "value",
                "authority",
                "grants",
                "version",
            ],
            json_string("1")?,
        )?),
        "requestAgentAuthorityVersion1" => refresh_hashes(&set_path(
            receipt,
            &[
                "artifacts",
                "request",
                "value",
                "agent",
                "authority",
                "version",
            ],
            json_string("1")?,
        )?),
        "requestSessionAuthorityVersion1" => refresh_hashes(&set_path(
            receipt,
            &[
                "artifacts",
                "request",
                "value",
                "session",
                "authority",
                "version",
            ],
            json_string("1")?,
        )?),
        "grantedDiffersFromEnvelope" => set_path(
            receipt,
            &["authority", "granted", "authority", "network"],
            Json::object(Vec::new()).map_err(|err| format!("empty {}", err.code()))?,
        ),
        "grantedRemoved" => remove_path(receipt, &["authority", "granted", "authority"]),
        _ => Err(format!("unknown v2 mutation {label}")),
    }
}

fn apply_v1_mutation(receipt: &Json, label: &str) -> Result<Json, String> {
    match label {
        "resignedUnchanged_control" => Ok(receipt.clone()),
        "versionTagV2NoMarker" => {
            set_field(receipt, "version", json_string(AUDIT_RECEIPT_V2_VERSION)?)
        }
        "planEnvelopeVersion2" => refresh_hashes(&set_path(
            receipt,
            &["artifacts", "plan", "value", "authority", "version"],
            json_string("2")?,
        )?),
        "planEnvelopeVersion1Explicit" => refresh_hashes(&set_path(
            receipt,
            &["artifacts", "plan", "value", "authority", "version"],
            json_string("1")?,
        )?),
        "grantedVersion2" => set_path(
            receipt,
            &["authority", "granted", "authority", "version"],
            json_string("2")?,
        ),
        _ => Err(format!("unknown v1 mutation {label}")),
    }
}

fn resign(receipt: &Json, key: &[u8]) -> Result<Json, String> {
    resign_audit_receipt(receipt, key).map_err(|err| format!("resign {}", err.code()))
}

fn refresh_hashes(receipt: &Json) -> Result<Json, String> {
    let artifacts = expect_object(field(receipt, "artifacts")?)?;
    let mut entries = Vec::new();
    for (name, entry) in artifacts {
        let value = field(entry, "value")?;
        let hash = stable_hash_value(value).map_err(|err| format!("hash {}", err.code()))?;
        entries.push((name.clone(), set_field(entry, "hash", json_string(&hash)?)?));
    }
    set_field(
        receipt,
        "artifacts",
        Json::object(entries).map_err(|err| format!("artifacts {}", err.code()))?,
    )
}

fn uppercase_signature(receipt: &Json) -> Result<Json, String> {
    let sig = json_text(field(field(receipt, "integrity")?, "signature")?)?;
    set_path(
        receipt,
        &["integrity", "signature"],
        json_string(&sig.to_ascii_uppercase())?,
    )
}

fn json_string(text: &str) -> Result<Json, String> {
    Ok(Json::string(Wtf16::from_str(text)))
}

fn expect_bool(value: &Json) -> Result<bool, String> {
    match &value.node {
        Node::Bool(flag) => Ok(*flag),
        _ => Err("expected bool".into()),
    }
}

fn lookup_str<'a>(entries: &'a [(Wtf16, Json)], name: &str) -> Result<&'a Json, String> {
    let want = Wtf16::from_str(name);
    lookup(entries, &want).ok_or_else(|| format!("missing {name}"))
}

fn field_path<'a>(value: &'a Json, path: &[&str]) -> Result<&'a Json, String> {
    let mut current = value;
    for name in path {
        current = field(current, name)?;
    }
    Ok(current)
}

fn set_field(value: &Json, name: &str, next: Json) -> Result<Json, String> {
    let want = Wtf16::from_str(name);
    let mut entries = Vec::new();
    let mut found = false;
    for (key, child) in expect_object(value)? {
        if key == &want {
            entries.push((key.clone(), next.clone()));
            found = true;
        } else {
            entries.push((key.clone(), child.clone()));
        }
    }
    if !found {
        entries.push((want, next));
    }
    Json::object(entries).map_err(|err| format!("set {name} {}", err.code()))
}

fn remove_field(value: &Json, name: &str) -> Result<Json, String> {
    let want = Wtf16::from_str(name);
    let entries = expect_object(value)?
        .iter()
        .filter(|(key, _)| key != &want)
        .cloned()
        .collect();
    Json::object(entries).map_err(|err| format!("remove {name} {}", err.code()))
}

fn set_path(value: &Json, path: &[&str], next: Json) -> Result<Json, String> {
    match path {
        [] => Err("empty path".into()),
        [name] => set_field(value, name, next),
        [name, rest @ ..] => {
            let child = match field(value, name) {
                Ok(existing) if existing.as_object().is_some() => existing.clone(),
                _ => Json::object(Vec::new())
                    .map_err(|err| format!("empty object {}", err.code()))?,
            };
            let updated = set_path(&child, rest, next)?;
            set_field(value, name, updated)
        }
    }
}

fn remove_path(value: &Json, path: &[&str]) -> Result<Json, String> {
    match path {
        [] => Err("empty path".into()),
        [name] => remove_field(value, name),
        [name, rest @ ..] => {
            let child = field(value, name)?;
            let updated = remove_path(child, rest)?;
            set_field(value, name, updated)
        }
    }
}
