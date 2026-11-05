use std::fs;
use std::path::PathBuf;

use super::{
    canonical_json, canonical_json_value, parse::parse, stable_hash, stable_hash_value, Error,
    Json, Node, Wtf16,
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
    if count != rows.len() || rows.len() != 20 {
        return Err(format!("count {count} len {}", rows.len()));
    }

    let mut pending_lines = Vec::new();
    let mut seen = Vec::new();
    let mut failures = Vec::new();
    let mut canonical_ok = 0usize;
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
    if canonical_ok != 8 || pending_lines.len() != 12 || canonical_ok + pending_lines.len() != 20 {
        failures.push(format!(
            "counts canonicalize {canonical_ok} pending {}",
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
        Node::Number(number) if number.get() == 20.0 => Ok(20),
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
