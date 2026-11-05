use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agent_receipts::canonical_json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

const NAMES: &[&str] = &[
    "duplicate-escaped.json",
    "duplicate-key.json",
    "integer-above-safe.json",
    "invalid-json.json",
    "lone-surrogate.json",
    "negative-zero.json",
    "not-utf8.json",
    "number-1e2.json",
    "trailing-value.json",
];

fn main() -> ExitCode {
    let dir = vectors_dir();
    let mut paths = match vector_paths(&dir) {
        Ok(paths) => paths,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    paths.sort();
    let names: Vec<&str> = paths
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .collect();
    if names != NAMES {
        eprintln!("vectors/text files {names:?}");
        return ExitCode::from(1);
    }

    println!("running {} vector cases", paths.len());
    let mut failed = 0usize;
    for path in &paths {
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("vector");
        match check_vector(path) {
            Ok(()) => println!("test {name} ... ok"),
            Err(err) => {
                failed += 1;
                println!("test {name} ... FAILED");
                eprintln!("{err}");
            }
        }
    }

    let passed = paths.len() - failed;
    if failed == 0 {
        println!("test result: ok. {passed} passed; 0 failed");
        ExitCode::SUCCESS
    } else {
        println!("test result: FAILED. {passed} passed; {failed} failed");
        ExitCode::from(1)
    }
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/text")
}

fn vector_paths(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        fs::read_dir(dir).map_err(|err| format!("failed to read {}: {err}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        return Err("vectors/text is empty".into());
    }
    Ok(paths)
}

fn check_vector(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let obj = parse_string_object(&text).map_err(|err| format!("{}: {err}", path.display()))?;
    let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    let input = decode_field(required_str(&obj, "input_b64")?)?;
    match keys.as_slice() {
        ["input_b64", "output_b64"] => check_success(path, &input, &obj),
        ["error", "input_b64"] => check_error(path, &input, required_str(&obj, "error")?),
        _ => Err(format!("{} has illegal keys {keys:?}", path.display())),
    }
}

fn check_success(path: &Path, input: &[u8], obj: &BTreeMap<String, String>) -> Result<(), String> {
    let expected = decode_field(required_str(obj, "output_b64")?)?;
    let got = canonical_json(input).map_err(|err| {
        format!(
            "{} returned {} for a success vector",
            path.display(),
            err.code()
        )
    })?;
    if got != expected {
        return Err(format!(
            "{} bytes differ\n got {}\n want {}",
            path.display(),
            STANDARD.encode(&got),
            STANDARD.encode(&expected)
        ));
    }
    let again = canonical_json(&got)
        .map_err(|err| format!("{} second pass returned {}", path.display(), err.code()))?;
    if again != got {
        return Err(format!("{} is not stable", path.display()));
    }
    Ok(())
}

fn check_error(path: &Path, input: &[u8], expected: &str) -> Result<(), String> {
    match canonical_json(input) {
        Ok(_) => Err(format!("{} succeeded, want {expected}", path.display())),
        Err(err) if err.code() == expected => Ok(()),
        Err(err) => Err(format!(
            "{} code {} != {expected}",
            path.display(),
            err.code()
        )),
    }
}

fn required_str<'a>(obj: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    obj.get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing string {key}"))
}

fn decode_field(field: &str) -> Result<Vec<u8>, String> {
    let bytes = STANDARD
        .decode(field)
        .map_err(|err| format!("base64: {err}"))?;
    let encoded = STANDARD.encode(&bytes);
    if encoded != field {
        return Err(format!("base64 field {field} encodes as {encoded}"));
    }
    Ok(bytes)
}

fn parse_string_object(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut cursor = Cursor { text, index: 0 };
    cursor.skip_ws();
    cursor.expect('{')?;
    cursor.skip_ws();
    let mut map = BTreeMap::new();
    if cursor.eat('}') {
        cursor.skip_ws();
        if !cursor.done() {
            return Err("trailing junk".into());
        }
        return Ok(map);
    }
    loop {
        cursor.skip_ws();
        let key = cursor.parse_string()?;
        cursor.skip_ws();
        cursor.expect(':')?;
        cursor.skip_ws();
        let value = cursor.parse_string()?;
        if map.insert(key.clone(), value).is_some() {
            return Err(format!("duplicate key {key}"));
        }
        cursor.skip_ws();
        if cursor.eat('}') {
            break;
        }
        cursor.expect(',')?;
    }
    cursor.skip_ws();
    if !cursor.done() {
        return Err("trailing junk".into());
    }
    Ok(map)
}

struct Cursor<'a> {
    text: &'a str,
    index: usize,
}

impl Cursor<'_> {
    fn done(&self) -> bool {
        self.index == self.text.len()
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
                self.index += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.text.get(self.index..)?.chars().next()
    }

    fn expect(&mut self, want: char) -> Result<(), String> {
        if self.eat(want) {
            Ok(())
        } else {
            Err(format!("expected {want}"))
        }
    }

    fn eat(&mut self, want: char) -> bool {
        if self.peek() == Some(want) {
            self.index += want.len_utf8();
            true
        } else {
            false
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            let ch = self.next_char()?;
            match ch {
                '"' => return Ok(out),
                '\\' => out.push(self.escape()?),
                ch if (ch as u32) < 0x20 => return Err("control in string".into()),
                ch => out.push(ch),
            }
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        match self.next_char()? {
            '"' => Ok('"'),
            '\\' => Ok('\\'),
            '/' => Ok('/'),
            'b' => Ok('\u{0008}'),
            'f' => Ok('\u{000c}'),
            'n' => Ok('\n'),
            'r' => Ok('\r'),
            't' => Ok('\t'),
            'u' => {
                let mut value = 0u32;
                for _ in 0..4 {
                    let digit = hex_digit(self.next_char()?).ok_or("bad hex")?;
                    value = (value << 4) | digit;
                }
                char::from_u32(value).ok_or_else(|| "bad unicode escape".into())
            }
            _ => Err("bad escape".into()),
        }
    }

    fn next_char(&mut self) -> Result<char, String> {
        let rest = self.text.get(self.index..).ok_or("truncated")?;
        let ch = rest.chars().next().ok_or("truncated")?;
        self.index += ch.len_utf8();
        Ok(ch)
    }
}

fn hex_digit(ch: char) -> Option<u32> {
    match ch {
        '0'..='9' => Some(u32::from(ch) - u32::from('0')),
        'a'..='f' => Some(u32::from(ch) - u32::from('a') + 10),
        'A'..='F' => Some(u32::from(ch) - u32::from('A') + 10),
        _ => None,
    }
}
