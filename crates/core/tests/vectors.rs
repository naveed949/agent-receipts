use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agent_receipts::canonicalize_bytes;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{Map, Value};

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
    if paths.is_empty() {
        eprintln!("vectors/canonicalize is empty");
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/canonicalize")
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
    Ok(paths)
}

fn check_vector(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| format!("{} is not JSON: {err}", path.display()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let input = decode_field(required_str(obj, "input_b64")?)?;

    match keys.as_slice() {
        ["input_b64", "output_b64"] => check_success(path, &input, obj),
        ["error", "input_b64"] => check_error(path, &input, required_str(obj, "error")?),
        _ => Err(format!("{} has illegal keys {keys:?}", path.display())),
    }
}

fn check_success(path: &Path, input: &[u8], obj: &Map<String, Value>) -> Result<(), String> {
    let expected = decode_field(required_str(obj, "output_b64")?)?;
    let got = canonicalize_bytes(input).map_err(|err| {
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
    let again = canonicalize_bytes(&got)
        .map_err(|err| format!("{} second pass returned {}", path.display(), err.code()))?;
    if again != got {
        return Err(format!("{} is not stable", path.display()));
    }
    Ok(())
}

fn check_error(path: &Path, input: &[u8], expected: &str) -> Result<(), String> {
    match canonicalize_bytes(input) {
        Ok(_) => Err(format!("{} succeeded, want {expected}", path.display())),
        Err(err) if err.code() == expected => Ok(()),
        Err(err) => Err(format!(
            "{} code {} != {expected}",
            path.display(),
            err.code()
        )),
    }
}

fn required_str<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(Value::as_str)
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
