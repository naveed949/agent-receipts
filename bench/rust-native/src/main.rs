use std::io::{self, Read, Write};
use std::time::Instant;

use agent_receipts::{
    canonical_json_value, compare_authority_contracts, stable_hash_value, verify_audit_receipt,
    verify_controlled_integrity, Json, Wtf16,
};
use serde_json::{json, Map, Value};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .map_err(|err| err.to_string())?;
    let plan: Value = serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    let plan = plan.as_object().ok_or("plan")?;
    if plan.get("schema").and_then(Value::as_u64) != Some(1) {
        return Err("schema".to_string());
    }
    let cases = plan.get("cases").and_then(Value::as_array).ok_or("cases")?;
    let mut probes = Vec::new();
    let mut samples = Vec::new();
    for case in cases {
        let case = case.as_object().ok_or("case")?;
        let operation = case
            .get("operation")
            .and_then(Value::as_str)
            .ok_or("operation")?;
        let case_id = case.get("caseId").cloned().ok_or("caseId")?;
        let warmup = required_u32(case, "warmup")?;
        let iterations = required_u32(case, "iterations")?;
        let payload = case.get("payload").ok_or("payload")?;
        let prepared = prepare(operation, payload)?;
        let observed = prepared.probe()?;
        let ns = prepared.time(warmup, iterations)?;
        probes.push(json!({
            "operation": operation,
            "caseId": case_id,
            "observed": observed,
        }));
        samples.push(json!({
            "operation": operation,
            "caseId": case_id,
            "ns": ns,
        }));
    }
    let reply = json!({
        "schema": 1,
        "probes": probes,
        "samples": samples,
    });
    let text = serde_json::to_string(&reply).map_err(|err| err.to_string())?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{text}").map_err(|err| err.to_string())?;
    Ok(())
}

fn required_u32(case: &Map<String, Value>, name: &str) -> Result<u32, String> {
    let value = case.get(name).and_then(Value::as_u64).ok_or(name)?;
    u32::try_from(value).map_err(|_| name.to_string())
}

enum Prepared {
    Text(Json, TextOp),
    Audit(Json, Vec<u8>),
    Controlled(Json, Vec<u8>, String, Json),
    Compare(Json, Json),
}

enum TextOp {
    Canonical,
    Hash,
}

impl Prepared {
    fn probe(&self) -> Result<Value, String> {
        match self {
            Prepared::Text(value, TextOp::Canonical) => {
                let bytes = canonical_json_value(value).map_err(|err| err.code().to_string())?;
                let text = String::from_utf8(bytes).map_err(|_| "canonical utf-8".to_string())?;
                Ok(Value::String(text))
            }
            Prepared::Text(value, TextOp::Hash) => {
                let text = stable_hash_value(value).map_err(|err| err.code().to_string())?;
                Ok(Value::String(text))
            }
            Prepared::Audit(receipt, key) => Ok(Value::Bool(verify_audit_receipt(receipt, key))),
            Prepared::Controlled(value, key, key_id, evidence) => Ok(Value::Bool(
                verify_controlled_integrity(value, key, key_id, evidence),
            )),
            Prepared::Compare(previous, next) => {
                let result = compare_authority_contracts(previous, next)
                    .map_err(|err| err.code().to_string())?;
                Ok(json!({
                    "relationship": result.relationship.as_str(),
                    "widened": result.widened.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
                    "narrowed": result.narrowed.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
                }))
            }
        }
    }

    fn time(&self, warmup: u32, iterations: u32) -> Result<Vec<u64>, String> {
        match self {
            Prepared::Text(value, TextOp::Canonical) => time_loop(
                warmup,
                iterations,
                || canonical_json_value(value).map_err(|err| err.code().to_string()),
                |bytes| bytes.len() as u64,
            ),
            Prepared::Text(value, TextOp::Hash) => time_loop(
                warmup,
                iterations,
                || stable_hash_value(value).map_err(|err| err.code().to_string()),
                |text| text.len() as u64,
            ),
            Prepared::Audit(receipt, key) => time_loop(
                warmup,
                iterations,
                || Ok(verify_audit_receipt(receipt, key)),
                |flag| u64::from(*flag),
            ),
            Prepared::Controlled(value, key, key_id, evidence) => time_loop(
                warmup,
                iterations,
                || Ok(verify_controlled_integrity(value, key, key_id, evidence)),
                |flag| u64::from(*flag),
            ),
            Prepared::Compare(previous, next) => time_loop(
                warmup,
                iterations,
                || {
                    compare_authority_contracts(previous, next)
                        .map_err(|err| err.code().to_string())
                },
                |result| result.relationship.as_str().len() as u64,
            ),
        }
    }
}

fn prepare(operation: &str, payload: &Value) -> Result<Prepared, String> {
    match operation {
        "canonical_json" => Ok(Prepared::Text(json_to_agent(payload)?, TextOp::Canonical)),
        "stable_hash" => Ok(Prepared::Text(json_to_agent(payload)?, TextOp::Hash)),
        "verify_audit_receipt" => {
            let object = payload.as_object().ok_or("audit payload")?;
            let receipt = json_to_agent(object.get("receipt").ok_or("receipt")?)?;
            let key = object
                .get("key")
                .and_then(Value::as_str)
                .ok_or("key")?
                .as_bytes()
                .to_vec();
            Ok(Prepared::Audit(receipt, key))
        }
        "verify_controlled_integrity" => {
            let object = payload.as_object().ok_or("controlled payload")?;
            let value = json_to_agent(object.get("value").ok_or("value")?)?;
            let key = object
                .get("key")
                .and_then(Value::as_str)
                .ok_or("key")?
                .as_bytes()
                .to_vec();
            let key_id = object
                .get("keyId")
                .and_then(Value::as_str)
                .ok_or("keyId")?
                .to_string();
            let evidence = json_to_agent(object.get("evidence").ok_or("evidence")?)?;
            Ok(Prepared::Controlled(value, key, key_id, evidence))
        }
        "compare_authority_contracts" => {
            let object = payload.as_object().ok_or("compare payload")?;
            let previous = json_to_agent(object.get("previous").ok_or("previous")?)?;
            let next = json_to_agent(object.get("next").ok_or("next")?)?;
            Ok(Prepared::Compare(previous, next))
        }
        _ => Err(format!("operation {operation}")),
    }
}

fn json_to_agent(value: &Value) -> Result<Json, String> {
    match value {
        Value::Null => Ok(Json::null()),
        Value::Bool(flag) => Ok(Json::bool(*flag)),
        Value::Number(number) => {
            Json::number(finite_f64(number)?).map_err(|err| err.code().to_string())
        }
        Value::String(text) => Ok(Json::string(Wtf16::from_str(text))),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_agent(item)?);
            }
            Ok(Json::array(out))
        }
        Value::Object(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (key, child) in map {
                entries.push((Wtf16::from_str(key), json_to_agent(child)?));
            }
            Json::object(entries).map_err(|err| err.code().to_string())
        }
    }
}

fn finite_f64(number: &serde_json::Number) -> Result<f64, String> {
    if let Some(value) = number.as_i64() {
        let float = value as f64;
        if float as i64 != value {
            return Err("integer is not exact in f64".to_string());
        }
        return Ok(float);
    }
    if let Some(value) = number.as_u64() {
        let float = value as f64;
        if float as u64 != value {
            return Err("integer is not exact in f64".to_string());
        }
        return Ok(float);
    }
    let float = number.as_f64().ok_or("number")?;
    if !float.is_finite() {
        return Err("non-finite".to_string());
    }
    Ok(float)
}

fn time_loop<T>(
    warmup: u32,
    iterations: u32,
    mut call: impl FnMut() -> Result<T, String>,
    observe: impl Fn(&T) -> u64,
) -> Result<Vec<u64>, String> {
    for _ in 0..warmup {
        let value = call()?;
        std::hint::black_box(observe(&value));
    }
    let mut samples = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let started = Instant::now();
        let value = call()?;
        std::hint::black_box(observe(&value));
        let elapsed = nanos(started.elapsed())?;
        samples.push(elapsed);
        drop(value);
    }
    Ok(samples)
}

fn nanos(elapsed: std::time::Duration) -> Result<u64, String> {
    let value = u64::try_from(elapsed.as_nanos()).map_err(|_| "sample".to_string())?;
    if value > MAX_SAFE_INTEGER {
        return Err("sample exceeds the json integer range".to_string());
    }
    Ok(value)
}
