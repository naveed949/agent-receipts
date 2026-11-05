use std::io::{self, Read};

use agent_receipts::{
    audit_signing_key, controlled_signing_key, resign_audit_receipt_bytes,
    sign_controlled_integrity_bytes, stable_hash, verify_audit_receipt_bytes,
    verify_controlled_integrity_bytes, SigningKey,
};

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("read stdin");
    match run(&input) {
        Ok(line) => println!("{line}"),
        Err(line) => println!("{line}"),
    }
}

fn run(input: &[u8]) -> Result<String, String> {
    let cmd: serde_json::Value =
        serde_json::from_slice(input).map_err(|err| format!("err parse {err}"))?;
    let op = cmd
        .get("op")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "err missing op".to_string())?;
    match op {
        "verify_audit" => {
            let receipt = encode_value(&cmd["receipt"])?;
            let key = key_bytes(&cmd)?;
            Ok(format!("ok {}", verify_audit_receipt_bytes(&receipt, &key)))
        }
        "resign" => {
            let receipt = encode_value(&cmd["receipt"])?;
            let key = key_bytes(&cmd)?;
            match resign_audit_receipt_bytes(&receipt, &key) {
                Ok(bytes) => Ok(format!(
                    "ok {}",
                    String::from_utf8(bytes).map_err(|_| "err resign utf8")?
                )),
                Err(err) => Ok(format!("err {}", err.code())),
            }
        }
        "resign_then_verify" => {
            let receipt = encode_value(&cmd["receipt"])?;
            let key = key_bytes(&cmd)?;
            match resign_audit_receipt_bytes(&receipt, &key) {
                Ok(bytes) => Ok(format!("ok {}", verify_audit_receipt_bytes(&bytes, &key))),
                Err(_) => Ok("ok false".into()),
            }
        }
        "verify_controlled" => {
            let value = encode_value(&cmd["value"])?;
            let evidence = encode_value(&cmd["evidence"])?;
            let key = key_bytes(&cmd)?;
            let key_id = cmd["keyId"].as_str().ok_or("err missing keyId")?;
            Ok(format!(
                "ok {}",
                verify_controlled_integrity_bytes(&value, &key, key_id, &evidence)
            ))
        }
        "sign_controlled" => {
            let value = encode_value(&cmd["value"])?;
            let key = key_bytes(&cmd)?;
            let key_id = cmd["keyId"].as_str().ok_or("err missing keyId")?;
            match sign_controlled_integrity_bytes(&value, &key, key_id) {
                Ok(bytes) => Ok(format!(
                    "ok {}",
                    String::from_utf8(bytes).map_err(|_| "err sign utf8")?
                )),
                Err(err) => Ok(format!("err {}", signer_message(err.code()))),
            }
        }
        "audit_signing_key" => {
            let key = key_bytes(&cmd)?;
            let result = if is_bytes(&cmd) {
                audit_signing_key(SigningKey::Bytes(&key))
            } else {
                let units = cmd
                    .get("utf16Len")
                    .and_then(|value| value.as_u64())
                    .map(|n| n as usize)
                    .unwrap_or_else(|| String::from_utf8_lossy(&key).encode_utf16().count());
                audit_signing_key(SigningKey::Text {
                    utf8: &key,
                    utf16_len: units,
                })
            };
            match result {
                Ok(_) => Ok("ok".into()),
                Err(err) => Ok(format!("err {}", signer_message(err.code()))),
            }
        }
        "controlled_signing_key" => {
            let key = key_bytes(&cmd)?;
            match controlled_signing_key(&key) {
                Ok(_) => Ok("ok".into()),
                Err(err) => Ok(format!("err {}", signer_message(err.code()))),
            }
        }
        "stable_hash" => {
            let value = encode_value(&cmd["value"])?;
            match stable_hash(&value) {
                Ok(hash) => Ok(format!("ok {hash}")),
                Err(err) => Ok(format!("err {}", err.code())),
            }
        }
        other => Err(format!("err unknown op {other}")),
    }
}

fn encode_value(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|err| format!("err encode {err}"))
}

fn is_bytes(cmd: &serde_json::Value) -> bool {
    cmd.get("as").and_then(|value| value.as_str()) == Some("bytes")
}

fn key_bytes(cmd: &serde_json::Value) -> Result<Vec<u8>, String> {
    cmd.get("key")
        .and_then(|value| value.as_str())
        .map(|text| text.as_bytes().to_vec())
        .ok_or_else(|| "err missing key".into())
}

fn signer_message(code: &str) -> String {
    match code {
        "short_audit_key" => "audit signingKey must contain at least 16 bytes".into(),
        "short_controlled_key" => {
            "controlled integrity signing key must contain at least 16 bytes".into()
        }
        "invalid_key_id" => "invalid key id".into(),
        other => other.to_string(),
    }
}
