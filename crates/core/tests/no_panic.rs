use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use agent_receipts::{
    canonical_json, compare_authority_contracts_bytes, is_https_authority_subset_bytes,
    normalize_authority_policy_bytes, normalize_https_authority_rules_bytes,
    resign_audit_receipt_bytes, stable_hash, verify_audit_receipt_bytes,
    verify_controlled_integrity_bytes,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};

const SEED: u64 = 0x1234_5678_9ABC_DEF1;

#[test]
fn corpus_returns_result_and_ok_is_idempotent() {
    for input in corpus() {
        let parsed = catch_unwind(AssertUnwindSafe(|| canonical_json(&input)));
        let parsed = match parsed {
            Ok(result) => result,
            Err(_) => panic!("canonical_json panicked on {}", prefix(&input)),
        };
        match parsed {
            Ok(bytes) => {
                let again = catch_unwind(AssertUnwindSafe(|| canonical_json(&bytes)));
                match again {
                    Ok(Ok(second)) => assert_eq!(second, bytes, "{}", prefix(&input)),
                    Ok(Err(err)) => panic!("second pass {} on {}", err.code(), prefix(&input)),
                    Err(_) => panic!("second pass panicked on {}", prefix(&input)),
                }
                let hash = catch_unwind(AssertUnwindSafe(|| stable_hash(&input)));
                let hash = match hash {
                    Ok(Ok(hash)) => hash,
                    Ok(Err(err)) => panic!("stable_hash {} on {}", err.code(), prefix(&input)),
                    Err(_) => panic!("stable_hash panicked on {}", prefix(&input)),
                };
                assert_eq!(hash, sha256_hex(&bytes), "{}", prefix(&input));
                let again_hash = catch_unwind(AssertUnwindSafe(|| stable_hash(&bytes)));
                match again_hash {
                    Ok(Ok(again)) => assert_eq!(again, hash),
                    Ok(Err(err)) => panic!("second hash {} on {}", err.code(), prefix(&input)),
                    Err(_) => panic!("second hash panicked on {}", prefix(&input)),
                }
            }
            Err(err) => {
                let hash = catch_unwind(AssertUnwindSafe(|| stable_hash(&input)));
                match hash {
                    Ok(Err(hash_err)) => assert_eq!(hash_err, err),
                    Ok(Ok(_)) => panic!("stable_hash succeeded on {}", prefix(&input)),
                    Err(_) => panic!("stable_hash panicked on {}", prefix(&input)),
                }
            }
        }
        probe_hmac(&input);
        probe_authority(&input);
    }
}

fn probe_authority(input: &[u8]) {
    let compared = catch_unwind(AssertUnwindSafe(|| {
        compare_authority_contracts_bytes(input, input)
    }));
    match compared {
        Ok(_) => {}
        Err(_) => panic!(
            "compare_authority_contracts_bytes panicked on {}",
            prefix(input)
        ),
    }
    let normalized = catch_unwind(AssertUnwindSafe(|| normalize_authority_policy_bytes(input)));
    match normalized {
        Ok(_) => {}
        Err(_) => panic!(
            "normalize_authority_policy_bytes panicked on {}",
            prefix(input)
        ),
    }
    let rules = catch_unwind(AssertUnwindSafe(|| {
        normalize_https_authority_rules_bytes(input)
    }));
    match rules {
        Ok(_) => {}
        Err(_) => panic!(
            "normalize_https_authority_rules_bytes panicked on {}",
            prefix(input)
        ),
    }
    let subset = catch_unwind(AssertUnwindSafe(|| {
        is_https_authority_subset_bytes(input, input)
    }));
    match subset {
        Ok(_) => {}
        Err(_) => panic!(
            "is_https_authority_subset_bytes panicked on {}",
            prefix(input)
        ),
    }
}

fn probe_hmac(input: &[u8]) {
    let verified = catch_unwind(AssertUnwindSafe(|| {
        verify_audit_receipt_bytes(input, input)
    }));
    match verified {
        Ok(_) => {}
        Err(_) => panic!("verify_audit_receipt_bytes panicked on {}", prefix(input)),
    }
    let resigned = catch_unwind(AssertUnwindSafe(|| {
        resign_audit_receipt_bytes(input, input)
    }));
    match resigned {
        Ok(_) => {}
        Err(_) => panic!("resign_audit_receipt_bytes panicked on {}", prefix(input)),
    }
    let controlled = catch_unwind(AssertUnwindSafe(|| {
        verify_controlled_integrity_bytes(input, input, "k", input)
    }));
    match controlled {
        Ok(_) => {}
        Err(_) => panic!(
            "verify_controlled_integrity_bytes panicked on {}",
            prefix(input)
        ),
    }
}

fn corpus() -> Vec<Vec<u8>> {
    let mut rng = XorShift64(SEED);
    let mut inputs = Vec::new();
    for _ in 0..200 {
        let len = usize::try_from(rng.next_u64() % 257).unwrap();
        inputs.push(rng.bytes(len));
    }
    inputs.push(Vec::new());
    inputs.push(vec![0xFF]);
    inputs.push(b"{".to_vec());
    inputs.push(br#"{"a":1,"a":2}"#.to_vec());
    inputs.push(nested_arrays(129));
    inputs.push(nested_arrays(10_000));
    inputs.extend(text_inputs());
    inputs
}

fn text_inputs() -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/text");
    let mut paths = Vec::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display())) {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    assert!(!paths.is_empty(), "vectors/text is empty");
    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            let field = string_field(&text, "input_b64").unwrap_or_else(|err| {
                panic!("{}: {err}", path.display());
            });
            STANDARD.decode(field).unwrap_or_else(|err| {
                panic!("{} base64: {err}", path.display());
            })
        })
        .collect()
}

fn string_field<'a>(text: &'a str, key: &str) -> Result<&'a str, String> {
    let marker = format!("\"{key}\":\"");
    let start = text.find(&marker).ok_or_else(|| format!("missing {key}"))? + marker.len();
    let end = text[start..]
        .find('"')
        .ok_or_else(|| format!("unterminated {key}"))?
        + start;
    Ok(&text[start..end])
}

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(depth * 2 + 1);
    bytes.extend(std::iter::repeat(b'[').take(depth));
    bytes.push(b'0');
    bytes.extend(std::iter::repeat(b']').take(depth));
    bytes
}

fn prefix(input: &[u8]) -> String {
    let shown = input.len().min(16);
    format!("{} bytes {:02x?}", input.len(), &input[..shown])
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    hex
}

struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.0 = state;
        state
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}
