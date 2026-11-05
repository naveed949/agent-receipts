use std::io::{self, Read};

use agent_receipts::{compare_authority_contracts_bytes, CompareResult};

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
    let previous = encode_value(&cmd["previous"])?;
    let next = encode_value(&cmd["next"])?;
    match compare_authority_contracts_bytes(&previous, &next) {
        Ok(result) => Ok(format!("ok {}", result_json(&result))),
        Err(_) => Ok("err TypeError".into()),
    }
}

fn encode_value(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|err| format!("err encode {err}"))
}

fn result_json(result: &CompareResult) -> String {
    let widened = result
        .widened
        .iter()
        .map(|path| format!("\"{}\"", path.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let narrowed = result
        .narrowed
        .iter()
        .map(|path| format!("\"{}\"", path.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"relationship\":\"{}\",\"widened\":[{widened}],\"narrowed\":[{narrowed}]}}",
        result.relationship.as_str()
    )
}
