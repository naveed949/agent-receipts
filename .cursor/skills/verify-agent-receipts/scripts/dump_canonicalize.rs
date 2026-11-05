use std::io::{self, Read, Write};

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("read stdin");
    match agent_receipts::canonical_json(&input) {
        Ok(bytes) => {
            let hash = agent_receipts::stable_hash(&input).expect("hash");
            let mut out = io::stdout().lock();
            write!(out, "ok ").expect("write stdout");
            for byte in &bytes {
                write!(out, "{byte:02x}").expect("write stdout");
            }
            writeln!(out, " {hash}").expect("write stdout");
        }
        Err(err) => println!("err {}", err.code()),
    }
}
