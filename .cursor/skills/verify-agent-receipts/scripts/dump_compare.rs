use std::collections::BTreeSet;
use std::io::{self, Read};

use agent_receipts::{compare_authority_contracts_bytes, AuthorityError, CompareResult};

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("read stdin");
    match run(&input) {
        Ok(line) => println!("{line}"),
        Err(line) => println!("{line}"),
    }
}

fn run(input: &[u8]) -> Result<String, String> {
    let (previous, next) = match extract_command(input) {
        Ok(pair) => pair,
        Err(ExtractError::DuplicateKey) => return Ok("err invalid_input".into()),
        Err(ExtractError::Parse(msg)) => return Err(format!("err parse {msg}")),
    };
    match compare_authority_contracts_bytes(&previous, &next) {
        Ok(result) => Ok(format!("ok {}", result_json(&result))),
        Err(AuthorityError::InvalidInput) => Ok("err invalid_input".into()),
        Err(_) => Ok("err TypeError".into()),
    }
}

enum ExtractError {
    DuplicateKey,
    Parse(&'static str),
}

struct Parser<'a> {
    input: &'a [u8],
    i: usize,
}

fn extract_command(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ExtractError> {
    let mut parser = Parser { input, i: 0 };
    parser.skip_ws();
    parser.expect(b'{')?;
    let mut previous = None;
    let mut next = None;
    let mut keys = BTreeSet::new();
    loop {
        parser.skip_ws();
        if parser.peek() == Some(b'}') {
            parser.i += 1;
            break;
        }
        if !keys.is_empty() {
            parser.expect(b',')?;
            parser.skip_ws();
        }
        let key = parser.parse_string()?;
        if !keys.insert(key.clone()) {
            return Err(ExtractError::DuplicateKey);
        }
        parser.skip_ws();
        parser.expect(b':')?;
        parser.skip_ws();
        let start = parser.i;
        parser.skip_value()?;
        let value = parser.input[start..parser.i].to_vec();
        match key.as_str() {
            "previous" => previous = Some(value),
            "next" => next = Some(value),
            _ => {}
        }
    }
    parser.skip_ws();
    if parser.i != parser.input.len() {
        return Err(ExtractError::Parse("trailing"));
    }
    match (previous, next) {
        (Some(previous), Some(next)) => Ok((previous, next)),
        _ => Err(ExtractError::Parse("missing previous or next")),
    }
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, want: u8) -> Result<(), ExtractError> {
        if self.peek() != Some(want) {
            return Err(ExtractError::Parse("token"));
        }
        self.i += 1;
        Ok(())
    }

    fn skip_value(&mut self) -> Result<(), ExtractError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.skip_object(),
            Some(b'[') => self.skip_array(),
            Some(b'"') => {
                self.parse_string()?;
                Ok(())
            }
            Some(b't') => self.skip_literal(b"true"),
            Some(b'f') => self.skip_literal(b"false"),
            Some(b'n') => self.skip_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            _ => Err(ExtractError::Parse("value")),
        }
    }

    fn skip_object(&mut self) -> Result<(), ExtractError> {
        self.expect(b'{')?;
        let mut keys = BTreeSet::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.i += 1;
                return Ok(());
            }
            if !keys.is_empty() {
                self.expect(b',')?;
                self.skip_ws();
            }
            let key = self.parse_string()?;
            if !keys.insert(key) {
                return Err(ExtractError::DuplicateKey);
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_value()?;
        }
    }

    fn skip_array(&mut self) -> Result<(), ExtractError> {
        self.expect(b'[')?;
        let mut first = true;
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.i += 1;
                return Ok(());
            }
            if !first {
                self.expect(b',')?;
                self.skip_ws();
            }
            first = false;
            self.skip_value()?;
        }
    }

    fn skip_literal(&mut self, lit: &[u8]) -> Result<(), ExtractError> {
        if self.input.get(self.i..self.i + lit.len()) != Some(lit) {
            return Err(ExtractError::Parse("literal"));
        }
        self.i += lit.len();
        Ok(())
    }

    fn skip_number(&mut self) -> Result<(), ExtractError> {
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.i += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(ExtractError::Parse("number")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ExtractError::Parse("fraction"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ExtractError::Parse("exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> Result<String, ExtractError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(ExtractError::Parse("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'/') => out.push('/'),
                        Some(b'b') => out.push('\u{0008}'),
                        Some(b'f') => out.push('\u{000c}'),
                        Some(b'n') => out.push('\n'),
                        Some(b'r') => out.push('\r'),
                        Some(b't') => out.push('\t'),
                        Some(b'u') => {
                            self.i += 1;
                            out.push(self.hex_escape()?);
                            continue;
                        }
                        _ => return Err(ExtractError::Parse("escape")),
                    }
                    self.i += 1;
                }
                Some(b) if b < 0x20 => return Err(ExtractError::Parse("control")),
                Some(_) => {
                    let rest = std::str::from_utf8(&self.input[self.i..])
                        .map_err(|_| ExtractError::Parse("utf8"))?;
                    let ch = rest.chars().next().ok_or(ExtractError::Parse("utf8"))?;
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn hex_escape(&mut self) -> Result<char, ExtractError> {
        let mut code = 0u32;
        for _ in 0..4 {
            let b = self.peek().ok_or(ExtractError::Parse("hex"))?;
            let digit = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a') + 10,
                b'A'..=b'F' => u32::from(b - b'A') + 10,
                _ => return Err(ExtractError::Parse("hex")),
            };
            self.i += 1;
            code = (code << 4) | digit;
        }
        char::from_u32(code).ok_or(ExtractError::Parse("hex"))
    }
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
