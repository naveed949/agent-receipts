use crate::{check_depth, Error, Finite, Json, Node, Wtf16};

pub(crate) fn parse(input: &[u8]) -> Result<Json, Error> {
    let text = std::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        index: 0,
        stack: Vec::new(),
        done: None,
    };
    parser.parse_document()
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    index: usize,
    stack: Vec<Frame>,
    done: Option<Json>,
}

enum Frame {
    Array {
        items: Vec<Json>,
        slot: Slot,
    },
    ObjKey {
        entries: Vec<(Wtf16, Json)>,
        slot: Slot,
    },
    Colon {
        entries: Vec<(Wtf16, Json)>,
        key: Wtf16,
    },
    ObjValue {
        entries: Vec<(Wtf16, Json)>,
        key: Wtf16,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Item,
    Comma,
}

enum Role {
    Value,
    Comma,
    Key,
    Colon,
}

impl Parser<'_> {
    fn parse_document(&mut self) -> Result<Json, Error> {
        loop {
            if let Some(value) = self.done.take() {
                if self.stack.is_empty() {
                    self.skip_ws();
                    if self.index != self.bytes.len() {
                        return Err(Error::InvalidJson);
                    }
                    return Ok(value);
                }
                self.attach(value)?;
                continue;
            }
            self.skip_ws();
            self.step()?;
        }
    }

    fn attach(&mut self, value: Json) -> Result<(), Error> {
        match self.stack.pop() {
            Some(Frame::Array { mut items, .. }) => {
                items.push(value);
                self.stack.push(Frame::Array {
                    items,
                    slot: Slot::Comma,
                });
                Ok(())
            }
            Some(Frame::ObjValue { mut entries, key }) => {
                entries.push((key, value));
                self.stack.push(Frame::ObjKey {
                    entries,
                    slot: Slot::Comma,
                });
                Ok(())
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn step(&mut self) -> Result<(), Error> {
        let byte = self.byte()?;
        match self.role() {
            Role::Comma => self.step_comma(byte),
            Role::Key => self.step_key(byte),
            Role::Colon => self.step_colon(byte),
            Role::Value => self.step_value(byte),
        }
    }

    fn role(&self) -> Role {
        match self.stack.last() {
            Some(Frame::Array {
                slot: Slot::Comma, ..
            })
            | Some(Frame::ObjKey {
                slot: Slot::Comma, ..
            }) => Role::Comma,
            Some(Frame::ObjKey {
                slot: Slot::Item, ..
            }) => Role::Key,
            Some(Frame::Colon { .. }) => Role::Colon,
            Some(Frame::Array {
                slot: Slot::Item, ..
            })
            | Some(Frame::ObjValue { .. })
            | None => Role::Value,
        }
    }

    fn step_comma(&mut self, byte: u8) -> Result<(), Error> {
        match byte {
            b',' => {
                self.index += 1;
                self.set_item_slot()
            }
            b']' => {
                self.index += 1;
                self.finish_array()
            }
            b'}' => {
                self.index += 1;
                self.finish_object()
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn step_key(&mut self, byte: u8) -> Result<(), Error> {
        match byte {
            b'}' => {
                self.index += 1;
                self.finish_object()
            }
            b'"' => {
                let key = self.parse_string()?;
                self.become_colon(key)
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn step_colon(&mut self, byte: u8) -> Result<(), Error> {
        if byte != b':' {
            return Err(Error::InvalidJson);
        }
        self.index += 1;
        match self.stack.pop() {
            Some(Frame::Colon { entries, key }) => {
                self.stack.push(Frame::ObjValue { entries, key });
                Ok(())
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn step_value(&mut self, byte: u8) -> Result<(), Error> {
        match byte {
            b'n' => self.finish_literal(b"null", Json::null()),
            b't' => self.finish_literal(b"true", Json::bool(true)),
            b'f' => self.finish_literal(b"false", Json::bool(false)),
            b'"' => {
                let text = self.parse_string()?;
                self.done = Some(Json::string(text));
                Ok(())
            }
            b'-' | b'0'..=b'9' => self.parse_number(),
            b'[' => {
                self.index += 1;
                self.push_frame(Frame::Array {
                    items: Vec::new(),
                    slot: Slot::Item,
                })
            }
            b'{' => {
                self.index += 1;
                self.push_frame(Frame::ObjKey {
                    entries: Vec::new(),
                    slot: Slot::Item,
                })
            }
            b']' => {
                self.index += 1;
                self.finish_array()
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn finish_literal(&mut self, literal: &[u8], value: Json) -> Result<(), Error> {
        let rest = self.bytes.get(self.index..).ok_or(Error::InvalidJson)?;
        if !rest.starts_with(literal) {
            return Err(Error::InvalidJson);
        }
        self.index += literal.len();
        self.done = Some(value);
        Ok(())
    }

    fn push_frame(&mut self, frame: Frame) -> Result<(), Error> {
        check_depth(self.stack.len() + 1)?;
        self.stack.push(frame);
        Ok(())
    }

    fn set_item_slot(&mut self) -> Result<(), Error> {
        match self.stack.last_mut() {
            Some(Frame::Array { slot, .. }) | Some(Frame::ObjKey { slot, .. }) => {
                *slot = Slot::Item;
                Ok(())
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn finish_array(&mut self) -> Result<(), Error> {
        match self.stack.pop() {
            Some(Frame::Array { items, slot }) if slot == Slot::Comma || items.is_empty() => {
                self.done = Some(Json::array(items));
                Ok(())
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn finish_object(&mut self) -> Result<(), Error> {
        match self.stack.pop() {
            Some(Frame::ObjKey { entries, slot }) if slot == Slot::Comma || entries.is_empty() => {
                self.done = Some(Json::object(entries)?);
                Ok(())
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn become_colon(&mut self, key: Wtf16) -> Result<(), Error> {
        match self.stack.pop() {
            Some(Frame::ObjKey {
                entries,
                slot: Slot::Item,
            }) => {
                self.stack.push(Frame::Colon { entries, key });
                Ok(())
            }
            _ => Err(Error::InvalidJson),
        }
    }

    fn parse_number(&mut self) -> Result<(), Error> {
        let start = self.index;
        let end = scan_number(self.bytes, start)?;
        let literal = self.text.get(start..end).ok_or(Error::InvalidJson)?;
        let parsed = literal.parse::<f64>().map_err(|_| Error::InvalidJson)?;
        let finite = Finite::try_new(parsed).ok_or(Error::InvalidJson)?;
        self.index = end;
        self.done = Some(Json {
            node: Node::Number(finite),
        });
        Ok(())
    }

    fn parse_string(&mut self) -> Result<Wtf16, Error> {
        if self.byte()? != b'"' {
            return Err(Error::InvalidJson);
        }
        self.index += 1;
        let mut units = Vec::new();
        loop {
            let byte = self.byte()?;
            if byte == b'"' {
                self.index += 1;
                return Ok(Wtf16::from_units(units));
            }
            if byte == b'\\' {
                self.index += 1;
                self.push_escape(&mut units)?;
                continue;
            }
            if byte < 0x20 {
                return Err(Error::InvalidJson);
            }
            let scalar = self.next_scalar()?;
            let mut encoded = [0u16; 2];
            units.extend_from_slice(scalar.encode_utf16(&mut encoded));
        }
    }

    fn push_escape(&mut self, units: &mut Vec<u16>) -> Result<(), Error> {
        let byte = self.byte()?;
        self.index += 1;
        let unit = match byte {
            b'"' | b'\\' | b'/' => u16::from(byte),
            b'b' => 0x08,
            b'f' => 0x0C,
            b'n' => 0x0A,
            b'r' => 0x0D,
            b't' => 0x09,
            b'u' => return self.push_hex_unit(units),
            _ => return Err(Error::InvalidJson),
        };
        units.push(unit);
        Ok(())
    }

    fn push_hex_unit(&mut self, units: &mut Vec<u16>) -> Result<(), Error> {
        let mut value = 0u16;
        for _ in 0..4 {
            let digit = hex_value(self.byte()?).ok_or(Error::InvalidJson)?;
            self.index += 1;
            value = (value << 4) | digit;
        }
        // A \u escape is one code unit. Combining surrogates here would drop a lone surrogate.
        units.push(value);
        Ok(())
    }

    fn next_scalar(&mut self) -> Result<char, Error> {
        let rest = self.text.get(self.index..).ok_or(Error::InvalidJson)?;
        let scalar = rest.chars().next().ok_or(Error::InvalidJson)?;
        self.index += scalar.len_utf8();
        Ok(scalar)
    }

    fn byte(&self) -> Result<u8, Error> {
        self.bytes
            .get(self.index)
            .copied()
            .ok_or(Error::InvalidJson)
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.bytes.get(self.index).copied() {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' => self.index += 1,
                _ => break,
            }
        }
    }
}

fn scan_number(bytes: &[u8], start: usize) -> Result<usize, Error> {
    let mut index = start;
    if bytes.get(index) == Some(&b'-') {
        index += 1;
    }
    match bytes.get(index) {
        Some(b'0') => {
            index += 1;
            if matches!(bytes.get(index), Some(b'0'..=b'9')) {
                return Err(Error::InvalidJson);
            }
        }
        Some(b'1'..=b'9') => {
            index += 1;
            while matches!(bytes.get(index), Some(b'0'..=b'9')) {
                index += 1;
            }
        }
        _ => return Err(Error::InvalidJson),
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == fraction {
            return Err(Error::InvalidJson);
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let exponent = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == exponent {
            return Err(Error::InvalidJson);
        }
    }
    if index == start {
        return Err(Error::InvalidJson);
    }
    Ok(index)
}

fn hex_value(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some(u16::from(byte - b'0')),
        b'a'..=b'f' => Some(u16::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u16::from(byte - b'A' + 10)),
        _ => None,
    }
}
