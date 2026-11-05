use crate::{check_depth, Error, Json, Node};

pub(crate) fn emit(value: &Json) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut stack = vec![Task::Value(value)];
    let mut depth = 0usize;
    while let Some(task) = stack.pop() {
        match task {
            Task::Punct(byte) => write_punct(byte, &mut out, &mut depth)?,
            Task::Key(units) => write_string(units, &mut out),
            Task::Value(current) => push_value(current, &mut out, &mut stack, &mut depth)?,
        }
    }
    if depth != 0 {
        return Err(Error::InvalidJson);
    }
    Ok(out)
}

enum Task<'a> {
    Value(&'a Json),
    Key(&'a [u16]),
    Punct(u8),
}

fn push_value<'a>(
    current: &'a Json,
    out: &mut Vec<u8>,
    stack: &mut Vec<Task<'a>>,
    depth: &mut usize,
) -> Result<(), Error> {
    match &current.node {
        Node::Null => out.extend_from_slice(b"null"),
        Node::Bool(true) => out.extend_from_slice(b"true"),
        Node::Bool(false) => out.extend_from_slice(b"false"),
        Node::Number(number) => format_number(number.get(), out),
        Node::String(text) => write_string(text.units(), out),
        Node::Array(items) => {
            check_depth(*depth + 1)?;
            out.push(b'[');
            if items.is_empty() {
                out.push(b']');
            } else {
                *depth += 1;
                stack.push(Task::Punct(b']'));
                for (index, item) in items.iter().enumerate().rev() {
                    stack.push(Task::Value(item));
                    if index > 0 {
                        stack.push(Task::Punct(b','));
                    }
                }
            }
        }
        Node::Object(entries) => {
            check_depth(*depth + 1)?;
            out.push(b'{');
            if entries.is_empty() {
                out.push(b'}');
            } else {
                *depth += 1;
                stack.push(Task::Punct(b'}'));
                for (index, (key, child)) in entries.iter().enumerate().rev() {
                    stack.push(Task::Value(child));
                    stack.push(Task::Punct(b':'));
                    stack.push(Task::Key(key.units()));
                    if index > 0 {
                        stack.push(Task::Punct(b','));
                    }
                }
            }
        }
    }
    Ok(())
}

fn write_punct(byte: u8, out: &mut Vec<u8>, depth: &mut usize) -> Result<(), Error> {
    if byte == b']' || byte == b'}' {
        *depth = depth.checked_sub(1).ok_or(Error::InvalidJson)?;
    }
    out.push(byte);
    Ok(())
}

fn write_string(units: &[u16], out: &mut Vec<u8>) {
    out.push(b'"');
    escape(units, out);
    out.push(b'"');
}

fn escape(units: &[u16], out: &mut Vec<u8>) {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if is_high_surrogate(unit) {
            if let Some(&next) = units.get(index + 1) {
                if is_low_surrogate(next) {
                    push_utf8(scalar_from_pair(unit, next), out);
                    index += 2;
                    continue;
                }
            }
        }
        if is_high_surrogate(unit) || is_low_surrogate(unit) {
            push_hex4(unit, out);
            index += 1;
            continue;
        }
        match unit {
            0x22 => out.extend_from_slice(b"\\\""),
            0x5C => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x00..=0x1F => push_hex4(unit, out),
            other => push_utf8(u32::from(other), out),
        }
        index += 1;
    }
}

fn format_number(value: f64, out: &mut Vec<u8>) {
    debug_assert!(value.is_finite());
    debug_assert!(value.is_sign_positive() || value != 0.0);
    let mut buffer = ryu_js::Buffer::new();
    let text = buffer.format_finite(value);
    out.extend_from_slice(text.as_bytes());
}

fn push_utf8(code_point: u32, out: &mut Vec<u8>) {
    if code_point < 0x80 {
        out.push(code_point as u8);
    } else if code_point < 0x800 {
        out.push((0xC0 | (code_point >> 6)) as u8);
        out.push((0x80 | (code_point & 0x3F)) as u8);
    } else if code_point < 0x10000 {
        out.push((0xE0 | (code_point >> 12)) as u8);
        out.push((0x80 | ((code_point >> 6) & 0x3F)) as u8);
        out.push((0x80 | (code_point & 0x3F)) as u8);
    } else {
        out.push((0xF0 | (code_point >> 18)) as u8);
        out.push((0x80 | ((code_point >> 12) & 0x3F)) as u8);
        out.push((0x80 | ((code_point >> 6) & 0x3F)) as u8);
        out.push((0x80 | (code_point & 0x3F)) as u8);
    }
}

fn push_hex4(unit: u16, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(&[
        b'\\',
        b'u',
        HEX[usize::from((unit >> 12) & 0xF)],
        HEX[usize::from((unit >> 8) & 0xF)],
        HEX[usize::from((unit >> 4) & 0xF)],
        HEX[usize::from(unit & 0xF)],
    ]);
}

fn is_high_surrogate(unit: u16) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

fn is_low_surrogate(unit: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
}

fn scalar_from_pair(high: u16, low: u16) -> u32 {
    0x10000 + (u32::from(high - 0xD800) << 10) + u32::from(low - 0xDC00)
}
