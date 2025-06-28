use std::collections::HashMap;
use std::str;
use thiserror::Error;

pub mod value;
pub use value::*;

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("Expected ByteString but found {0:?}")]
    NotByteString(Value),

    #[error("Expected Integer but found {0:?}")]
    NotInteger(Value),

    #[error("Expected Dict but found {0:?}")]
    NotDict(Value),

    #[error("Expected List but found {0:?}")]
    NotList(Value),

    #[error("Invalid UTF-8 in Bencode: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Invalid integer in Bencode: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("Invalid format: missing ':' for string length")]
    MissingColon,

    #[error("Invalid format: missing 'e' terminator")]
    MissingEnd,

    #[error("Invalid format: expected ByteString key in dict")]
    NonByteStringKey,

    #[error("Unexpected end of input")]
    UnexpectedEof,

    #[error("Unhandled byte: {0} (char: {1:?})")]
    UnhandledByte(u8, Option<char>),
}

pub fn decode(bytes: &[u8]) -> Result<(Value, usize), Error> {
    match bytes.first().ok_or(Error::UnexpectedEof)? {
        b'0'..=b'9' => {
            // Example: "5:hello" -> "hello"
            let colon_index = bytes
                .iter()
                .position(|&b| b == b':')
                .ok_or(Error::MissingColon)?;
            let len: usize = str::from_utf8(&bytes[..colon_index])?.parse()?;
            let start = colon_index + 1;
            let end = start.checked_add(len).ok_or(Error::UnexpectedEof)?;
            if end > bytes.len() {
                Err(Error::UnexpectedEof)
            } else {
                Ok((Value::ByteString(bytes[start..end].into()), end))
            }
        }
        b'i' => {
            // Example: "i52e" -> 52
            let end = bytes
                .iter()
                .position(|&b| b == b'e')
                .ok_or(Error::MissingEnd)?;
            let number = str::from_utf8(&bytes[1..end])?.parse()?;
            Ok((Value::Integer(number), end + 1))
        }
        b'l' => {
            // Example "l3:fooi52e" -> [ "foo", 52]
            let mut values = Vec::new();
            let mut i = 1;
            while i < bytes.len() && bytes[i] != b'e' {
                let (v, len) = decode(&bytes[i..])?;
                values.push(v);
                i += len;
            }
            if i >= bytes.len() {
                Err(Error::MissingEnd)
            } else {
                Ok((Value::List(values), i + 1))
            }
        }
        b'd' => {
            let mut dict = HashMap::new();
            let mut i = 1;
            while i < bytes.len() && bytes[i] != b'e' {
                let (key, len_k) = decode(&bytes[i..])?;
                i += len_k;
                let key = key.try_into().map_err(|_| Error::NonByteStringKey)?;

                let (val, len_v) = decode(&bytes[i..])?;
                i += len_v;

                dict.insert(key, val);
            }
            if i >= bytes.len() {
                Err(Error::MissingEnd)
            } else {
                Ok((Value::Dict(dict), i + 1))
            }
        }
        b => Err(Error::UnhandledByte(*b, Some(*b as char))),
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    match value {
        Value::ByteString(b) => {
            let mut out = format!("{}:", b.len()).into_bytes();
            out.extend(b);
            out
        }
        Value::Integer(n) => format!("i{n}e").into_bytes(),
        Value::List(lst) => {
            let mut out = vec![b'l'];
            for v in lst {
                out.extend(encode(v));
            }
            out.push(b'e');
            out
        }
        Value::Dict(map) => {
            let mut out = vec![b'd'];
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort(); // bencode dicts must be sorted by raw key bytes
            for k in keys {
                let val = &map[k];
                out.extend(format!("{}:", k.len()).into_bytes());
                out.extend(k.iter());
                out.extend(encode(val));
            }
            out.push(b'e');
            out
        }
    }
}

#[cfg(test)]
mod tests;
