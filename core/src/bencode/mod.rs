use std::{collections::HashMap, io::Write, str};
use thiserror::Error;

pub mod value;
pub use value::*;

#[cfg(test)]
mod tests;

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
    Utf8(#[from] str::Utf8Error),

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

    #[error("MAX_DEPTH exceeded parsing data")]
    DepthExceeded,

    #[error("Encountered invalid string length: '{0}'")]
    InvalidStrLen(String),

    #[error("String too long: {0} bytes")]
    StringTooLong(usize),

    #[error("Invalid integer: {0}")]
    InvalidInteger(String),

    #[error("Trailing data found: [{0:?}]")]
    TrailingData(Vec<u8>),
}

pub const MAX_DEPTH: usize = 1024;
/// # Errors
/// Will return some parsing error for:
/// - malformed input
/// - a value exceeds 10MB in size
/// - nested depth exceeds {`MAX_DEPTH`}
pub fn decode(bytes: &[u8]) -> Result<(Value, usize), Error> {
    let (value, consumed) = decode_with_depth(bytes, 0)?;
    if consumed == bytes.len() {
        Ok((value, consumed))
    } else {
        Err(Error::TrailingData(bytes[consumed..].to_vec()))
    }
}

fn decode_with_depth(bytes: &[u8], depth: usize) -> Result<(Value, usize), Error> {
    let depth = depth + 1;
    if depth > MAX_DEPTH {
        return Err(Error::DepthExceeded);
    }

    match bytes.first().ok_or(Error::UnexpectedEof)? {
        b'0'..=b'9' => {
            // STRINGS: "5:hello" -> "hello"
            let colon_index = bytes
                .iter()
                .position(|&b| b == b':')
                .ok_or(Error::MissingColon)?;

            let len_str = str::from_utf8(&bytes[..colon_index])?;

            // check length is valid
            if len_str.len() > 1 && len_str.starts_with('0') // leading zeroes
                || len_str.is_empty()
                || !len_str.chars().all(|c| c.is_ascii_digit())
            {
                return Err(Error::InvalidStrLen(len_str.into()));
            }

            // parse into usize
            let Ok(len) = len_str.parse() else {
                return Err(Error::InvalidStrLen(len_str.into()));
            };
            // dont let strings exceed 10MB
            if len > 10 * 1024 * 1024 {
                return Err(Error::StringTooLong(len));
            }

            let start = colon_index + 1;
            let end = start.checked_add(len).ok_or(Error::UnexpectedEof)?;
            if end > bytes.len() {
                Err(Error::UnexpectedEof)
            } else {
                Ok((Value::ByteString(bytes[start..end].into()), end))
            }
        }
        b'i' => {
            // INTS: "i52e" -> 52
            let end = bytes
                .iter()
                .position(|&b| b == b'e')
                .ok_or(Error::MissingEnd)?;

            let num_str = str::from_utf8(&bytes[1..end])?;
            // validate number: empty, neg zero, +ve/-ve leading zero
            if num_str.is_empty()
                || num_str == "-0"
                || num_str.len() > 1 && num_str.starts_with('0')
                || num_str.len() > 2 && num_str.starts_with("-0")
            {
                return Err(Error::InvalidInteger(num_str.into()));
            }

            Ok((Value::Integer(num_str.parse()?), end + 1))
        }
        b'l' => {
            // LISTS: "l3:fooi52e" -> [ "foo", 52 ]
            let mut values = Vec::new();
            let mut i = 1;
            while i < bytes.len() && bytes[i] != b'e' {
                let (v, len) = decode_with_depth(&bytes[i..], depth)?;
                values.push(v);
                i += len;
            }
            if i < bytes.len() {
                Ok((Value::List(values), i + 1))
            } else {
                Err(Error::MissingEnd)
            }
        }
        b'd' => {
            // DICTS: "d3:fooi52ee" -> { foo => 52 }
            let mut dict = HashMap::new();
            let mut i = 1;
            while i < bytes.len() && bytes[i] != b'e' {
                let (key, len_k) = decode_with_depth(&bytes[i..], depth)?;
                i += len_k;
                let key = key.try_into().map_err(|_| Error::NonByteStringKey)?;

                let (val, len_v) = decode_with_depth(&bytes[i..], depth)?;
                i += len_v;

                dict.insert(key, val);
            }
            if i < bytes.len() {
                Ok((Value::Dict(dict), i + 1))
            } else {
                Err(Error::MissingEnd)
            }
        }
        b => Err(Error::UnhandledByte(*b, Some(*b as char))),
    }
}

#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    match value {
        Value::ByteString(b) => {
            let mut out = Vec::with_capacity(b.len() + 20);
            write!(&mut out, "{}:", b.len()).expect("writing ByteString length");
            out.extend(b);
            out
        }
        Value::Integer(n) => {
            let mut out = Vec::with_capacity(24); // enough for "i" + digits + "e"
            write!(&mut out, "i{n}e").expect("writing Integer");
            out
        }
        Value::List(lst) => {
            let mut out = Vec::with_capacity(16);
            out.push(b'l');
            for v in lst {
                out.extend(encode(v));
            }
            out.push(b'e');
            out
        }
        Value::Dict(map) => {
            let mut out = Vec::with_capacity(16);
            out.push(b'd');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort(); // bencode dicts must be sorted by raw key bytes
            for k in keys {
                write!(&mut out, "{}:", k.len()).expect("writing Dict length");
                out.extend(k.iter());
                out.extend(encode(&map[k]));
            }
            out.push(b'e');
            out
        }
    }
}
