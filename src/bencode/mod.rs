use std::collections::HashMap;
use std::str;

pub mod value;
pub use value::Value;

pub fn decode(bytes: &[u8]) -> (Value, usize) {
    match bytes[0] {
        b'0'..=b'9' => {
            // Example: "5:hello" -> "hello"
            let colon_index = bytes.iter().position(|&b| b == b':').unwrap();
            let len: usize = str::from_utf8(&bytes[..colon_index])
                .unwrap()
                .parse()
                .unwrap();
            let start = colon_index + 1;
            let end = start + len;
            (Value::ByteString(bytes[start..end].into()), end)
        }
        b'i' => {
            // Example: "i52e" -> 52
            let end = bytes.iter().position(|&b| b == b'e').unwrap();
            let number = str::from_utf8(&bytes[1..end]).unwrap().parse().unwrap();
            (Value::Integer(number), end + 1)
        }
        b'l' => {
            // Example "l3:fooi52e" -> [ "foo", 52]
            let mut values = Vec::new();
            let mut i = 1;
            while bytes[i] != b'e' {
                let (v, len) = decode(&bytes[i..]);
                values.push(v);
                i += len;
            }
            (Value::List(values), i + 1)
        }
        b'd' => {
            let mut dict = HashMap::new();
            let mut i = 1;
            while bytes[i] != b'e' {
                let (key, len_k) = decode(&bytes[i..]);
                i += len_k;

                let (val, len_v) = decode(&bytes[i..]);
                i += len_v;

                dict.insert(key.try_into().unwrap(), val);
            }
            (Value::Dict(dict), i + 1)
        }
        b => unreachable!("unhandled byte: {} {:?}", b, str::from_utf8(bytes)),
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
