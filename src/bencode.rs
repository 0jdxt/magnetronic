use std::collections::HashMap;
use std::ops::Deref;
use std::str;

#[derive(Debug, Hash, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub struct Key(pub Vec<u8>);

impl TryFrom<Value> for Key {
    type Error = &'static str;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::ByteString(b) = value {
            Ok(Key(b))
        } else {
            Err("Only ByteString variants can be converted to Key")
        }
    }
}

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    ByteString(Vec<u8>),
    Integer(i64),
    List(Vec<Value>),
    Dict(HashMap<Key, Value>),
}

impl Value {
    pub fn get(&self, bs: &[u8]) -> Option<&Self> {
        match self {
            Self::Dict(d) => d.get(&Key(bs.to_vec())),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::ByteString(slice) => str::from_utf8(slice).ok(),
            _ => None,
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::ByteString(v) => match str::from_utf8(v) {
                Ok(s) => write!(f, "{s}"),
                Err(_) => write!(f, "0x{}", hex::encode(v)),
            },
            Value::Integer(n) => write!(f, "{n}"),
            Value::List(v) => {
                write!(f, "[")?;
                for (i, v) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Value::Dict(m) => {
                write!(f, "{{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", str::from_utf8(&k.0).unwrap_or("<?>"), v)?;
                }
                write!(f, "}}")
            }
        }
    }
}

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
