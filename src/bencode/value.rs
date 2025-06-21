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
