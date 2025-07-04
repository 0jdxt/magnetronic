use super::Error;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::ops::Deref;
use std::str;

#[derive(Debug, Hash, Eq, PartialEq, Clone, PartialOrd, Ord, Arbitrary)]
pub struct Key(pub Vec<u8>);

impl TryFrom<Value> for Key {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::ByteString(b) => Ok(Key(b)),
            _ => Err(Error::NotByteString(value)),
        }
    }
}

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Arbitrary)]
pub enum Value {
    ByteString(Vec<u8>),
    Integer(i64),
    List(Vec<Value>),
    Dict(HashMap<Key, Value>),
}

impl Value {
    pub fn get(&self, bs: &[u8]) -> Result<Option<&Self>, Error> {
        match self {
            Self::Dict(d) => Ok(d.get(&Key(bs.to_vec()))),
            _ => Err(Error::NotDict(self.clone())),
        }
    }

    pub fn get_index(&self, idx: usize) -> Result<Option<&Self>, Error> {
        match self {
            Self::List(list) => Ok(list.get(idx)),
            _ => Err(Error::NotList(self.clone())),
        }
    }

    pub fn as_int(&self) -> Result<i64, Error> {
        match self {
            Self::Integer(n) => Ok(*n),
            _ => Err(Error::NotInteger(self.clone())),
        }
    }

    pub fn as_str(&self) -> Result<&str, Error> {
        match self {
            Self::ByteString(slice) => Ok(str::from_utf8(slice)?),
            _ => Err(Error::NotByteString(self.clone())),
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::ByteString(v) => {
                f.write_str("\"")?;
                match str::from_utf8(v) {
                    Ok(s) => f.write_str(s),
                    Err(_) => write!(f, "0x{}", hex::encode(v)),
                }?;
                f.write_str("\"")
            }
            Value::Integer(n) => write!(f, "{n}"),
            Value::List(v) => {
                f.write_str("[")?;
                for (i, v) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Dict(m) => {
                f.write_str("{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}: {}", str::from_utf8(&k.0).unwrap_or("<?>"), v)?;
                }
                f.write_str("}")
            }
        }
    }
}
