use super::*;

#[test]
fn test_key_from_value() {
    let string = Value::ByteString(b"some string".to_vec());
    let int = Value::Integer(0);
    let dict = Value::Dict(HashMap::new());
    let list = Value::List(vec![]);

    assert_eq!(Key::try_from(string), Ok(Key(b"some string".to_vec())));
    assert_eq!(Key::try_from(int.clone()), Err(Error::NotByteString(int)));
    assert_eq!(Key::try_from(dict.clone()), Err(Error::NotByteString(dict)));
    assert_eq!(Key::try_from(list.clone()), Err(Error::NotByteString(list)));
}

#[test]
fn test_integer_type_methods() {
    let int = Value::Integer(42);
    assert_eq!(int.as_int(), Ok(42));
    assert_eq!(int.as_str(), Err(Error::NotByteString(int.clone())));
    assert_eq!(int.get(b"key"), Err(Error::NotDict(int.clone())));
    assert_eq!(int.get_index(0), Err(Error::NotList(int.clone())));
}

#[test]
fn test_bytestring_type_methods() {
    let string = Value::ByteString(b"some string".to_vec());
    assert_eq!(string.as_str(), Ok("some string"));
    assert_eq!(string.as_int(), Err(Error::NotInteger(string.clone())));
    assert_eq!(string.get(b"key"), Err(Error::NotDict(string.clone())));
    assert_eq!(string.get_index(0), Err(Error::NotList(string.clone())));
}

#[test]
fn test_dict_type_methods() {
    let dict = Value::Dict(HashMap::new());
    assert_eq!(dict.get(b"key"), Ok(None));
    assert_eq!(dict.as_int(), Err(Error::NotInteger(dict.clone())));
    assert_eq!(dict.as_str(), Err(Error::NotByteString(dict.clone())));
    assert_eq!(dict.get_index(0), Err(Error::NotList(dict.clone())));
}

#[test]
fn test_list_type_methods() {
    let value = Value::Integer(100);
    let list = Value::List(vec![value.clone()]);
    assert_eq!(list.get_index(0), Ok(Some(&value)));
    assert_eq!(list.get_index(1), Ok(None));
    assert_eq!(list.get(b"key"), Err(Error::NotDict(list.clone())));
    assert_eq!(list.as_int(), Err(Error::NotInteger(list.clone())));
    assert_eq!(list.as_str(), Err(Error::NotByteString(list.clone())));
}

#[test]
fn test_decode_integer() {
    let (val, consumed) = decode(b"i42e").unwrap();
    assert_eq!(val, Value::Integer(42));
    assert_eq!(consumed, 4);
}

#[test]
fn test_decode_negative_integer() {
    let (val, consumed) = decode(b"i-123e").unwrap();
    assert_eq!(val, Value::Integer(-123));
    assert_eq!(consumed, 6);

    let result = val.as_int();
    assert!(matches!(result, Ok(-123)));
}

#[test]
fn test_decode_bytestring() {
    let (val, consumed) = decode(b"5:hello").unwrap();
    assert_eq!(val, Value::ByteString(b"hello".to_vec()));
    assert_eq!(consumed, 7);
}

#[test]
fn test_decode_empty_bytestring() {
    let (val, consumed) = decode(b"0:").unwrap();
    assert_eq!(val, Value::ByteString(vec![]));
    assert_eq!(consumed, 2);
}

#[test]
fn test_decode_invalid_utf8() {
    let (val, consumed) = decode(b"3:\xff\xff\xff").unwrap();
    assert_eq!(consumed, 5);
    assert_eq!(val, Value::ByteString(b"\xff\xff\xff".to_vec()));

    let err = val.as_str().unwrap_err();
    assert!(matches!(err, Error::Utf8(_)));
}

#[test]
fn test_decode_list() {
    let (val, consumed) = decode(b"l3:foo3:bare").unwrap();
    assert_eq!(
        val,
        Value::List(vec![
            Value::ByteString(b"foo".to_vec()),
            Value::ByteString(b"bar".to_vec())
        ])
    );
    assert_eq!(consumed, 12);
}

#[test]
fn test_decode_dict() {
    let (val, consumed) = decode(b"d3:bar3:baze").unwrap();
    let mut expected = std::collections::HashMap::new();
    expected.insert(Key(b"bar".to_vec()), Value::ByteString(b"baz".to_vec()));

    assert_eq!(val, Value::Dict(expected));
    assert_eq!(consumed, 12);
}

#[test]
fn test_decode_nested() {
    let (val, consumed) = decode(b"d4:spamli1ei2eee").unwrap();
    let mut expected = std::collections::HashMap::new();
    expected.insert(
        Key(b"spam".to_vec()),
        Value::List(vec![Value::Integer(1), Value::Integer(2)]),
    );
    assert_eq!(val, Value::Dict(expected));
    assert_eq!(consumed, 16);
}

#[test]
fn test_decode_empty_list() {
    let (val, consumed) = decode(b"le").unwrap();
    assert_eq!(val, Value::List(vec![]));
    assert_eq!(consumed, 2);
}

#[test]
fn test_decode_empty_dict() {
    let (val, consumed) = decode(b"de").unwrap();
    assert_eq!(val, Value::Dict(std::collections::HashMap::new()));
    assert_eq!(consumed, 2);
}

#[test]
fn test_decode_invalid_bytestring() {
    let err = decode(b"9999:hi").unwrap_err();
    assert_eq!(err, Error::UnexpectedEof);
}

#[test]
fn test_decode_invalid_integer() {
    let err = decode(b"iNaNe").unwrap_err();
    assert!(matches!(err, Error::ParseInt(_)));
}

#[test]
fn test_decode_incomplete_input() {
    let err = decode(b"i42").unwrap_err();
    assert_eq!(err, Error::MissingEnd);
}

#[test]
fn test_invalid_string_lengths() {
    // Leading zero
    assert!(matches!(
        decode(b"03:foo"),
        Err(Error::InvalidStrLen(s)) if s == "03"
    ));

    // Empty length
    assert!(matches!(
        decode(b":foo"),
        Err(Error::UnhandledByte(b':', Some(':')))
    ));

    // Non-digit length
    assert!(matches!(
        decode(b"a3:foo"),
        Err(Error::UnhandledByte(b'a', Some('a')))
    ));

    // Mixed garbage
    assert!(matches!(
        decode(b"1a:foo"),
        Err(Error::InvalidStrLen(s)) if s == "1a"
    ));

    // Length too large
    let big = format!("{}:{}", 10 * 1024 * 1024 + 1, "a");
    assert!(matches!(
        decode(big.as_bytes()),
        Err(Error::StringTooLong(n)) if n == 10 * 1024 * 1024 + 1
    ));

    // Declared length longer than actual data
    assert!(matches!(decode(b"5:hi"), Err(Error::UnexpectedEof)));

    // Valid empty string
    assert_eq!(
        decode(b"0:").unwrap().0,
        super::Value::ByteString(b"".to_vec())
    );
}

#[test]
fn test_invalid_integer_lengths() {
    // Negative zero
    assert!(matches!(
        decode(b"i-0e"),
        Err(Error::InvalidInteger(s)) if s == "-0"
    ));

    // Leading +ve zero
    assert!(matches!(
        decode(b"i0003e"),
        Err(Error::InvalidInteger(s)) if s == "0003"
    ));

    // Leading -ve zero
    assert!(matches!(
        decode(b"i-0003e"),
        Err(Error::InvalidInteger(s)) if s == "-0003"
    ));

    // Empty number
    assert!(matches!(
        decode(b"ie"),
        Err(Error::InvalidInteger(s)) if s.is_empty()
    ));

    // Invalid number chars
    assert!(matches!(decode(b"i--3e"), Err(Error::ParseInt(_))));

    // Invalid number chars
    assert!(matches!(decode(b"i2x5e"), Err(Error::ParseInt(_))));
}
