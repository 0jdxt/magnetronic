#![no_main]

use bencode::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fn max_depth(value: &Value) -> usize {
        match value {
            Value::ByteString(_) | Value::Integer(_) => 1,
            Value::List(items) => 1 + items.iter().map(max_depth).max().unwrap_or(0),
            Value::Dict(map) => 1 + map.values().map(max_depth).max().unwrap_or(0),
        }
    }

    fn max_string_len(value: &Value) -> usize {
        match value {
            Value::ByteString(bytes) => bytes.len(),
            Value::Integer(_) => 0,
            Value::List(items) => items.iter().map(max_string_len).max().unwrap_or(0),
            Value::Dict(map) => map.values().map(max_string_len).max().unwrap_or(0),
        }
    }

    if let Ok((value, consumed)) = decode(data) {
        assert_eq!(consumed, data.len(), "did not consume all input");

        assert!(
            max_depth(&value) <= bencode::MAX_DEPTH,
            "exceeded max depth"
        );
        assert!(
            max_string_len(&value) <= 10 * 1024 * 1024,
            "string too long"
        );

        let enc = encode(&value);
        let (val2, _) = decode(&enc).unwrap();

        assert_eq!(value, val2, "roundtrip");
    }
});
