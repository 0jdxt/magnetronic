#![no_main]

use bencode::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|value: Value| {
    let encoded = encode(&value);
    let (decoded, consumed) = decode(&encoded).expect("encoded data must decode");
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded, value, "roundtrip failed");
});
