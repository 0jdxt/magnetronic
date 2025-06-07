use serde_json::Value;
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    // If encoded_value starts with a digit, it's a number
    let type_char = encoded_value.chars().next().unwrap();

    if type_char.is_digit(10) {
        // Example: "5:hello" -> "hello"
        let colon_index = encoded_value.find(':').unwrap();
        let number_string = &encoded_value[..colon_index];
        let number: usize = number_string.parse().unwrap();
        let string = &encoded_value[colon_index + 1..colon_index + 1 + number];
        return Value::String(string.to_string());
    } else if type_char == 'i' {
        // Example: "i52e" -> 52
        let end = encoded_value.find('e').unwrap();
        let number_string = &encoded_value[1..end];
        let number = number_string.parse().unwrap();
        return Value::Number(number);
    } else if type_char == 'l' {
        let mut values = Vec::new();
        let mut i = 1;
        while encoded_value.chars().nth(i) != Some('e') {
            let v = decode_bencoded_value(&encoded_value[i..]);
            // println!("processing: {}", &encoded_value[i..]);

            let skip = match &v {
                Value::String(s) => s.len() + 2,
                Value::Number(n) => {
                    let n = n.as_i64().unwrap();
                    n.abs().ilog10() as usize + 3 + n.is_negative() as usize
                }
                _ => panic!("unknown value"),
            };

            // println!("remaining: {}", &encoded_value[i + skip..]);
            // println!("{} - skip {}", v, skip);
            values.push(v);
            i += skip;
        }
        return serde_json::Value::Array(values);
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
    }
}

// Usage: your_program.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
