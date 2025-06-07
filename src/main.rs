use serde_json::{Map, Value};

fn value_length(v: &Value) -> usize {
    match &v {
        Value::String(s) => s.len() + s.len().ilog10() as usize + 2,
        Value::Number(n) => {
            let n = n.as_i64().unwrap();
            n.abs().ilog10() as usize + 3 + n.is_negative() as usize
        }
        Value::Array(v) => v.iter().map(|x| value_length(x)).sum::<usize>() + 1,
        Value::Object(o) => {
            o.iter()
                .map(|(k, v)| k.len() + 2 + value_length(v))
                .sum::<usize>()
                + 2
        }
        _ => panic!("unknown value"),
    }
}

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> Value {
    let type_char = encoded_value.chars().next().unwrap();

    if type_char.is_digit(10) {
        // Example: "5:hello" -> "hello"
        let colon_index = encoded_value.find(':').unwrap();
        let number_string = &encoded_value[..colon_index];
        let number: usize = number_string.parse().unwrap();
        let string = &encoded_value[colon_index + 1..colon_index + 1 + number];
        Value::String(string.to_string())
    } else if type_char == 'i' {
        // Example: "i52e" -> 52
        let end = encoded_value.find('e').unwrap();
        let number_string = &encoded_value[1..end];
        let number = number_string.parse().unwrap();
        Value::Number(number)
    } else if type_char == 'l' {
        // Example "l3:fooi52e" -> [ "foo", 52]
        let mut values = Vec::new();
        let mut i = 1;
        while encoded_value.chars().nth(i) != Some('e') {
            let v = decode_bencoded_value(&encoded_value[i..]);
            i += value_length(&v);
            values.push(v);
        }
        Value::Array(values)
    } else if type_char == 'd' {
        let mut dict = Map::new();
        let mut i = 1;
        while encoded_value.chars().nth(i) != Some('e') {
            let key = decode_bencoded_value(&encoded_value[i..]);
            i += value_length(&key);

            let val = decode_bencoded_value(&encoded_value[i..]);
            i += value_length(&val);

            dict.insert(key.as_str().unwrap().to_string(), val);
        }
        Value::Object(dict)
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
    }
}

// Usage: your_program.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
