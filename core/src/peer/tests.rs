use super::*;

fn roundtrip_message(msg: &Message) {
    let mut bytes = msg.to_bytes().unwrap();
    let parsed_msg = Message::try_from(&mut bytes[4..]).unwrap();
    assert_eq!(msg, &parsed_msg, "Roundtrip failed for {msg:?}");
}

#[test]
fn test_choke_message() {
    let msg = Message::Choke;
    roundtrip_message(&msg);
}

#[test]
fn test_unchoke_message() {
    let msg = Message::Unchoke;
    roundtrip_message(&msg);
}

#[test]
fn test_have_message() {
    let msg = Message::Have(42);
    roundtrip_message(&msg);
}

#[test]
fn test_request_message() {
    let msg = Message::Request {
        index: 1,
        begin: 2,
        length: 3,
    };
    roundtrip_message(&msg);
}

#[test]
fn test_piece_message() {
    let data = b"hello world";
    let msg = Message::Piece {
        index: 0,
        begin: 0,
        block: &data[..],
    };
    roundtrip_message(&msg);
}

#[test]
fn test_bitfield_message() {
    let data = &[0b1010_1010, 0b0101_0101];
    let msg = Message::Bitfield(data);
    roundtrip_message(&msg);
}

#[test]
fn test_extended_message() {
    let msg = Message::Extended {
        id: 1,
        payload: b"d1:md11:ut_metadatai16eee",
    };
    roundtrip_message(&msg);
}

#[test]
fn test_unknown_message() {
    let payload = b"random payload";
    let msg = Message::Unknown(99, payload);
    roundtrip_message(&msg);
}

#[test]
fn test_from_bytes_to_bytes() {
    // raw example bytes for "Have" message (message id 4 + payload)
    let mut bytes = [0, 0, 0, 5, 4, 0, 0, 0, 42]; // length=5, id=4, payload=42 (u32)
    let msg = Message::try_from(&mut bytes[4..]).unwrap();
    assert_eq!(msg, Message::Have(42));

    let serialized = msg.to_bytes().unwrap();
    assert_eq!(serialized, bytes);
}
