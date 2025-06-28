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

#[test]
fn test_new_piece_initialization() {
    let piece = Piece::new(1024, 256);
    assert_eq!(piece.total_size, 1024);
    assert_eq!(piece.block_size, 256);
    assert_eq!(piece.data.len(), 1024);
    assert_eq!(piece.blocks_downloaded.len(), 4);
    assert!(!piece.is_complete());
}

#[test]
fn test_write_block_and_is_complete() {
    let mut piece = Piece::new(1024, 256);

    // Write one block
    let block = vec![1u8; 256];
    piece.write_block(0, &block);
    assert!(!piece.is_complete());
    assert_eq!(&piece.data[0..256], &block[..]);
    assert!(piece.blocks_downloaded[0]);

    // Write remaining blocks
    for i in 1..piece.blocks_downloaded.len() {
        let start = i * piece.block_size;
        piece.write_block(start, &block);
    }

    assert!(piece.is_complete());
}

#[test]
#[should_panic(expected = "Block write out of bounds")]
fn test_write_block_out_of_bounds_panics() {
    let mut piece = Piece::new(1024, 256);
    let block = vec![0u8; 512];
    piece.write_block(800, &block); // 800 + 512 = 1312 > 1024, should panic
}

#[test]
fn test_next_request_returns_correct_block() {
    let mut piece = Piece::new(1024, 256);

    // Initially first block should be requested
    assert_eq!(piece.next_request(), Some((0, 256)));

    // Write first block
    piece.write_block(0, &vec![0u8; 256]);
    assert_eq!(piece.next_request(), Some((256, 256)));

    // Write second block
    piece.write_block(256, &vec![0u8; 256]);
    assert_eq!(piece.next_request(), Some((512, 256)));

    // Write last two blocks
    piece.write_block(512, &vec![0u8; 256]);
    piece.write_block(768, &vec![0u8; 256]);

    // Now no blocks left to request
    assert_eq!(piece.next_request(), None);
    assert!(piece.is_complete());
}

#[test]
fn test_next_request_for_partial_last_block() {
    // total_size not a multiple of block_size
    let mut piece = Piece::new(1025, 256);

    // Blocks: 256, 256, 256, 256, 1 byte
    assert_eq!(piece.blocks_downloaded.len(), 5);

    for i in 0..4 {
        let start = i * piece.block_size;
        piece.write_block(start, &vec![0u8; 256]);
    }

    // Last block only 1 byte length
    assert_eq!(piece.next_request(), Some((1024, 1)));

    // Write last partial block
    piece.write_block(1024, &[0]);

    assert_eq!(piece.next_request(), None);
    assert!(piece.is_complete());
}
