#![allow(clippy::too_many_lines)]
use crate::{
    bencode::{Key, Value},
    error::TorrentError,
    handshake::Handshake,
    peer::{Message, MessageParseError, Piece},
    torrent::TorrentInfo,
};
use mockito::Matcher;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_download_with_non_ascii_peer_id_and_invalid_block() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", Matcher::Regex(r".*info_hash=.*".into()))
        .with_status(200)
        .with_body(crate::bencode::encode(&Value::Dict({
            let mut map = HashMap::new();
            map.insert(
                Key(b"peers".to_vec()),
                Value::ByteString(vec![127, 0, 0, 1, 26, 225]), // 127.0.0.1:6881
            );
            map
        })))
        .create_async()
        .await;

    let block_data = vec![42u8; 256];
    let expected_hash = Sha1::digest(&block_data);
    let torrent = TorrentInfo {
        info_hash: [0u8; 20],
        piece_length: 512,
        total_length: 512,
        piece_hashes: vec![expected_hash.into()],
        trackers: vec![server.url()],
        filename: "test.txt".to_string(),
        peers: vec!["127.0.0.1:6881".parse().unwrap()],
    };

    let (mut client, mut server) = duplex(1024);
    let peer_id = &[0xFF; 20];

    tokio::spawn(async move {
        let mut buf = [0u8; 68];
        if let Err(e) = server.read_exact(&mut buf).await {
            log::error!("Server read handshake error: {e}");
            return;
        }
        let handshake = Handshake::new(&torrent.info_hash, peer_id);
        if let Err(e) = server.write_all(&handshake.0).await {
            log::error!("Server write handshake error: {e}");
            return;
        }
        let bitfield = Message::Bitfield(&[0b1]);
        if let Err(e) = server.write_all(&bitfield.to_bytes().unwrap()).await {
            log::error!("Server write bitfield error: {e}");
            return;
        }
        let mut len_buf = [0u8; 4];
        if let Err(e) = server.read_exact(&mut len_buf).await {
            log::error!("Server read interested len error: {e}");
            return;
        }
        if let Err(e) = server.read_exact(&mut [0u8; 1]).await {
            log::error!("Server read interested error: {e}");
            return;
        } // Interested
        let unchoke = Message::Unchoke;
        if let Err(e) = server.write_all(&unchoke.to_bytes().unwrap()).await {
            log::error!("Server write unchoke error: {e}");
            return;
        }
        if let Err(e) = server.read_exact(&mut len_buf).await {
            log::error!("Server read request len error: {e}");
            return;
        }
        let mut req_buf = [0u8; 13];
        if let Err(e) = server.read_exact(&mut req_buf).await {
            log::error!("Server read request error: {e}");
            return;
        }
        let piece_data = vec![42u8; 256];
        let piece_msg = Message::Piece {
            index: 0,
            begin: 0,
            block: &piece_data,
        };
        if let Err(e) = server.write_all(&piece_msg.to_bytes().unwrap()).await {
            log::error!("Server write piece error: {e}");
            return;
        }
        if let Err(e) = server.read_exact(&mut len_buf).await {
            log::error!("Server read second request len error: {e}");
            return;
        }
        if let Err(e) = server.read_exact(&mut req_buf).await {
            log::error!("Server read second request error: {e}");
            return;
        }
        let invalid_msg = Message::Piece {
            index: 0,
            begin: 512,
            block: &piece_data,
        };
        if let Err(e) = server.write_all(&invalid_msg.to_bytes().unwrap()).await {
            log::error!("Server write invalid piece error: {e}");
        }
    });

    crate::handshake::handshake(&mut client, &torrent.info_hash)
        .await
        .unwrap();

    let (reader, writer) = tokio::io::split(client);
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer_half = writer;
    let mut buffer = vec![0u8; torrent.piece_length];

    Message::Bitfield(&[0u8; 1])
        .send(&mut writer_half)
        .await
        .unwrap();
    let message = crate::retrieve_message(&mut reader, &mut buffer, Some(&torrent))
        .await
        .unwrap();
    assert!(matches!(message, Message::Bitfield(_)));
    Message::Interested.send(&mut writer_half).await.unwrap();
    let message = crate::retrieve_message(&mut reader, &mut buffer, Some(&torrent))
        .await
        .unwrap();
    assert!(matches!(message, Message::Unchoke));

    let mut piece = Piece::new(torrent.piece_length, 256);
    let (begin, length) = piece.next_request().unwrap();
    Message::make_request(0, begin, length)
        .unwrap()
        .send(&mut writer_half)
        .await
        .unwrap();
    let message = timeout(
        Duration::from_secs(5),
        crate::retrieve_message(&mut reader, &mut buffer, Some(&torrent)),
    )
    .await
    .unwrap()
    .unwrap();
    if let Message::Piece {
        index: _,
        begin,
        block,
    } = message
    {
        assert!(piece.write_block(begin as usize, block).is_ok());
    } else {
        panic!("Expected Piece message");
    }
    let (begin, length) = piece.next_request().unwrap();
    Message::make_request(0, begin, length)
        .unwrap()
        .send(&mut writer_half)
        .await
        .unwrap();
    let message = timeout(
        Duration::from_secs(5),
        crate::retrieve_message(&mut reader, &mut buffer, Some(&torrent)),
    )
    .await
    .unwrap();
    assert!(matches!(
        message,
        Err(TorrentError::MessageParse(
            MessageParseError::PieceBlockOutOfBounds {
                index: 0,
                begin: 512,
                block_len: 256,
                piece_len: 512
            }
        ))
    ));
}

#[tokio::test]
async fn test_main_multi_peer() {
    let mut server = mockito::Server::new_async().await;
    let block_data = vec![42u8; 512]; // Match piece_length
    let expected_hash = Sha1::digest(&block_data);
    let torrent = Arc::new(TorrentInfo {
        info_hash: [0u8; 20],
        piece_length: 512,
        total_length: 512,
        piece_hashes: vec![expected_hash.into()],
        trackers: vec![server.url()],
        filename: "test_multi.txt".to_string(),
        peers: vec![
            "127.0.0.1:6881".parse().unwrap(),
            "127.0.0.1:6882".parse().unwrap(),
            "127.0.0.1:6883".parse().unwrap(),
        ],
    });

    let _m = server
        .mock("GET", Matcher::Regex(r".*info_hash=.*".to_string()))
        .with_status(200)
        .with_body(crate::bencode::encode(&Value::Dict({
            let mut map = HashMap::new();
            map.insert(
                Key(b"peers".to_vec()),
                Value::ByteString(vec![
                    127, 0, 0, 1, 26, 225, // 127.0.0.1:6881
                    127, 0, 0, 1, 26, 226, // 127.0.0.1:6882
                    127, 0, 0, 1, 26, 227, // 127.0.0.1:6883
                ]),
            );
            map
        })))
        .create_async()
        .await;

    for port in [6881, 6882, 6883] {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let torrent = Arc::clone(&torrent);
        let block_data = block_data.clone();
        tokio::spawn(async move {
            match timeout(Duration::from_secs(10), async {
                let (stream, _) = listener.accept().await?;
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut buf = [0u8; 68];
                log::debug!("Server waiting for handshake on port {port}");
                if reader.read_exact(&mut buf).await.is_err() {
                    log::error!("Server failed to read handshake on port {port}");
                    return Ok::<(),TorrentError>(());
                }
                let handshake = Handshake::new(&torrent.info_hash, &[0xFF; 20]);
                writer.write_all(&handshake.0).await?;
                log::debug!("Server sent handshake on port {port}");
                let bitfield = Message::Bitfield(&[0b1000_0000]);
                writer.write_all(&bitfield.to_bytes().unwrap()).await?;
                log::debug!("Server sent Bitfield on port {port}");
                // Loop to handle messages until Interested
                let mut interested_received = false;
                let mut buf = vec![0u8; crate::MAX_MESSAGE_SIZE as usize];
                while !interested_received {

                    let message = crate::peer::retrieve_message(&mut reader, &mut buf, Some(&torrent)).await?;
                    log::debug!("Server received message {message:?} on port {port}");
                    match message {
                        Message::KeepAlive => {
                            Message::KeepAlive.send(&mut writer).await?;
                            log::debug!("Server sent KeepAlive on port {port}");
                        }
                        Message::Bitfield(_) => {
                            log::debug!("Server received Bitfield on port {port}");
                        }
                        Message::Interested => {
                            log::debug!("Server received Interested on port {port}");
                            interested_received = true;
                        }
                        m => log::warn!("Unexpected message {m:?} on port {port}"),
                    }
                }
                 Message::Unchoke.send(&mut writer).await?;
                log::debug!("Server sent Unchoke on port {port}");
                // Read and validate Request message
                let request = crate::peer::retrieve_message(&mut reader, &mut buf, Some(&torrent)).await?;
                    if let Message::Request {..}  = request {
                        log::debug!("Server received valid Request (index=0, begin=0, length=512) on port {port}");
                    } else {
                        log::error!("Expected request (index=0, begin=0, length=512), got {request:?} on port {port}");
                    return Ok(());
                }
                 Message::Piece {
                    index: 0,
                    begin: 0,
                    block: &block_data,
                }.send(&mut writer).await?;
                log::debug!("Server sent Piece {{ index: 0, begin: 0, block: 512 bytes }} on port {port}");
                // Keep mock peer alive
                let mut len_buf = [0; 4];
                loop {
                    if reader.read_exact(&mut len_buf).await.is_err() {
                        log::debug!("Server on port {port} finished or client closed connection");
                        return Ok(());
                    }
                    let len = u32::from_be_bytes(len_buf);
                    if len == 0 {
                        let keep_alive = Message::KeepAlive;
                        writer.write_all(&keep_alive.to_bytes().unwrap()).await?;
                        log::debug!("Server sent KeepAlive on port {port}");
                    } else {
                        let mut discard_buf = vec![0u8; len as usize];
                        if reader.read_exact(&mut discard_buf).await.is_err() {
                            log::debug!("Server on port {port} failed to read unexpected message");
                            return Ok(());
                        }
                        log::warn!("Unexpected message length {len} with data {discard_buf:?} on port {port}");
                    }
                }
            })
            .await
            {
                Ok(Ok(())) => log::info!("Server task on port {port} completed"),
                Ok(Err(e)) => log::error!("Server error on port {port}: {e}"),
                Err(_) => log::error!("Server timeout on port {port}"),
            }
        });
    }

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path().to_str().unwrap().to_string();
    std::fs::write(&path, b"").unwrap(); // Mock .torrent file
    let args = vec!["magnetronic".to_string(), path];
    tokio::time::sleep(Duration::from_secs(2)).await; // Increased delay
    crate::run(args, Some(torrent.as_ref().clone()))
        .await
        .unwrap();

    let data = tokio::fs::read(&torrent.filename).await.unwrap();
    assert_eq!(data.len(), torrent.total_length as usize);
    assert_eq!(&data[..512], &vec![42u8; 512]);
}

#[tokio::test]
async fn test_main_two_peers_one_piece() -> Result<(), TorrentError> {
    env_logger::init();
    let mut server = mockito::Server::new_async().await;
    let tracker_url = server.url();
    let _m = server
        .mock("GET", "/")
        .with_status(200)
        .with_body(crate::bencode::encode(&{
            let mut m = HashMap::new();
            m.insert(
                Key(b"peers".to_vec()),
                Value::ByteString(vec![
                    127, 0, 0, 1, 26, 228, // 127.0.0.1:6884
                    127, 0, 0, 1, 26, 229, // 127.0.0.1:6885
                ]),
            );
            Value::Dict(m)
        }))
        .create_async()
        .await;

    let torrent = TorrentInfo {
        info_hash: [0u8; 20],
        piece_length: 32 * 1024,
        total_length: 32 * 1024,
        piece_hashes: vec![sha1::Sha1::digest(vec![42u8; 512]).into()],
        trackers: vec![tracker_url],
        filename: String::from("test_multi.txt"),
        peers: vec![
            "127.0.0.1:6884".parse().unwrap(),
            "127.0.0.1:6885".parse().unwrap(),
        ],
    };

    let torrent_ref = Arc::new(torrent.clone());
    let torrent_file = tempfile::NamedTempFile::new()?;
    let args = vec![
        "magnetronic".to_string(),
        torrent_file.path().to_string_lossy().into(),
    ];
    let mut join_set: tokio::task::JoinSet<Result<(), TorrentError>> = tokio::task::JoinSet::new();

    // Spawn two mock peers
    for (port, begin, length) in [(6884, 0, 16 * 1024), (6885, 16 * 1024, 16 * 1024)] {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
        let torrent_ref = Arc::clone(&torrent_ref);
        join_set.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.split();
            let mut reader = BufReader::new(reader);

            // Handshake
            let mut handshake_buf = [0u8; 68];
            reader.read_exact(&mut handshake_buf).await.unwrap();
            let handshake = Handshake::new(&torrent_ref.info_hash, &[0xFF; 20]);
            writer.write_all(&handshake.0).await.unwrap();
            log::debug!("Server sent handshake on port {}", port);

            // Send Bitfield
            let bitfield = Message::Bitfield(&[0x80]);
            bitfield.send(&mut writer).await.unwrap();
            log::debug!("Server sent Bitfield on port {}", port);

            // Handle messages until Interested
            let mut buffer = vec![0u8; torrent_ref.piece_length];
            let mut interested_received = false;
            while !interested_received {
                let message = crate::peer::retrieve_message(&mut reader, &mut buffer, Some(&torrent_ref))
                    .await
                    .unwrap();
                log::debug!("Server received message {message:?} on port {}", port);
                match message {
                    Message::KeepAlive => {
                        Message::KeepAlive.send(&mut writer).await.unwrap();
                        log::debug!("Server sent KeepAlive on port {}", port);
                    }
                    Message::Bitfield(_) => {
                        log::debug!("Server received Bitfield on port {}", port);
                    }
                    Message::Interested => {
                        log::debug!("Server received Interested on port {}", port);
                        interested_received = true;
                    }
                    m => log::warn!("Unexpected message {m:?} on port {}", port),
                }
            }

            // Send Unchoke
            Message::Unchoke.send(&mut writer).await.unwrap();
            log::debug!("Server sent Unchoke on port {}", port);

            // Handle Request
            let message = timeout(Duration::from_secs(2), crate::peer::retrieve_message(&mut reader, &mut buffer, Some(&torrent_ref)))
                .await
                .map_err(|_| {
                    log::error!("Timeout waiting for Request on port {}", port);
                    TorrentError::Timeout
                })
                .unwrap()?;
            log::debug!("Server received message {message:?} on port {}", port);
            if let Message::Request { index, begin: req_begin, length: req_length } = message {
                if index == 0 && req_begin == begin && req_length == length {
                    let block_data = vec![42u8; length as usize];
                    Message::Piece {
                        index: 0,
                        begin,
                        block: &block_data,
                    }
                    .send(&mut writer)
                    .await
                    .unwrap();
                    log::debug!("Server sent Piece {{ index: 0, begin: {}, block: {} bytes }} on port {}", begin, length, port);
                } else {
                    log::error!("Expected request (index=0, begin={}, length={}), got {index}, {req_begin}, {req_length} on port {}", begin, length, port);
                    return Ok(());
                }
            } else {
                log::error!("Expected Request, got {message:?} on port {}", port);
                return Ok(());
            }

            // Keep connection alive
            loop {
                let message = crate::peer::retrieve_message(&mut reader, &mut buffer, Some(&torrent_ref))
                    .await
                    .unwrap();
                log::debug!("Server received message {message:?} on port {}", port);
                if let Message::KeepAlive = message {
                    Message::KeepAlive.send(&mut writer).await.unwrap();
                    log::debug!("Server sent KeepAlive on port {}", port);
                }
            }
        });
    }

    tokio::time::sleep(Duration::from_secs(2)).await;
    crate::run(args, Some(torrent)).await.unwrap();

    // Check file
    let contents = tokio::fs::read("test_multi.txt").await.unwrap();
    assert_eq!(contents.len(), 32 * 1024);
    assert!(contents.iter().all(|&byte| byte == 42));
    Ok(())
}
