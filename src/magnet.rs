use crate::bencode;
use crate::handshake;
use crate::peer;
use crate::peers;
use crate::retrieve_message;
use crate::torrent::TorrentInfo;

use percent_encoding::percent_decode_str;
use tokio::io::BufReader;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct MagnetInfo<'i> {
    pub info_hash: [u8; 20],
    pub trackers: Vec<String>,
    name: Option<&'i str>,
}

fn parse_magnet_link(uri: &str) -> Option<MagnetInfo> {
    let query_start = uri.find('?')?;
    let query = &uri[query_start + 1..];

    let mut info_hash = None;
    let mut name = None;
    let mut trackers = Vec::new();
    let pairs = query.split('&').filter_map(|pair| pair.split_once('='));
    for (key, value) in pairs {
        match key {
            "xt" if value.starts_with("urn:btih:") => {
                let hash_str = &value[9..];
                assert_eq!(hash_str.len(), 40, "Found base32 hash");
                let mut buf = [0u8; 20];
                hex::decode_to_slice(hash_str, &mut buf).ok()?;
                info_hash = Some(buf);
            }
            "dn" => name = Some(value),
            "tr" => trackers.push(percent_decode_str(value).decode_utf8().unwrap().to_string()),
            _ => {}
        }
    }
    Some(MagnetInfo {
        info_hash: info_hash?,
        trackers,
        name,
    })
}

pub async fn fetch_torrent_info_from_magnet(
    magnet: &str,
) -> std::io::Result<(TorrentInfo, (BufReader<OwnedReadHalf>, OwnedWriteHalf))> {
    let magnet = parse_magnet_link(magnet).expect("Failed to parse magnet");
    log::debug!("MagnetInfo: {magnet:?}");
    log::info!("Fetching metadata for {:?}", magnet.name);

    let peers = peers::request_peers(&magnet).await;
    log::debug!("{peers:?}");

    let peer = peers[0];
    log::info!("Connecting to peer {peer}");
    let mut stream = TcpStream::connect(peer).await?;
    let supports_extensions = handshake::handshake(&mut stream, &magnet.info_hash).await?;
    assert!(
        supports_extensions,
        "Magnet tracker doesnt support extensions"
    );

    // let mut reader = BufReader::new(stream.try_clone()?);
    let (reader_half, mut writer_half) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut msg_buf = vec![0u8; 64 * 1024];
    let message = retrieve_message(&mut reader, &mut msg_buf).await?;
    log::debug!("Recieved: {message:?}");

    assert!(
        supports_extensions,
        "Tracker for magnet doesnt support extensions"
    );

    let extended = peer::Message::Extended {
        id: 0,
        payload: b"d1:md11:ut_metadatai16eee",
    };

    log::debug!("extended: {extended:?}");
    extended.send(&mut writer_half).await?;

    let reply = retrieve_message(&mut reader, &mut msg_buf).await?;
    assert!(matches!(reply, peer::Message::Extended { .. }));
    log::debug!("{reply:?}");

    let ext_bytes = reply.to_bytes();
    let (dict, _) = bencode::decode(&ext_bytes[6..]);
    log::debug!("{dict}");

    let metadata_id = dict.get(b"m").unwrap().get(b"ut_metadata").unwrap();
    log::debug!("metadata_id: {metadata_id}");

    let req = &peer::Message::Extended {
        id: metadata_id.as_int().unwrap() as u8,
        payload: b"d8:msg_typei0e5:piecei0ee",
    };
    log::debug!("{req:?}");
    req.send(&mut writer_half).await?;

    let msg = retrieve_message(&mut reader, &mut msg_buf).await?;
    assert!(matches!(msg, peer::Message::Extended { .. }));
    log::debug!("{msg:?}");

    let msg_bytes = msg.to_bytes();
    let (data, end) = bencode::decode(&msg_bytes[6..]);
    log::debug!("data: {data}");
    let metadata_piece = &msg_bytes[6 + end..];
    log::debug!("rest: {metadata_piece:?} {}", metadata_piece.len());
    let (metadata, _) = bencode::decode(metadata_piece);

    Ok((
        TorrentInfo {
            trackers: magnet.trackers,
            info_hash: magnet.info_hash,
            filename: metadata.get(b"name").unwrap().as_str().unwrap().to_string(),
            piece_length: metadata.get(b"piece length").unwrap().as_int().unwrap() as usize,
            total_length: metadata.get(b"length").unwrap().as_int().unwrap() as usize,
            piece_hashes: match metadata.get(b"pieces").unwrap() {
                bencode::Value::ByteString(b) => b
                    .chunks_exact(20)
                    .map(|chunk| {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(chunk);
                        arr
                    })
                    .collect(),
                _ => unreachable!("pieces field is not a ByteString"),
            },
            peers,
        },
        (reader, writer_half),
    ))
}
