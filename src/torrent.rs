use crate::bencode;
use sha1::{Digest, Sha1};
use std::net::SocketAddr;

#[derive(Debug)]
pub struct TorrentInfo {
    pub info_hash: [u8; 20],
    pub piece_length: usize,
    pub total_length: usize,
    pub piece_hashes: Vec<[u8; 20]>,
    pub trackers: Vec<String>,
    pub filename: String,
    pub peers: Vec<SocketAddr>,
}

pub fn parse_torrent_file(torrent_info_dict: &bencode::Value) -> Option<TorrentInfo> {
    // read & parse .torrent file bencode
    // fill in info_hash, piece_length, etc.

    let mut trackers = vec![];
    if let Some(bencode::Value::List(tiers)) = torrent_info_dict.get(b"announce-list") {
        for tier in tiers {
            if let bencode::Value::List(urls) = tier {
                for url in urls {
                    if let Some(s) = url.as_str() {
                        trackers.push(s.to_string());
                    }
                }
            }
        }
    }
    if trackers.is_empty() {
        let tracker_url = torrent_info_dict.get(b"announce")?.as_str()?;
        trackers.push(tracker_url.to_string());
    }

    let info = torrent_info_dict.get(b"info")?;
    let total_length = info.get(b"length")?.as_int()? as usize;
    let filename = info.get(b"name")?.as_str()?.to_string();

    let encoded_info = bencode::encode(info);
    let info_hash = Sha1::digest(encoded_info).into();

    let piece_length = info.get(b"piece length")?.as_int()? as usize;

    let piece_hashes = match info.get(b"pieces")? {
        bencode::Value::ByteString(b) => b
            .chunks_exact(20)
            .map(|chunk| {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(chunk);
                arr
            })
            .collect(),
        _ => unreachable!("pieces field is not a ByteString"),
    };

    Some(TorrentInfo {
        info_hash,
        piece_length,
        total_length,
        piece_hashes,
        trackers,
        filename,
        peers: vec![],
    })
}
