use crate::{bencode, error::TorrentError};
use sha1::{Digest, Sha1};
use std::net::SocketAddr;

#[derive(Debug)]
pub struct TorrentInfo {
    pub info_hash: [u8; 20],
    pub piece_length: usize,
    pub total_length: u64,
    pub piece_hashes: Vec<[u8; 20]>,
    pub trackers: Vec<String>,
    pub filename: String,
    pub peers: Vec<SocketAddr>,
}

pub fn parse_torrent_file(torrent_info_dict: &bencode::Value) -> Result<TorrentInfo, TorrentError> {
    // read & parse .torrent file bencode
    // fill in info_hash, piece_length, etc.

    let mut trackers = vec![];
    if let Some(bencode::Value::List(tiers)) = torrent_info_dict.get(b"announce-list")? {
        for tier in tiers {
            if let bencode::Value::List(urls) = tier {
                for url in urls {
                    if let Ok(s) = url.as_str() {
                        trackers.push(s.to_string());
                    }
                }
            }
        }
    }
    if trackers.is_empty() {
        match torrent_info_dict.get(b"announce")? {
            Some(bencode::Value::ByteString(announce)) => {
                let s = std::str::from_utf8(announce).map_err(bencode::Error::Utf8)?;
                trackers.push(s.to_string());
                Ok(())
            }
            Some(v) => Err(bencode::Error::NotByteString(v.clone()).into()),
            None => Err(TorrentError::TorrentParse("No trackers found".into())),
        }
    } else {
        Ok(())
    }?;

    let info = torrent_info_dict
        .get(b"info")?
        .ok_or(TorrentError::TorrentParse("Missing 'info' field".into()))?;

    let total_length = info
        .get(b"length")?
        .ok_or(TorrentError::TorrentParse("Missing 'length' field".into()))?
        .as_int()?
        .try_into()
        .map_err(|_| TorrentError::TorrentParse("'length' field must be non-negative".into()))?;

    let filename = info
        .get(b"name")?
        .ok_or(TorrentError::TorrentParse("missing 'name' field".into()))?
        .as_str()?
        .to_string();

    let piece_length = info
        .get(b"piece length")?
        .ok_or(TorrentError::TorrentParse(
            "Missing 'piece length' field".into(),
        ))?
        .as_int()?
        .try_into()
        .map_err(|_| {
            TorrentError::TorrentParse(format!(
                "'piece length' field must be non-negative and fit inside {} bits",
                usize::BITS
            ))
        })?;

    let piece_hashes = match info.get(b"pieces")? {
        Some(bencode::Value::ByteString(b)) => Ok(b
            .chunks_exact(20)
            .map(|chunk| {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(chunk);
                arr
            })
            .collect()),
        value => Err(TorrentError::TorrentParse(format!(
            "Invalid pieces field: {value:?}",
        ))),
    }?;

    let encoded_info = bencode::encode(info);
    let info_hash = Sha1::digest(encoded_info).into();

    Ok(TorrentInfo {
        info_hash,
        piece_length,
        total_length,
        piece_hashes,
        trackers,
        filename,
        peers: vec![],
    })
}
