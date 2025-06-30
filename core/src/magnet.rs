use std::num::TryFromIntError;

use crate::bencode;
use crate::error;
use crate::handshake;
use crate::peer;
use crate::peers;
use crate::retrieve_message;
use crate::torrent::TorrentInfo;

use data_encoding::BASE32;
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

#[derive(Debug, thiserror::Error)]
pub enum MagnetParseError {
    #[error("Missing info hash")]
    MissingInfoHash,

    #[error("Invalid hex info hash: {0}")]
    InvalidHex(String),

    #[error("Invalid base32 info hash: {0}")]
    InvalidBase32(String),

    #[error("No valid trackers found in magnet link")]
    NoValidTrackers,

    #[error("Malformed magnet URI")]
    MalformedUri,

    #[error("Failed to case integer: {0}")]
    CastError(#[from] TryFromIntError),

    #[error("Invalid metadata")]
    InvalidMeta(String),
}

fn parse_magnet_link(uri: &str) -> Result<MagnetInfo<'_>, MagnetParseError> {
    let query_start = uri.find('?').ok_or(MagnetParseError::MalformedUri)?;
    let query = &uri[query_start + 1..];

    let mut info_hash = None;
    let mut name = None;
    let mut trackers = Vec::new();
    let pairs = query.split('&').filter_map(|pair| pair.split_once('='));
    for (key, value) in pairs {
        match key {
            "xt" if value.starts_with("urn:btih:") => {
                let hash_str = &value[9..];
                let mut buf = [0u8; 20];
                if hash_str.len() == 40 {
                    if hex::decode_to_slice(hash_str, &mut buf).is_err() {
                        log::warn!("Invalid hex info_hash '{hash_str}'");
                        return Err(MagnetParseError::InvalidHex(hash_str.into()));
                    }
                } else {
                    let hash_upper = hash_str.to_ascii_uppercase();
                    if BASE32.decode_mut(hash_upper.as_bytes(), &mut buf).is_err() {
                        log::warn!("Invalid base32 info_hash '{hash_str}'");
                        return Err(MagnetParseError::InvalidBase32(hash_str.into()));
                    }
                }
                info_hash = Some(buf);
            }
            "dn" => name = Some(value),
            "tr" => match percent_decode_str(value).decode_utf8() {
                Ok(decoded) => trackers.push(decoded.into()),
                Err(e) => log::warn!("skipping invalid tracker '{value}': {e}"),
            },
            _ => log::debug!("Ignoring magnet param: {key}={value}"),
        }
    }
    if trackers.is_empty() {
        Err(MagnetParseError::NoValidTrackers)
    } else {
        Ok(MagnetInfo {
            info_hash: info_hash.ok_or(MagnetParseError::MissingInfoHash)?,
            trackers,
            name,
        })
    }
}

pub async fn fetch_torrent_info_from_magnet(
    magnet: &str,
) -> Result<(TorrentInfo, (BufReader<OwnedReadHalf>, OwnedWriteHalf)), error::TorrentError> {
    let magnet = parse_magnet_link(magnet).expect("Failed to parse magnet");
    log::debug!("MagnetInfo: {magnet:?}");
    log::info!("Fetching metadata for {:?}", magnet.name);

    let peers = peers::request_peers(&magnet).await?;
    log::debug!("{peers:?}");

    let peer = peers.first().ok_or(error::TorrentError::NoPeers)?;
    log::info!("Connecting to peer {peer}");

    let mut stream = TcpStream::connect(peer).await?;
    let supports_extensions = handshake::handshake(&mut stream, &magnet.info_hash).await?;
    if !supports_extensions {
        log::warn!("Peer {peer} does not support extensions");
        return Err(error::TorrentError::HandshakeMismatch);
    }

    // let mut reader = BufReader::new(stream.try_clone()?);
    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut msg_buf = vec![0u8; 64 * 1024];
    let message = retrieve_message(&mut reader, &mut msg_buf, None).await?;
    log::debug!("Recieved: {message:?}");

    let extended = peer::Message::Extended {
        id: 0,
        payload: b"d1:md11:ut_metadatai16eee",
    };
    log::debug!("extended: {extended:?}");
    extended.send(&mut writer).await?;

    let reply = retrieve_message(&mut reader, &mut msg_buf, None).await?;
    if !matches!(reply, peer::Message::Extended { .. }) {
        return Err(error::TorrentError::HandshakeMismatch);
    }
    log::debug!("{reply:?}");

    let ext_bytes = reply.to_bytes()?;
    let (dict, _) = bencode::decode(&ext_bytes[6..])?;
    log::debug!("{dict}");

    let metadata_id = dict
        .get(b"m")?
        .ok_or(MagnetParseError::InvalidMeta("m".into()))?
        .get(b"ut_metadata")?
        .ok_or(MagnetParseError::InvalidMeta("m > ut_metadata".into()))?
        .as_int()?;
    log::debug!("metadata_id: {metadata_id}");

    let req = &peer::Message::Extended {
        id: u8::try_from(metadata_id).map_err(MagnetParseError::from)?,
        payload: b"d8:msg_typei0e5:piecei0ee",
    };
    log::debug!("{req:?}");
    req.send(&mut writer).await?;

    let msg = retrieve_message(&mut reader, &mut msg_buf, None).await?;
    if !matches!(msg, peer::Message::Extended { .. }) {
        return Err(error::TorrentError::HandshakeMismatch);
    }
    log::debug!("{msg:?}");

    let msg_bytes = msg.to_bytes()?;
    let (data, end) = bencode::decode(&msg_bytes[6..])?;
    log::debug!("data: {data}");
    let metadata_piece = &msg_bytes[6 + end..];
    log::debug!("rest: {metadata_piece:?} {}", metadata_piece.len());
    let (metadata, _) = bencode::decode(metadata_piece)?;

    let filename = metadata
        .get(b"name")?
        .ok_or(MagnetParseError::InvalidMeta("name".into()))?
        .as_str()?
        .to_string();

    let piece_length = usize::try_from(
        metadata
            .get(b"piece length")?
            .ok_or(MagnetParseError::InvalidMeta("piece length".into()))?
            .as_int()?,
    )
    .map_err(MagnetParseError::CastError)?;

    let total_length = u64::try_from(
        metadata
            .get(b"length")?
            .ok_or(MagnetParseError::InvalidMeta("length".into()))?
            .as_int()?,
    )
    .map_err(MagnetParseError::CastError)?;

    Ok((
        TorrentInfo {
            trackers: magnet.trackers,
            info_hash: magnet.info_hash,
            filename,
            piece_length,
            total_length,
            piece_hashes: match metadata.get(b"pieces")? {
                Some(bencode::Value::ByteString(b)) => b
                    .chunks_exact(20)
                    .map(|chunk| {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(chunk);
                        arr
                    })
                    .collect(),
                _ => unreachable!("Pieces field missing"),
            },
            peers,
        },
        (reader, writer),
    ))
}
