#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
mod handshake;
use handshake::Handshake;

mod bencode;

mod peer_message;
use peer_message::PeerMessage;

use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};
use sha1::{Digest, Sha1};
use std::fs::OpenOptions;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};

struct Piece {
    data: Vec<u8>,
    blocks_downloaded: Vec<bool>,
    block_size: usize,
    total_size: usize,
}

impl Piece {
    fn new(total_size: usize, block_size: usize) -> Self {
        let num_blocks = total_size.div_ceil(block_size);
        Self {
            data: vec![0; total_size],
            blocks_downloaded: vec![false; num_blocks],
            block_size,
            total_size,
        }
    }

    fn write_block(&mut self, begin: usize, block: &[u8]) {
        let end = begin + block.len();
        assert!(end <= self.total_size, "Block write out of bounds");

        self.data[begin..end].copy_from_slice(block);

        let block_index = begin / self.block_size;
        self.blocks_downloaded[block_index] = true;
    }

    fn is_complete(&self) -> bool {
        self.blocks_downloaded.iter().all(|&b| b)
    }

    fn next_request(&self) -> Option<(usize, usize)> {
        for (i, &downloaded) in self.blocks_downloaded.iter().enumerate() {
            if !downloaded {
                let begin = i * self.block_size;
                let remaining = self.total_size - begin;
                let length = remaining.min(self.block_size);
                return Some((begin, length));
            }
        }
        None
    }
}

#[derive(Debug)]
struct TorrentInfo {
    info_hash: [u8; 20],
    piece_length: usize,
    total_length: usize,
    piece_hashes: Vec<[u8; 20]>,
    trackers: Vec<String>,
    filename: String,
    peers: Vec<SocketAddr>,
}

fn parse_torrent_file(torrent_info_dict: &bencode::Value) -> Option<TorrentInfo> {
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

#[derive(Debug)]
struct MagnetInfo<'i> {
    info_hash: [u8; 20],
    trackers: Vec<String>,
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

trait NeedsPeers<'i> {
    fn get_tracker(&'i self) -> &'i str;
    fn get_hash(&'i self) -> &'i [u8];
    fn get_left(&'i self) -> &'i usize;
}

impl<'t> NeedsPeers<'t> for TorrentInfo {
    fn get_tracker(&'t self) -> &'t str {
        &self.trackers[0]
    }
    fn get_hash(&'t self) -> &'t [u8] {
        &self.info_hash
    }

    fn get_left(&'t self) -> &'t usize {
        &self.total_length
    }
}

impl<'m> NeedsPeers<'m> for MagnetInfo<'_> {
    fn get_tracker(&'m self) -> &'m str {
        &self.trackers[0]
    }
    fn get_hash(&'m self) -> &'m [u8] {
        &self.info_hash
    }
    fn get_left(&'m self) -> &'m usize {
        &1
    }
}

async fn request_peers<'i, I>(info: &'i I) -> Vec<SocketAddr>
where
    I: NeedsPeers<'i>,
{
    // Build tracker URL with params & send request
    // Parse response for peers (compact format)

    let info_hash_encoded = percent_encode(info.get_hash(), NON_ALPHANUMERIC).to_string();
    let peer_id_encoded = percent_encode(&PEER_ID, NON_ALPHANUMERIC).to_string();

    let url = format!(
        "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left={}&compact=1&event=started",
        info.get_tracker(),
        info_hash_encoded,
        peer_id_encoded,
        info.get_left()
    );
    log::debug!("requesting: {url}");

    let res = reqwest::get(&url).await.unwrap().bytes().await.unwrap();
    log::debug!("{res:?}");

    let (resp, _) = bencode::decode(&res);
    log::debug!("{resp:?}");

    match resp.get(b"peers").expect("No peers recieved!") {
        bencode::Value::ByteString(v) => v
            .chunks_exact(6)
            .map(|chunk| {
                SocketAddr::from((
                    [chunk[0], chunk[1], chunk[2], chunk[3]],
                    u16::from_be_bytes([chunk[4], chunk[5]]),
                ))
            })
            .collect(),
        _ => unreachable!("peers not a ByteString!"),
    }
}

fn handshake(stream: &mut TcpStream, info_hash: &[u8]) -> std::io::Result<bool> {
    // Send handshake, receive & validate handshake response
    let handshake = Handshake::new(info_hash, &PEER_ID);
    log::debug!("Sending Handshake: {handshake:?}");
    stream.write_all(handshake.as_ref())?;

    let mut buf = [0u8; 68];
    stream.read_exact(&mut buf)?;
    let handshake = Handshake::from_bytes(buf);

    log::debug!("Recieved Handshake: {handshake:?}");
    assert!(handshake.validate(info_hash));
    Ok(handshake.supports_extensions())
}

fn retrieve_message<'a>(
    reader: &'a mut BufReader<TcpStream>,
    buffer: &'a mut [u8],
) -> std::io::Result<PeerMessage<'a>> {
    let mut len_buf = [0; 4];
    reader.read_exact(&mut len_buf)?;
    let length = u32::from_be_bytes(len_buf);

    Ok(if length == 0 {
        PeerMessage::KeepAlive
    } else {
        let slice = &mut buffer[..length as usize];
        reader.read_exact(slice)?;
        slice.into()
    })
}

async fn fetch_torrent_info_from_magnet(magnet: &str) -> std::io::Result<(TorrentInfo, TcpStream)> {
    let magnet = parse_magnet_link(magnet).expect("Failed to parse magnet");
    log::debug!("MagnetInfo: {magnet:?}");
    log::info!("Fetching metadata for {:?}", magnet.name);

    let peers = request_peers(&magnet).await;
    log::debug!("{peers:?}");

    let peer = peers[0];
    log::info!("Connecting to peer {peer}");
    let mut stream = TcpStream::connect(peer)?;
    let supports_extensions = handshake(&mut stream, &magnet.info_hash)?;
    assert!(
        supports_extensions,
        "Magnet tracker doesnt support extensions"
    );

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut msg_buf = vec![0u8; 64 * 1024];
    let message = retrieve_message(&mut reader, &mut msg_buf)?;
    log::debug!("Recieved: {message:?}");

    assert!(
        supports_extensions,
        "Tracker for magnet doesnt support extensions"
    );

    let extended = PeerMessage::Extended {
        id: 0,
        payload: b"d1:md11:ut_metadatai16eee",
    };

    log::debug!("extended: {extended:?}");
    extended.send(&mut stream)?;

    let reply = retrieve_message(&mut reader, &mut msg_buf)?;
    assert!(matches!(reply, PeerMessage::Extended { .. }));
    log::debug!("{reply:?}");

    let ext_bytes = reply.to_bytes();
    let (dict, _) = bencode::decode(&ext_bytes[6..]);
    log::debug!("{dict}");

    let metadata_id = dict.get(b"m").unwrap().get(b"ut_metadata").unwrap();
    log::debug!("metadata_id: {metadata_id}");

    let req = &PeerMessage::Extended {
        id: metadata_id.as_int().unwrap() as u8,
        payload: b"d8:msg_typei0e5:piecei0ee",
    };
    log::debug!("{req:?}");
    req.send(&mut stream)?;

    let msg = retrieve_message(&mut reader, &mut msg_buf)?;
    assert!(matches!(msg, PeerMessage::Extended { .. }));
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
        stream,
    ))
}

const PEER_ID: [u8; 20] = *b"-TR2940-6wfG2wk6wWLc";
const BLOCK_SIZE: usize = 16 * 1024;

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_default_env()
        .format_target(false)
        .format_file(true)
        .format_timestamp(None)
        .init();

    let args: Vec<String> = std::env::args().collect();
    assert_eq!(2, args.len(), "No args given!");

    let (torrent, mut stream) = if args[1].starts_with("magnet:?") {
        let (t, mut s) = fetch_torrent_info_from_magnet(&args[1]).await?;
        PeerMessage::Interested.send(&mut s)?;
        (t, s)
    } else {
        let bytes = std::fs::read(&args[1]).unwrap();

        let (torrent_info_dict, _) = bencode::decode(&bytes);
        log::debug!("{torrent_info_dict}");

        let mut t =
            parse_torrent_file(&torrent_info_dict).expect("Failed to get TorrentInfo from file");
        t.peers = request_peers(&t).await;

        let peer = t.peers[0];
        log::info!("Connecting to {peer}");
        let mut stream = TcpStream::connect(peer)?;

        handshake(&mut stream, &t.info_hash)?;

        (t, stream)
    };
    log::debug!("TorrentInfo: {torrent:?}");

    let mut reader = BufReader::new(stream.try_clone()?);

    let bitfield_len = torrent.piece_hashes.len().div_ceil(8);
    let empty_bitfield = vec![0u8; bitfield_len];
    PeerMessage::Bitfield(&empty_bitfield).send(&mut stream)?;

    let mut availability = vec![0u8; torrent.piece_hashes.len()];
    log::info!("Waiting for Unchoke");

    let mut buffer = vec![0u8; torrent.piece_length];
    loop {
        let message = retrieve_message(&mut reader, &mut buffer)?;
        log::debug!("Recieved: {message:?}");

        let reply = match message {
            PeerMessage::Bitfield(field) => {
                for (i, byte) in field.iter().enumerate() {
                    for bit_pos in 0..8 {
                        let piece_index = i * 8 + bit_pos;
                        if byte & (0x80 >> bit_pos) != 0 {
                            availability[piece_index] = availability[piece_index].saturating_add(1);
                        }
                    }
                }
                log::debug!("availability: {availability:?}");
                PeerMessage::Interested
            }
            PeerMessage::KeepAlive => PeerMessage::KeepAlive,
            PeerMessage::Unchoke => break,
            m => {
                log::warn!("Unexpected message waiting for Unchoke: {m:?}");
                continue;
            }
        };

        log::debug!("Sent: {reply:?}");
        reply.send(&mut stream)?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&torrent.filename)?;

    for (i, expected_hash) in torrent.piece_hashes.iter().enumerate() {
        log::info!("Downloading piece {i}");

        let length = if i == torrent.piece_hashes.len() - 1 {
            torrent.total_length - i * torrent.piece_length
        } else {
            torrent.piece_length
        };

        let mut piece = Piece::new(length, BLOCK_SIZE);

        if let Some((begin, length)) = piece.next_request() {
            PeerMessage::Request {
                index: i as u32,
                begin: begin as u32,
                length: length as u32,
            }
            .send(&mut stream)?;
        }

        loop {
            let message = retrieve_message(&mut reader, &mut buffer)?;

            let reply = match message {
                PeerMessage::KeepAlive => PeerMessage::KeepAlive,
                PeerMessage::Piece {
                    index,
                    begin,
                    block,
                } => {
                    log::debug!(
                        "Recieved: Piece {{ index: {}, begin: {}, block: {} bytes }}",
                        index,
                        begin,
                        block.len()
                    );

                    piece.write_block(begin as usize, block);
                    if piece.is_complete() {
                        break;
                    }

                    if let Some((next_begin, next_length)) = piece.next_request() {
                        PeerMessage::Request {
                            index,
                            begin: next_begin as u32,
                            length: next_length as u32,
                        }
                    } else {
                        continue;
                    }
                }
                m => {
                    log::warn!("Unexpected message waiting for Piece: {m:?}");
                    continue;
                }
            };

            log::debug!("Sent: {reply:?}");
            reply.send(&mut stream)?;
        }

        assert_eq!(
            Sha1::digest(&piece.data).as_slice(),
            expected_hash.as_slice(),
            "Piece {i} failed hash check!"
        );

        log::debug!("first bytes: {:?}", &piece.data[..10]);
        log::debug!("last byte: {:?}", &piece.data[piece.data.len() - 1]);

        file.set_len(torrent.total_length as u64)?;
        let piece_offset = i * torrent.piece_length;
        log::info!(
            "Writing {} bytes to {} @ {}",
            piece.data.len(),
            torrent.filename,
            piece_offset
        );
        file.seek(SeekFrom::Start(piece_offset as u64))?;
        file.write_all(&piece.data)?;
    }

    log::info!("{} downloaded.", torrent.filename);

    Ok(())
}
