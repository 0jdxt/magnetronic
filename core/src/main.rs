#![warn(clippy::all)]
#![warn(clippy::pedantic)]
mod bencode;
mod error;
mod handshake;
mod magnet;
mod peer;
mod peers;
mod torrent;

// modules
use error::TorrentError;
use magnet::fetch_torrent_info_from_magnet;
use magnet::MagnetInfo;
use torrent::parse_torrent_file;
use torrent::TorrentInfo;
// cargo
use sha1::{Digest, Sha1};
use tokio::{
    fs::OpenOptions,
    io::{AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom},
    net::TcpStream,
};

use crate::peer::{retrieve_message, Message};

const PEER_ID: &[u8; 20] = b"-TR2940-6wfG2wk6wWLc";
const BLOCK_SIZE: usize = 16 * 1024; // 16KB blocks
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1MB max

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<(), error::TorrentError> {
    env_logger::Builder::from_default_env()
        .format_target(false)
        .format_file(true)
        .format_timestamp(None)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <torrent | magnet>", args[0]);
        std::process::exit(1);
    }

    let (torrent, (mut reader, mut writer_half)) = if args[1].starts_with("magnet:?") {
        let (t, (r, mut w)) = fetch_torrent_info_from_magnet(&args[1]).await?;
        peer::Message::Interested.send(&mut w).await?;
        (t, (r, w))
    } else {
        let bytes = std::fs::read(&args[1]).unwrap();

        let (torrent_info_dict, _) = bencode::decode(&bytes)?;
        log::debug!("{torrent_info_dict}");

        let mut t =
            parse_torrent_file(&torrent_info_dict).expect("Failed to get TorrentInfo from file");
        t.peers = peers::request_peers(&t).await?;

        let peer = t.peers[0];
        log::info!("Connecting to {peer}");
        let mut stream = TcpStream::connect(peer).await?;

        handshake::handshake(&mut stream, &t.info_hash).await?;
        let (r, w) = stream.into_split();
        (t, (BufReader::new(r), w))
    };
    log::debug!("TorrentInfo: {torrent:?}");

    let bitfield_len = torrent.piece_hashes.len().div_ceil(8);
    let empty_bitfield = vec![0u8; bitfield_len];
    peer::Message::Bitfield(&empty_bitfield)
        .send(&mut writer_half)
        .await?;

    let mut availability = vec![0u8; torrent.piece_hashes.len()];
    log::info!("Waiting for Unchoke");

    let mut buffer = vec![0u8; torrent.piece_length];
    loop {
        let message = retrieve_message(&mut reader, &mut buffer, Some(&torrent)).await?;
        log::debug!("Recieved: {message:?}");

        let reply = match message {
            peer::Message::Bitfield(field) => {
                for (i, byte) in field.iter().enumerate() {
                    for bit_pos in 0..8 {
                        let piece_index = i * 8 + bit_pos;
                        if byte & (0x80 >> bit_pos) != 0 {
                            availability[piece_index] = availability[piece_index].saturating_add(1);
                        }
                    }
                }
                log::debug!("availability: {availability:?}");
                peer::Message::Interested
            }
            peer::Message::KeepAlive => peer::Message::KeepAlive,
            peer::Message::Unchoke => break,
            m => {
                log::warn!("Unexpected message waiting for Unchoke: {m:?}");
                continue;
            }
        };

        log::debug!("Sent: {reply:?}");
        reply.send(&mut writer_half).await?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&torrent.filename)
        .await?;

    file.set_len(torrent.total_length).await?;

    for (i, expected_hash) in torrent.piece_hashes.iter().enumerate() {
        log::info!("Downloading piece {i}");

        let piece_offset = i * torrent.piece_length;
        let length = {
            let remaining = torrent
                .total_length
                .checked_sub(piece_offset as u64)
                .ok_or_else(|| TorrentError::TorrentParse("Invalid piece offset".into()))?;

            remaining
                .min(torrent.piece_length as u64)
                .try_into()
                .map_err(|_| TorrentError::TorrentParse("piece length exceeds usize".into()))?
        };

        let mut piece = peer::Piece::new(length, BLOCK_SIZE);

        if let Some((begin, length)) = piece.next_request() {
            Message::make_request(i, begin, length)?
                .send(&mut writer_half)
                .await?;
        }

        loop {
            let message = retrieve_message(&mut reader, &mut buffer, Some(&torrent)).await?;

            let reply = match message {
                peer::Message::KeepAlive => peer::Message::KeepAlive,
                peer::Message::Piece {
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
                        Message::make_request(i, next_begin, next_length)?
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
            reply.send(&mut writer_half).await?;
        }

        if Sha1::digest(&piece.data).as_slice() != expected_hash.as_slice() {
            return Err(error::TorrentError::PieceHashMismatch(i));
        }

        log::debug!("first bytes: {:?}", &piece.data[..10]);
        log::debug!("last byte: {:?}", &piece.data[piece.data.len() - 1]);

        log::info!(
            "Writing {} bytes to {} @ {}",
            piece.data.len(),
            torrent.filename,
            piece_offset
        );
        file.seek(SeekFrom::Start(piece_offset as u64)).await?;
        file.write_all(&piece.data).await?;
    }

    log::info!("{} downloaded.", torrent.filename);

    Ok(())
}
