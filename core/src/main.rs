#![warn(clippy::all)]
#![warn(clippy::pedantic)]
mod bencode;
mod error;
mod handshake;
mod magnet;
mod peer;
mod peers;
mod torrent;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

// modules
use error::TorrentError;
use magnet::fetch_torrent_info_from_magnet;
use magnet::MagnetInfo;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;
use torrent::parse_torrent_file;
use torrent::TorrentInfo;
// cargo
use rand::Rng;
use tokio::{
    fs::OpenOptions,
    io::{AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom},
    net::TcpStream,
};

use crate::handshake::handshake;
use crate::peer::{retrieve_message, Message};

static PEER_ID_PREFIX: &[u8; 8] = b"-MG0001-";
static PEER_ID: LazyLock<[u8; 20]> = LazyLock::new(|| {
    let mut id = [0u8; 20];
    id[0..8].copy_from_slice(PEER_ID_PREFIX);
    id[8..20].copy_from_slice(&rand::rng().random::<[u8; 12]>());
    log::info!("Generated Peer ID: {}", hex::encode(id));
    id
});
const BLOCK_SIZE: usize = 16 * 1024; // 16KB blocks
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1MB max

/// # Errors
///
/// at the moment will bubble up many errors before proper handling is done.
pub async fn run(
    args: Vec<String>,
    test_torrent: Option<TorrentInfo>,
) -> Result<(), error::TorrentError> {
    if args.len() != 2 {
        eprintln!("Usage: {} <torrent | magnet>", args[0]);
        std::process::exit(1);
    }

    let (torrent, initial_stream) = if args[1].starts_with("magnet:?") {
        let (t, (r, mut w)) = fetch_torrent_info_from_magnet(&args[1]).await?;
        peer::Message::Interested.send(&mut w).await?;
        (t, Some((r, w)))
    } else if let Some(mut torrent) = test_torrent {
        if torrent.peers.is_empty() {
            log::debug!("Fetching peers for test torrent");
            torrent.peers = peers::request_peers(&torrent).await?;
        } else {
            log::debug!("Using test-provided peers: {:?}", torrent.peers);
        }
        (torrent, None)
    } else {
        let bytes = std::fs::read(&args[1])?;
        if bytes.is_empty() {
            return Err(TorrentError::TorrentParse("Empty torrent file".into()));
        }

        let (torrent_info_dict, _) = bencode::decode(&bytes)?;
        log::debug!("{torrent_info_dict}");

        let mut t = parse_torrent_file(&torrent_info_dict)?;
        t.peers = peers::request_peers(&t).await?;

        (t, None)
    };
    log::debug!("TorrentInfo: {torrent:?}");

    let availability = Arc::new(Mutex::new(vec![0u8; torrent.piece_hashes.len()]));
    let completed = Arc::new(Mutex::new(vec![false; torrent.piece_hashes.len()]));
    let torrent = Arc::new(torrent);
    let mut join_set = JoinSet::new();

    let queue = Arc::new(Mutex::new(
        (0..torrent.piece_hashes.len()).collect::<Vec<usize>>(),
    ));

    let mut is_magnet = false;
    if let Some((reader, writer)) = initial_stream {
        is_magnet = true;
        let torrent = Arc::clone(&torrent);
        let availability = Arc::clone(&availability);
        let completed = Arc::clone(&completed);
        let queue = Arc::clone(&queue);
        join_set.spawn(handle_peer(
            reader,
            writer,
            torrent,
            availability,
            completed,
            queue,
        ));
    }

    for peer in torrent.peers.iter().skip(is_magnet.into()) {
        log::info!("Connecting to {peer}");
        match TcpStream::connect(peer).await {
            Ok(mut stream) => match handshake(&mut stream, &torrent.info_hash).await {
                Ok(_) => {
                    let (reader, writer) = stream.into_split();
                    let torrent = Arc::clone(&torrent);
                    let availability = Arc::clone(&availability);
                    let completed = Arc::clone(&completed);
                    let queue = Arc::clone(&queue);
                    join_set.spawn(handle_peer(
                        BufReader::new(reader),
                        writer,
                        torrent,
                        availability,
                        completed,
                        queue,
                    ));
                }
                Err(e) => log::warn!("Handshake failed for peer {peer}: {e}"),
            },
            Err(e) => log::warn!("Failed to connect to peer {peer}: {e}"),
        }
    }

    while !completed.lock().await.iter().all(|&done| done) {
        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                log::warn!("Peer task failed: {e}");
            }
        }
        if join_set.is_empty() && !completed.lock().await.iter().all(|&done| done) {
            log::error!("No active peers and download incomplete");
            return Err(TorrentError::NoPeers);
        }
    }

    log::info!("{} downloaded", torrent.filename);
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn handle_peer(
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
    torrent: Arc<TorrentInfo>,
    availability: Arc<Mutex<Vec<u8>>>,
    completed: Arc<Mutex<Vec<bool>>>,
    queue: Arc<Mutex<Vec<usize>>>,
) -> Result<(), TorrentError> {
    let bitfield_len = torrent.piece_hashes.len().div_ceil(8);
    let empty_bitfield = vec![0u8; bitfield_len];
    peer::Message::Bitfield(&empty_bitfield)
        .send(&mut writer)
        .await?;

    let mut buffer = vec![0u8; MAX_MESSAGE_SIZE as usize];
    let mut peer_availability = vec![false; torrent.piece_hashes.len()];

    log::info!("Waiting for Unchoke from peer");
    match timeout(Duration::from_secs(30), async {
        loop {
            let message = retrieve_message(&mut reader, &mut buffer, Some(&torrent)).await?;
            log::debug!("Recieved from peer: {message:?}");

            match message {
                peer::Message::Bitfield(field) => {
                    let mut avail = availability.lock().await;
                    for (i, byte) in field.iter().enumerate() {
                        for bit_pos in 0..8 {
                            let piece_index = i * 8 + bit_pos;
                            if piece_index < torrent.piece_hashes.len()
                                && byte & (0x80 >> bit_pos) != 0
                            {
                                peer_availability[piece_index] = true;
                                avail[piece_index] = avail[piece_index].saturating_add(1);
                            }
                        }
                    }
                    log::debug!("availability: {availability:?}");
                    log::debug!("peer availability: {peer_availability:?}");
                    peer::Message::Interested.send(&mut writer).await?;
                }
                peer::Message::KeepAlive => peer::Message::KeepAlive.send(&mut writer).await?,
                peer::Message::Unchoke => {
                    return Ok(());
                }
                peer::Message::Choke => {
                    return Err(TorrentError::PeerChoked);
                }
                m => log::warn!("Unexpected message waiting for Unchoke: {m:?}"),
            }
        }
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(TorrentError::Timeout),
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&torrent.filename)
        .await?;
    file.set_len(torrent.total_length).await?;

    // for (i, expected_hash) in torrent.piece_hashes.iter().enumerate() {
    while let Some(i) = queue.lock().await.pop() {
        if completed.lock().await[i] {
            log::info!("Piece {i} already downloaded; skipping");
            continue;
        }
        if !peer_availability[i] {
            log::info!("Piece {i} not available");
            continue;
        }

        log::info!("Downloading piece {i} from peer");
        let piece_offset = i * torrent.piece_length;
        let length = {
            let remaining = torrent
                .total_length
                .checked_sub(piece_offset as u64)
                .ok_or_else(|| TorrentError::TorrentParse("Invalid piece offset".into()))?;

            remaining
                .min(torrent.piece_length as u64)
                .try_into()
                .map_err(|_| TorrentError::TorrentParse("Piece length exceeds usize".into()))?
        };

        let mut piece = peer::Piece::new(length, BLOCK_SIZE);

        if let Some((begin, length)) = piece.next_request() {
            match timeout(
                Duration::from_secs(10),
                Message::make_request(i, begin, length)?.send(&mut writer),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                _ => return Err(TorrentError::Timeout),
            }
        }

        loop {
            let message = retrieve_message(&mut reader, &mut buffer, Some(&torrent)).await?;

            match message {
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

                    piece.write_block(begin as usize, block)?;
                    if piece.is_complete() {
                        break;
                    }

                    if let Some((next_begin, next_length)) = piece.next_request() {
                        match timeout(
                            Duration::from_secs(10),
                            Message::make_request(i, next_begin, next_length)?.send(&mut writer),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => return Err(e),
                            Err(_) => return Err(TorrentError::Timeout),
                        }
                    }
                }
                peer::Message::KeepAlive => peer::Message::KeepAlive.send(&mut writer).await?,
                m => log::warn!("Unexpected message waiting for Piece: {m:?}"),
            }
        }

        match piece.verify_hash(&torrent.piece_hashes[i]) {
            Ok(()) => {
                file.seek(SeekFrom::Start(piece_offset as u64)).await?;
                file.write_all(&piece.data).await?;
                completed.lock().await[i] = true;
                log::info!(
                    "Wrote {} bytes to {} @ {}",
                    piece.data.len(),
                    torrent.filename,
                    piece_offset
                );
                peer::Message::Have(i as u32).send(&mut writer).await?;
                log::debug!("Sent Have({i}) to peer");
            }
            Err(e) => {
                log::error!("Piece {i} verification failed: {e}");
                queue.lock().await.push(i);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .format_target(false)
        .format_file(true)
        .format_timestamp(None)
        .init();

    if let Err(e) = run(std::env::args().collect(), None).await {
        log::error!("Error: {e}");
        std::process::exit(1);
    }
}
