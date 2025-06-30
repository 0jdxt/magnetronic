use crate::{bencode, error};
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use std::net::SocketAddr;

pub trait NeedsPeers<'i> {
    fn get_tracker(&'i self) -> &'i str;
    fn get_hash(&'i self) -> &'i [u8];
    fn get_left(&'i self) -> &'i u64;
}

impl<'t> NeedsPeers<'t> for crate::TorrentInfo {
    fn get_tracker(&'t self) -> &'t str {
        &self.trackers[0]
    }
    fn get_hash(&'t self) -> &'t [u8] {
        &self.info_hash
    }

    fn get_left(&'t self) -> &'t u64 {
        &self.total_length
    }
}

impl<'m> NeedsPeers<'m> for crate::MagnetInfo<'_> {
    fn get_tracker(&'m self) -> &'m str {
        &self.trackers[0]
    }
    fn get_hash(&'m self) -> &'m [u8] {
        &self.info_hash
    }
    fn get_left(&'m self) -> &'m u64 {
        &1
    }
}

pub async fn request_peers<'i, I: NeedsPeers<'i>>(
    info: &'i I,
) -> Result<Vec<SocketAddr>, error::TorrentError> {
    // Build tracker URL with params & send request
    // Parse response for peers (compact format)

    let info_hash_encoded = percent_encode(info.get_hash(), NON_ALPHANUMERIC).to_string();
    let peer_id_encoded = percent_encode(&*crate::PEER_ID, NON_ALPHANUMERIC).to_string();

    let url = format!(
        "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left={}&compact=1&event=started",
        info.get_tracker(),
        info_hash_encoded,
        peer_id_encoded,
        info.get_left()
    );
    log::debug!("requesting: {url}");

    let res = reqwest::get(&url).await?;
    log::debug!("{res:?}");
    if !res.status().is_success() {
        return Err(error::TorrentError::TrackerHttp(res.status()));
    }

    let bytes = res.bytes().await?;
    let (resp, _) = bencode::decode(&bytes)?;
    log::debug!("{resp:?}");

    match resp.get(b"peers")? {
        Some(bencode::Value::ByteString(v)) if v.len() % 6 == 0 => {
            let peers = v
                .chunks_exact(6)
                .map(|chunk| {
                    SocketAddr::from((
                        [chunk[0], chunk[1], chunk[2], chunk[3]],
                        u16::from_be_bytes([chunk[4], chunk[5]]),
                    ))
                })
                .collect();
            Ok(peers)
        }
        Some(bencode::Value::ByteString(v)) => {
            log::warn!("Peers byte string length not multiple of 6: {}", v.len());
            Err(error::TorrentError::NoPeers)
        }
        value => {
            log::warn!("Invalid peers field: '{value:?}'");
            Err(error::TorrentError::NoPeers)
        }
    }
}
