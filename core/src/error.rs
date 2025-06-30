#[derive(Debug, thiserror::Error)]
pub enum TorrentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Tracker HTTP error: {0}")]
    TrackerHttp(reqwest::StatusCode),

    #[error("Bencode decode error: {0}")]
    BencodeDecode(#[from] crate::bencode::Error), // Assuming your decode() uses a Result

    #[error("Handshake failed: Info hash mismatch")]
    HandshakeMismatch,

    #[error("Torrent parsing error: {0}")]
    TorrentParse(String),

    #[error("No peers available")]
    NoPeers,

    #[error("Peer choked")]
    PeerChoked,

    #[error("Timeout")]
    Timeout,

    #[error("Magnet parsing error: {0}")]
    MagnetParse(#[from] crate::magnet::MagnetParseError),

    #[error("Message parsing error: {0}")]
    MessageParse(#[from] crate::peer::MessageParseError),
}
