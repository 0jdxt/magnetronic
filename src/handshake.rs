use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct Handshake([u8; 68]);

impl Handshake {
    pub fn new(info_hash: &[u8], peer_id: &[u8]) -> Self {
        let mut buf = [0; 68];
        buf[0] = 19;
        buf[1..20].copy_from_slice(b"BitTorrent protocol");
        buf[25] |= 0x10;
        buf[28..48].copy_from_slice(info_hash);
        buf[48..68].copy_from_slice(peer_id);
        Self(buf)
    }

    pub fn from_bytes(bytes: [u8; 68]) -> Self {
        Self(bytes)
    }

    pub fn supports_extensions(&self) -> bool {
        self.0[25] & 0x10 != 0
    }

    pub fn info_hash(&self) -> &[u8] {
        &self.0[28..48]
    }

    pub fn _peer_id(&self) -> &[u8] {
        &self.0[48..68]
    }

    pub fn protocol_string(&self) -> &[u8] {
        &self.0[1..20]
    }

    pub fn validate(&self, expected_info_hash: &[u8]) -> bool {
        self.protocol_string() == b"BitTorrent protocol" && self.info_hash() == expected_info_hash
    }
}

impl AsRef<[u8]> for Handshake {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub async fn handshake(stream: &mut TcpStream, info_hash: &[u8]) -> std::io::Result<bool> {
    // Send handshake, receive & validate handshake response
    let handshake = Handshake::new(info_hash, crate::PEER_ID);
    log::debug!("Sending Handshake: {handshake:?}");
    stream.write_all(handshake.as_ref()).await?;

    let mut buf = [0u8; 68];
    stream.read_exact(&mut buf).await?;
    let handshake = Handshake::from_bytes(buf);

    log::debug!("Recieved Handshake: {handshake:?}");
    assert!(handshake.validate(info_hash));
    Ok(handshake.supports_extensions())
}
