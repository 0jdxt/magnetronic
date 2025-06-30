use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::error::{self, TorrentError};

#[derive(Debug)]
pub struct Handshake(pub [u8; 68]);

impl Handshake {
    pub fn new(info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Self {
        let mut buf = [0; 68];
        buf[0] = 19;
        buf[1..20].copy_from_slice(b"BitTorrent protocol");
        buf[25] |= 0x10;
        buf[28..48].copy_from_slice(info_hash);
        buf[48..68].copy_from_slice(peer_id);
        Self(buf)
    }

    pub fn supports_extensions(&self) -> bool {
        self.0[25] & 0x10 != 0
    }

    pub fn info_hash(&self) -> &[u8] {
        &self.0[28..48]
    }

    pub fn peer_id(&self) -> &[u8] {
        &self.0[48..68]
    }

    pub fn protocol_string(&self) -> &[u8] {
        &self.0[1..20]
    }

    pub fn validate(&self, expected_info_hash: &[u8]) -> bool {
        log::debug!(
            "first: {}, protocol: {:?}\nhash: {:?}\nexpected: {expected_info_hash:?}",
            self.0[0],
            self.protocol_string(),
            self.info_hash()
        );
        log::debug!("Peer ID: {:?}", self.peer_id());
        if !self.peer_id().iter().all(|&b| b.is_ascii()) {
            log::warn!("Non-ASCII peer_id prefix: {:?}", self.peer_id());
        }
        self.0[0] == 19
            && self.protocol_string() == b"BitTorrent protocol"
            && self.info_hash() == expected_info_hash
    }
}

pub async fn handshake<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    info_hash: &[u8; 20],
) -> Result<bool, error::TorrentError> {
    // Send handshake, receive & validate handshake response
    let handshake = Handshake::new(info_hash, &crate::PEER_ID);
    log::debug!("Sending Handshake: {handshake:?}");
    stream.write_all(&handshake.0).await?;

    let mut buf = [0u8; 68];
    timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .map_err(|_| {
            TorrentError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Handshake read timeout",
            ))
        })?
        .map_err(|e| {
            log::error!(
                "Failed to read handshake: {e}. Recieved {} bytes",
                buf.len()
            );
            TorrentError::Io(e)
        })?;

    let handshake = Handshake(buf);
    log::debug!("Recieved Handshake: {handshake:?}");

    if handshake.validate(info_hash) {
        Ok(handshake.supports_extensions())
    } else {
        log::error!(
            "Handshake validation failed: protocol={:?}, info_hash={:?}",
            handshake.protocol_string(),
            handshake.info_hash()
        );
        Err(error::TorrentError::HandshakeMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_handshake_new() {
        let info_hash = [0u8; 20];
        let peer_id = b"-MG0001-123456789012";
        let handshake = Handshake::new(&info_hash, peer_id);
        assert_eq!(handshake.0[0], 19);
        assert_eq!(&handshake.0[1..20], b"BitTorrent protocol");
        assert_eq!(handshake.0[25], 0x10);
        assert_eq!(&handshake.0[28..48], info_hash);
        assert_eq!(&handshake.0[48..68], peer_id);
    }

    #[test]
    fn test_handshake_validate_invalid_protocol() {
        let info_hash = [0u8; 20];
        let mut handshake = Handshake([0; 68]);
        handshake.0[0] = 19;
        handshake.0[1..20].copy_from_slice(b"InvalidProtocol1234");
        handshake.0[28..48].copy_from_slice(&info_hash);
        assert!(!handshake.validate(&info_hash));
    }

    #[test]
    fn test_handshake_validate_short_protocol() {
        let info_hash = [0u8; 20];
        let mut handshake = Handshake([0; 68]);
        handshake.0[0] = 10;
        handshake.0[1..11].copy_from_slice(b"ShortProto");
        handshake.0[28..48].copy_from_slice(&info_hash);
        assert!(!handshake.validate(&info_hash));
    }

    #[test]
    fn test_handshake_validate_zero_pstrlen() {
        let info_hash = [0u8; 20];
        let mut handshake = Handshake([0; 68]);
        handshake.0[0] = 0;
        handshake.0[28..48].copy_from_slice(&info_hash);
        assert!(!handshake.validate(&info_hash));
    }

    #[test]
    fn test_handshake_validate_invalid_pstrlen() {
        let info_hash = [0u8; 20];
        let mut handshake = Handshake([0; 68]);
        handshake.0[0] = 20;
        handshake.0[1..21].copy_from_slice(b"InvalidProtocol12345");
        handshake.0[28..48].copy_from_slice(&info_hash);
        assert!(!handshake.validate(&info_hash));
    }

    #[test]
    fn test_handshake_validate_mismatched_info_hash() {
        let info_hash = [0u8; 20];
        let wrong_hash = [1u8; 20];
        let mut handshake = Handshake::new(&info_hash, b"-MG0001-123456789012");
        handshake.0[28..48].copy_from_slice(&wrong_hash);
        assert!(!handshake.validate(&info_hash));
    }

    #[test]
    fn test_handshake_validate_no_extensions() {
        let info_hash = [0u8; 20];
        let mut handshake = Handshake::new(&info_hash, b"-MG0001-123456789012");
        handshake.0[25] = 0;
        assert!(handshake.validate(&info_hash));
        assert!(!handshake.supports_extensions());
    }

    #[test]
    fn test_handshake_validate_zeroed_buffer() {
        let info_hash = [0u8; 20];
        let handshake = Handshake([0; 68]);
        assert!(!handshake.validate(&info_hash));
    }

    #[test]
    fn test_handshake_validate_non_ascii_peer_id() {
        let info_hash = [0u8; 20];
        let mut handshake = Handshake::new(&info_hash, &[0xFF; 20]);
        handshake.0[28..48].copy_from_slice(&info_hash);
        assert!(handshake.validate(&info_hash)); // peer_id not checked
        assert!(!handshake.peer_id().iter().all(u8::is_ascii));
    }

    #[test]
    fn test_handshake_validate_ascii_peer_id() {
        let info_hash = [0u8; 20];
        let peer_id = b"-qB4500-123456789012";
        let handshake = Handshake::new(&info_hash, peer_id);
        assert!(handshake.validate(&info_hash));
        assert!(handshake.peer_id().iter().all(u8::is_ascii));
    }

    #[tokio::test]
    async fn test_handshake_async_valid() {
        let (mut client, mut server) = duplex(1024);
        let info_hash = [0u8; 20];
        let peer_id = b"-MG0001-123456789012";
        let shake = Handshake::new(&info_hash, peer_id);

        tokio::spawn(async move {
            let mut buf = [0u8; 68];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&shake.0).await.unwrap();
        });

        let result = handshake(&mut client, &info_hash).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_handshake_async_invalid_protocol() {
        let (mut client, mut server) = duplex(1024);
        let info_hash = [0u8; 20];
        let peer_id = b"-MG0001-123456789012";
        let mut invalid_handshake = Handshake::new(&info_hash, peer_id);
        invalid_handshake.0[1..20].copy_from_slice(b"InvalidProtocol1234");

        tokio::spawn(async move {
            server.write_all(&invalid_handshake.0).await.unwrap();
        });

        let result = handshake(&mut client, &info_hash).await;
        assert!(matches!(result, Err(TorrentError::HandshakeMismatch)));
    }

    #[tokio::test]
    async fn test_handshake_async_short_read() {
        let (mut client, mut server) = duplex(1024);
        tokio::spawn(async move {
            server.write_all(&[0u8; 10]).await.unwrap();
        });

        let result = handshake(&mut client, &[0u8; 20]).await;
        assert!(matches!(result, Err(TorrentError::Io(_))));
    }

    #[tokio::test]
    async fn test_handshake_async_partial_read() {
        let (mut client, mut server) = duplex(1024);
        let info_hash = [0u8; 20];
        let peer_id = b"-MG0001-123456789012";
        let shake = Handshake::new(&info_hash, peer_id);
        let partial = shake.0[..67].to_vec();

        tokio::spawn(async move {
            server.write_all(&partial).await.unwrap();
        });

        let result = handshake(&mut client, &info_hash).await;
        assert!(matches!(result, Err(TorrentError::Io(_))));
    }

    #[tokio::test]
    async fn test_handshake_async_timeout() {
        use tokio::time::Duration;

        let (mut client, mut server) = duplex(1024);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(6)).await;
            server.write_all(&[0u8; 68]).await.unwrap();
        });

        let result = handshake(&mut client, &[0u8; 20]).await;
        assert!(matches!(result, Err(TorrentError::Io(_))));
    }

    #[tokio::test]
    async fn test_handshake_async_non_ascii_peer_id() {
        let (mut client, mut server) = duplex(1024);
        let info_hash = [0u8; 20];
        let peer_id = [0xFF; 20];
        let shake = Handshake::new(&info_hash, &peer_id);

        tokio::spawn(async move {
            let mut buf = [0u8; 68];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&shake.0).await.unwrap();
        });

        let result = handshake(&mut client, &info_hash).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
