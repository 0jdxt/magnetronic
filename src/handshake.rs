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
