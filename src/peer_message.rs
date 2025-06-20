use std::io::Write;
use std::net::TcpStream;

#[derive(Debug)]
pub enum PeerMessage<'a> {
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(&'a [u8]),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: &'a [u8],
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Port(u16),
    KeepAlive,
    Extended {
        id: u8,
        payload: &'a [u8],
    },
    Unknown(u8, &'a [u8]),
}

impl PeerMessage<'_> {
    fn message_id(&self) -> Option<u8> {
        Some(match self {
            PeerMessage::Choke => 0,
            PeerMessage::Unchoke => 1,
            PeerMessage::Interested => 2,
            PeerMessage::NotInterested => 3,
            PeerMessage::Have(_) => 4,
            PeerMessage::Bitfield(_) => 5,
            PeerMessage::Request { .. } => 6,
            PeerMessage::Piece { .. } => 7,
            PeerMessage::Cancel { .. } => 8,
            PeerMessage::Port(_) => 9,
            PeerMessage::Extended { .. } => 20,
            PeerMessage::Unknown(id, _) => *id,
            PeerMessage::KeepAlive => return None,
        })
    }

    pub fn send(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        stream.write_all(&self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            PeerMessage::KeepAlive => {
                buf.extend(&0u32.to_be_bytes());
            }
            PeerMessage::Choke
            | PeerMessage::Unchoke
            | PeerMessage::Interested
            | PeerMessage::NotInterested => {
                buf.extend(&1u32.to_be_bytes());
                buf.push(self.message_id().unwrap());
            }
            PeerMessage::Have(index) => {
                buf.extend(&5u32.to_be_bytes());
                buf.push(4);
                buf.extend(&index.to_be_bytes());
            }
            PeerMessage::Bitfield(bitfield) => {
                buf.extend(&(1 + bitfield.len() as u32).to_be_bytes());
                buf.push(5);
                buf.extend(*bitfield);
            }
            PeerMessage::Request {
                index,
                begin,
                length,
            } => {
                buf.extend(13u32.to_be_bytes());
                buf.push(6);
                buf.extend(index.to_be_bytes());
                buf.extend(begin.to_be_bytes());
                buf.extend(length.to_be_bytes());
            }
            PeerMessage::Cancel {
                index,
                begin,
                length,
            } => {
                buf.extend(13u32.to_be_bytes());
                buf.push(8);
                buf.extend(index.to_be_bytes());
                buf.extend(begin.to_be_bytes());
                buf.extend(length.to_be_bytes());
            }
            PeerMessage::Port(port) => {
                buf.extend(3u32.to_be_bytes());
                buf.push(9);
                buf.extend(port.to_be_bytes());
            }
            PeerMessage::Extended { id, payload } => {
                buf.extend((payload.len() as u32 + 2).to_be_bytes());
                buf.push(20);
                buf.push(*id);
                buf.extend(*payload);
            }
            PeerMessage::Unknown(first, data) => {
                buf.push(*first);
                buf.extend(*data);
            }
            PeerMessage::Piece { .. } => unreachable!("Tried to create a piece!"),
        }

        buf
    }
}

impl<'a> From<&'a mut [u8]> for PeerMessage<'a> {
    fn from(buf: &'a mut [u8]) -> Self {
        let id = buf[0];
        let payload = &buf[1..];
        match id {
            0 => PeerMessage::Choke,
            1 => PeerMessage::Unchoke,
            2 => PeerMessage::Interested,
            3 => PeerMessage::NotInterested,
            4 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                PeerMessage::Have(index)
            }
            5 => PeerMessage::Bitfield(payload),
            6 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                let length = u32::from_be_bytes(payload[8..12].try_into().unwrap());
                PeerMessage::Request {
                    index,
                    begin,
                    length,
                }
            }
            7 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                let block = &payload[8..];
                PeerMessage::Piece {
                    index,
                    begin,
                    block,
                }
            }
            8 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                let length = u32::from_be_bytes(payload[8..12].try_into().unwrap());
                PeerMessage::Cancel {
                    index,
                    begin,
                    length,
                }
            }
            9 => {
                let port = u16::from_be_bytes(payload[0..2].try_into().unwrap());
                PeerMessage::Port(port)
            }
            20 => PeerMessage::Extended {
                id: payload[0],
                payload: &payload[1..],
            },
            _ => PeerMessage::Unknown(id, payload),
        }
    }
}
