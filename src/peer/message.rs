use tokio::io::AsyncWriteExt;

#[derive(Debug)]
pub enum Message<'a> {
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

impl Message<'_> {
    fn message_id(&self) -> Option<u8> {
        Some(match self {
            Message::Choke => 0,
            Message::Unchoke => 1,
            Message::Interested => 2,
            Message::NotInterested => 3,
            Message::Have(_) => 4,
            Message::Bitfield(_) => 5,
            Message::Request { .. } => 6,
            Message::Piece { .. } => 7,
            Message::Cancel { .. } => 8,
            Message::Port(_) => 9,
            Message::Extended { .. } => 20,
            Message::Unknown(id, _) => *id,
            Message::KeepAlive => return None,
        })
    }

    pub async fn send<W: AsyncWriteExt + std::marker::Unpin>(
        &self,
        stream: &mut W,
    ) -> std::io::Result<()> {
        stream.write_all(&self.to_bytes()).await
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            Message::KeepAlive => {
                buf.extend(&0u32.to_be_bytes());
            }
            Message::Choke | Message::Unchoke | Message::Interested | Message::NotInterested => {
                buf.extend(&1u32.to_be_bytes());
                buf.push(self.message_id().unwrap());
            }
            Message::Have(index) => {
                buf.extend(&5u32.to_be_bytes());
                buf.push(4);
                buf.extend(&index.to_be_bytes());
            }
            Message::Bitfield(bitfield) => {
                buf.extend(&(1 + bitfield.len() as u32).to_be_bytes());
                buf.push(5);
                buf.extend(*bitfield);
            }
            Message::Request {
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
            Message::Cancel {
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
            Message::Port(port) => {
                buf.extend(3u32.to_be_bytes());
                buf.push(9);
                buf.extend(port.to_be_bytes());
            }
            Message::Extended { id, payload } => {
                buf.extend((payload.len() as u32 + 2).to_be_bytes());
                buf.push(20);
                buf.push(*id);
                buf.extend(*payload);
            }
            Message::Unknown(first, data) => {
                buf.push(*first);
                buf.extend(*data);
            }
            Message::Piece { .. } => unreachable!("Tried to create a piece!"),
        }

        buf
    }
}

impl<'a> From<&'a mut [u8]> for Message<'a> {
    fn from(buf: &'a mut [u8]) -> Self {
        let id = buf[0];
        let payload = &buf[1..];
        match id {
            0 => Message::Choke,
            1 => Message::Unchoke,
            2 => Message::Interested,
            3 => Message::NotInterested,
            4 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                Message::Have(index)
            }
            5 => Message::Bitfield(payload),
            6 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                let length = u32::from_be_bytes(payload[8..12].try_into().unwrap());
                Message::Request {
                    index,
                    begin,
                    length,
                }
            }
            7 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                let block = &payload[8..];
                Message::Piece {
                    index,
                    begin,
                    block,
                }
            }
            8 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                let length = u32::from_be_bytes(payload[8..12].try_into().unwrap());
                Message::Cancel {
                    index,
                    begin,
                    length,
                }
            }
            9 => {
                let port = u16::from_be_bytes(payload[0..2].try_into().unwrap());
                Message::Port(port)
            }
            20 => Message::Extended {
                id: payload[0],
                payload: &payload[1..],
            },
            _ => Message::Unknown(id, payload),
        }
    }
}
