use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use crate::error::TorrentError;
use crate::TorrentInfo;

#[derive(Debug, PartialEq)]
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

#[derive(Debug, Error)]
pub enum MessageParseError {
    #[error("Message too large: {0}")]
    OversizedMessage(u32),

    #[error("Missing or incomplete payload for message ID {0}")]
    IncompletePayload(u8),

    #[error("Unexpected payload length: expected at least {expected}, got {actual}")]
    PayloadLengthMismatch { expected: usize, actual: usize },

    #[error("Invalid block length: {0}")]
    InvalidBlockLength(u32),

    #[error("Invalid block range: {length} bytes @ {begin} for piece length {piece_len}")]
    InvalidBlockRange {
        begin: u32,
        length: u32,
        piece_len: usize,
    },

    #[error("Piece index exceeds number of pieces {0}")]
    InvalidPieceIndex(u32),

    #[error("Piece {index} out of bounds for length {piece_len}: {block_len} bytes @ {begin}")]
    PieceBlockOutOfBounds {
        index: u32,
        begin: u32,
        block_len: usize,
        piece_len: usize,
    },
}

pub async fn retrieve_message<'a>(
    reader: &'a mut BufReader<OwnedReadHalf>,
    buffer: &'a mut [u8],
    torrent: Option<&'a TorrentInfo>,
) -> Result<Message<'a>, TorrentError> {
    let mut len_buf = [0; 4];
    reader.read_exact(&mut len_buf).await?;
    let length = u32::from_be_bytes(len_buf);

    if length == 0 {
        return Ok(Message::KeepAlive);
    } else if length > crate::MAX_MESSAGE_SIZE {
        return Err(MessageParseError::OversizedMessage(length))?;
    }

    let slice = &mut buffer[..length as usize];
    reader.read_exact(slice).await?;
    let message = slice.try_into()?;

    // If for torrent, validate against metadata
    if let Some(torrent) = torrent {
        match &message {
            Message::Request {
                index,
                begin,
                length,
            }
            | Message::Cancel {
                index,
                begin,
                length,
            } => {
                if *length == 0 || *length as usize > torrent.piece_length {
                    return Err(MessageParseError::InvalidBlockLength(*length))?;
                }
                if (*begin + *length) as usize > torrent.piece_length {
                    return Err(MessageParseError::InvalidBlockRange {
                        begin: *begin,
                        length: *length,
                        piece_len: torrent.piece_length,
                    })?;
                }
                if *index as usize >= torrent.piece_hashes.len() {
                    return Err(MessageParseError::InvalidPieceIndex(*index))?;
                }
            }
            Message::Piece {
                index,
                begin,
                block,
            } => {
                if *begin as usize + block.len() > torrent.piece_length {
                    return Err(MessageParseError::PieceBlockOutOfBounds {
                        index: *index,
                        begin: *begin,
                        block_len: block.len(),
                        piece_len: torrent.piece_length,
                    })?;
                }
            }
            _ => {}
        }
    }

    Ok(message)
}

impl Message<'_> {
    pub fn make_request(index: usize, begin: usize, length: usize) -> Result<Self, TorrentError> {
        let index_u32: u32 = index.try_into().map_err(|_| {
            TorrentError::TorrentParse(format!("Piece index {index} exceeds u32 max"))
        })?;
        let begin_u32: u32 = begin.try_into().map_err(|_| {
            TorrentError::TorrentParse(format!("Begin offset {begin} exceeds u32 max"))
        })?;
        let length_u32: u32 = length.try_into().map_err(|_| {
            TorrentError::TorrentParse(format!("Block length {length} exceeds u32 max"))
        })?;
        Ok(Message::Request {
            index: index_u32,
            begin: begin_u32,
            length: length_u32,
        })
    }

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

    pub async fn send(&self, w: &mut OwnedWriteHalf) -> Result<(), TorrentError> {
        w.write_all(&self.to_bytes()?)
            .await
            .map_err(TorrentError::Io)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TorrentError> {
        let mut buf = Vec::new();

        match self {
            Message::KeepAlive => {
                buf.extend(&0u32.to_be_bytes());
            }
            Message::Choke | Message::Unchoke | Message::Interested | Message::NotInterested => {
                buf.extend(&1u32.to_be_bytes());
                buf.push(self.message_id().expect("message_id returned None"));
            }
            Message::Have(index) => {
                buf.extend(&5u32.to_be_bytes());
                buf.push(4);
                buf.extend(&index.to_be_bytes());
            }
            Message::Bitfield(bitfield) => {
                let length_u32: u32 = (1 + bitfield.len()).try_into().map_err(|_| {
                    TorrentError::TorrentParse("Bitfield length exceeds u32 max".into())
                })?;
                buf.extend(&length_u32.to_be_bytes());
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
            Message::Piece {
                index,
                begin,
                block,
            } => {
                let length_u32: u32 = (block.len() + 9).try_into().map_err(|_| {
                    TorrentError::TorrentParse("message length exceeds u32 max".into())
                })?;
                buf.extend(length_u32.to_be_bytes());
                buf.push(7);
                buf.extend(index.to_be_bytes());
                buf.extend(begin.to_be_bytes());
                buf.extend_from_slice(block);
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
                let length_u32: u32 = (payload.len() + 2).try_into().map_err(|_| {
                    TorrentError::TorrentParse("message length exceeds u32 max".into())
                })?;
                buf.extend(length_u32.to_be_bytes());
                buf.push(20);
                buf.push(*id);
                buf.extend(*payload);
            }
            Message::Unknown(first, data) => {
                let length_u32: u32 = (data.len() + 1).try_into().map_err(|_| {
                    TorrentError::TorrentParse("message length exceeds u32 max".into())
                })?;
                buf.extend(length_u32.to_be_bytes());
                buf.push(*first);
                buf.extend(*data);
            }
        }

        Ok(buf)
    }
}

fn read_u32(slice: &[u8]) -> u32 {
    u32::from_be_bytes(slice.try_into().expect("slice must be exactly 4 bytes"))
}

impl<'a> TryFrom<&'a mut [u8]> for Message<'a> {
    type Error = MessageParseError;

    fn try_from(buf: &'a mut [u8]) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(MessageParseError::IncompletePayload(0));
        }

        let id = buf[0];
        let payload = &buf[1..];

        macro_rules! require_min_len {
            ($min:expr) => {
                if payload.len() < $min {
                    return Err(MessageParseError::PayloadLengthMismatch {
                        expected: $min,
                        actual: payload.len(),
                    });
                }
            };
        }

        Ok(match id {
            0 => Message::Choke,
            1 => Message::Unchoke,
            2 => Message::Interested,
            3 => Message::NotInterested,
            4 => {
                require_min_len!(4);
                let index = read_u32(&payload[0..4]);
                Message::Have(index)
            }
            5 => Message::Bitfield(payload),
            6 => {
                require_min_len!(12);
                let index = read_u32(&payload[0..4]);
                let begin = read_u32(&payload[4..8]);
                let length = read_u32(&payload[8..12]);
                Message::Request {
                    index,
                    begin,
                    length,
                }
            }
            7 => {
                require_min_len!(8);
                let index = read_u32(&payload[0..4]);
                let begin = read_u32(&payload[4..8]);
                let block = &payload[8..];
                Message::Piece {
                    index,
                    begin,
                    block,
                }
            }
            8 => {
                require_min_len!(12);
                let index = read_u32(&payload[0..4]);
                let begin = read_u32(&payload[4..8]);
                let length = read_u32(&payload[8..12]);
                Message::Cancel {
                    index,
                    begin,
                    length,
                }
            }
            9 => {
                require_min_len!(2);
                let port =
                    u16::from_be_bytes(payload[0..2].try_into().expect("slice must be 2 bytes"));
                Message::Port(port)
            }
            20 => {
                require_min_len!(1);
                Message::Extended {
                    id: payload[0],
                    payload: &payload[1..],
                }
            }
            _ => Message::Unknown(id, payload),
        })
    }
}
