use crate::peer::MessageParseError;
use sha1::{Digest, Sha1};

pub struct Piece {
    pub data: Vec<u8>,
    pub blocks_downloaded: Vec<bool>,
    pub block_size: usize,
    pub total_size: usize,
}

impl Piece {
    pub fn new(total_size: usize, block_size: usize) -> Self {
        let num_blocks = total_size.div_ceil(block_size);
        Self {
            data: vec![0; total_size],
            blocks_downloaded: vec![false; num_blocks],
            block_size,
            total_size,
        }
    }

    pub fn write_block(&mut self, begin: usize, block: &[u8]) -> Result<(), MessageParseError> {
        let end = begin + block.len();
        let block_index = begin / self.block_size;

        if block_index >= self.blocks_downloaded.len() || end > self.data.len() {
            Err(MessageParseError::InvalidBlock {
                begin,
                block_len: block.len(),
                piece_len: self.data.len(),
            })
        } else if self.blocks_downloaded[block_index] {
            Err(MessageParseError::DuplicateBlock { index: block_index })
        } else {
            self.data[begin..end].copy_from_slice(block);
            self.blocks_downloaded[block_index] = true;
            Ok(())
        }
    }

    pub fn is_complete(&self) -> bool {
        self.blocks_downloaded.iter().all(|&b| b)
    }

    pub fn next_request(&self) -> Option<(usize, usize)> {
        for (i, &downloaded) in self.blocks_downloaded.iter().enumerate() {
            if !downloaded {
                let begin = i * self.block_size;
                let remaining = self.total_size - begin;
                let length = remaining.min(self.block_size);
                return Some((begin, length));
            }
        }
        None
    }

    pub fn verify_hash(&self, expected_hash: &[u8; 20]) -> Result<(), MessageParseError> {
        let hash = Sha1::digest(&self.data);
        if hash.as_slice() == expected_hash.as_slice() {
            Ok(())
        } else {
            Err(MessageParseError::PieceHashMismatch {
                expected: *expected_hash,
                actual: hash.into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_piece_initialization() {
        let piece = Piece::new(1024, 256);
        assert_eq!(piece.total_size, 1024);
        assert_eq!(piece.block_size, 256);
        assert_eq!(piece.data.len(), 1024);
        assert_eq!(piece.blocks_downloaded.len(), 4);
        assert!(!piece.is_complete());
    }

    #[test]
    fn test_write_block_valid() {
        let mut piece = Piece::new(512, 256);
        let block = vec![1u8; 256];
        assert!(piece.write_block(0, &block).is_ok());
        assert_eq!(&piece.data[0..256], block.as_slice());
        assert!(piece.blocks_downloaded[0]);
        assert!(!piece.blocks_downloaded[1]);
    }

    #[test]
    fn test_write_block_out_of_bounds() {
        let mut piece = Piece::new(256, 256);
        let block = vec![0u8; 256];
        let result = piece.write_block(512, &block);
        assert!(matches!(
            result,
            Err(MessageParseError::InvalidBlock {
                begin: 512,
                block_len: 256,
                piece_len: 256
            })
        ));
    }

    #[test]
    fn test_write_block_duplicate() {
        let mut piece = Piece::new(256, 256);
        let block = vec![0u8; 256];
        assert!(piece.write_block(0, &block).is_ok());
        let result = piece.write_block(0, &block);
        assert!(matches!(
            result,
            Err(MessageParseError::DuplicateBlock { index: 0 })
        ));
    }

    #[test]
    fn test_write_block_partial_block() {
        let mut piece = Piece::new(512, 256);
        let block = vec![1u8; 128];
        assert!(piece.write_block(0, &block).is_ok());
        assert_eq!(&piece.data[0..128], block.as_slice());
        assert!(piece.blocks_downloaded[0]);
    }

    #[test]
    fn test_verify_hash_valid() {
        let mut piece = Piece::new(256, 256);
        let block = vec![42u8; 256];
        let expected_hash = Sha1::digest(&block);
        piece.write_block(0, &block).unwrap();
        assert!(piece.is_complete());
        assert!(piece.verify_hash(&expected_hash.into()).is_ok());
    }

    #[test]
    fn test_verify_hash_invalid() {
        let mut piece = Piece::new(256, 256);
        let block = vec![42u8; 256];
        let wrong_hash = [0u8; 20];
        piece.write_block(0, &block).unwrap();
        assert!(piece.is_complete());
        assert!(matches!(
            piece.verify_hash(&wrong_hash),
            Err(MessageParseError::PieceHashMismatch { .. })
        ));
    }

    #[test]
    fn test_next_request_first_block() {
        let piece = Piece::new(512, 256);
        assert_eq!(piece.next_request(), Some((0, 256)));
    }

    #[test]
    fn test_next_request_after_first_block() {
        let mut piece = Piece::new(512, 256);
        piece.write_block(0, &vec![0u8; 256]).unwrap();
        assert_eq!(piece.next_request(), Some((256, 256)));
    }

    #[test]
    fn test_next_request_last_partial_block() {
        let mut piece = Piece::new(384, 256); // 1 full block + 1 partial (128 bytes)
        piece.write_block(0, &vec![0u8; 256]).unwrap();
        assert_eq!(piece.next_request(), Some((256, 128)));
    }

    #[test]
    fn test_next_request_none_when_complete() {
        let mut piece = Piece::new(256, 256);
        piece.write_block(0, &vec![0u8; 256]).unwrap();
        assert!(piece.is_complete());
        assert_eq!(piece.next_request(), None);
    }
}
