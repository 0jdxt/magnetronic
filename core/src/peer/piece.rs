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

    pub fn write_block(&mut self, begin: usize, block: &[u8]) {
        let end = begin + block.len();
        assert!(end <= self.total_size, "Block write out of bounds");

        self.data[begin..end].copy_from_slice(block);

        let block_index = begin / self.block_size;
        self.blocks_downloaded[block_index] = true;
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
}
