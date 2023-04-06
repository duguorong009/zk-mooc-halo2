// Rows needed for each decompose gate
pub const DECOMPOSE_WORD_ROWS: usize = 2;

/// Returns row number of a word
pub fn get_word_row(word_idx: usize) -> usize {
    assert!(word_idx <= BLOCK_SIZE);
    word_idx * BLOCK_SIZE
}
