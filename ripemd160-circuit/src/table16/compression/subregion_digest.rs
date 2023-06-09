use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::{circuit::Region, plonk::Error};

use crate::table16::compression::compression_util::*;
use crate::{constants::DIGEST_SIZE, table16::BlockWord};

use super::{CompressionConfig, State};

impl<F: FieldExt> CompressionConfig<F> {
    pub fn assign_digest(
        &self,
        region: &mut Region<'_, F>,
        state: State<F>,
    ) -> Result<[BlockWord; DIGEST_SIZE], Error> {
        let (a, b, c, d, e) = match_state(state);

        let mut row: usize = 0;
        self.assign_decompose_word_dense(region, row, a.clone())?;
        row += 3;
        self.assign_decompose_word_dense(region, row, b.clone().dense_halves)?;
        row += 3;
        self.assign_decompose_word_dense(region, row, c.clone().dense_halves)?;
        row += 3;
        self.assign_decompose_word_dense(region, row, d.clone().dense_halves)?;
        row += 3;
        self.assign_decompose_word_dense(region, row, e.clone())?;

        Ok([
            BlockWord(a.value()),
            BlockWord(b.dense_halves.value()),
            BlockWord(c.dense_halves.value()),
            BlockWord(d.dense_halves.value()),
            BlockWord(e.value()),
        ])
    }
}
