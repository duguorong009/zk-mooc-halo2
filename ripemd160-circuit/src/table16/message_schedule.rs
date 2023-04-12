use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::constants::BLOCK_SIZE;

use super::{
    gates::Gate, spread_table::SpreadInputs, AssignedBits, BlockWord, Table16Assignment,
    NUM_ADVICE_COLS,
};

// Rows needed for each decompose gate
pub const DECOMPOSE_WORD_ROWS: usize = 2;

#[derive(Debug, Clone)]
pub(super) struct MessageWord<F: FieldExt>(AssignedBits<32, F>);

impl<F: FieldExt> std::ops::Deref for MessageWord<F> {
    type Target = AssignedBits<32, F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub(super) struct MessageScheduleConfig<F: FieldExt> {
    lookup: SpreadInputs,
    advice: [Column<Advice>; NUM_ADVICE_COLS],

    /// Decomposition gate for X[0..16]
    s_decompose_word: Selector,

    _marker: PhantomData<F>,
}

impl<F: FieldExt> Table16Assignment<F> for MessageScheduleConfig<F> {}

impl<F: FieldExt> MessageScheduleConfig<F> {
    /// Configures the message schedule
    ///
    /// `advice` contains columns that the message schedule will only use for internal
    /// gates, and will not place any constraints on (such as lookup constraints) outside
    /// itself.
    pub(super) fn configure(
        meta: &mut ConstraintSystem<F>,
        lookup: SpreadInputs,
        advice: [Column<Advice>; NUM_ADVICE_COLS],
        s_decompose_word: Selector,
    ) -> Self {
        // Rename these here for ease of matching the gates to the spec
        let a_3 = advice[0];
        let a_4 = advice[1];
        let a_5 = advice[2];

        // s_decompose_word for all words
        meta.create_gate("s_decompose_word", |meta| {
            let s_decompose_word = meta.query_selector(s_decompose_word);
            let lo = meta.query_advice(a_3, Rotation::cur());
            let hi = meta.query_advice(a_4, Rotation::cur());
            let word = meta.query_advice(a_5, Rotation::cur());

            Gate::s_decompose_word(s_decompose_word, lo, hi, word)
        });

        MessageScheduleConfig {
            lookup,
            advice,
            s_decompose_word,
            _marker: PhantomData,
        }
    }

    pub(super) fn process(
        &self,
        layouter: &mut impl Layouter<F>,
        input: [BlockWord; BLOCK_SIZE],
    ) -> Result<
        (
            [MessageWord<F>; BLOCK_SIZE],
            [(AssignedBits<16, F>, AssignedBits<16, F>); BLOCK_SIZE],
        ),
        Error,
    > {
        let mut w = Vec::<MessageWord<F>>::with_capacity(BLOCK_SIZE);
        let mut w_halves =
            Vec::<(AssignedBits<16, F>, AssignedBits<16, F>)>::with_capacity(BLOCK_SIZE);

        layouter.assign_region(
            || "process message block",
            |mut region| {
                w = Vec::<MessageWord<F>>::with_capacity(BLOCK_SIZE);
                w_halves =
                    Vec::<(AssignedBits<16, F>, AssignedBits<16, F>)>::with_capacity(BLOCK_SIZE);

                // Assign X[0..16]
                for (row, word) in input.iter().enumerate() {
                    let (word, halves) =
                        self.assign_msgblk_word_and_halves(&mut region, word.0, row)?;
                    w.push(MessageWord(word));
                    w_halves.push(halves);
                }

                Ok(())
            },
        )?;

        Ok((w.try_into().unwrap(), w_halves.try_into().unwrap()))
    }
}

/// Returns row number of a word
pub fn get_word_row(word_idx: usize) -> usize {
    assert!(word_idx <= BLOCK_SIZE);
    word_idx * BLOCK_SIZE
}

impl<F: FieldExt> MessageScheduleConfig<F> {
    // Assign a word and its hi and lo halves
    pub fn assign_msgblk_word_and_halves(
        &self,
        region: &mut Region<'_, F>,
        word: Value<u32>,
        word_idx: usize,
    ) -> Result<
        (
            AssignedBits<32, F>,
            (AssignedBits<16, F>, AssignedBits<16, F>),
        ),
        Error,
    > {
        // Rename these here for ease of matching the gates to the spec
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];

        let row = get_word_row(word_idx);
        self.s_decompose_word.enable(region, row)?;

        let (word, (spread_var_lo, spread_var_hi)) = self.assign_word_and_halves(
            || format!("X_{}", row),
            region,
            &self.lookup,
            a_3,
            a_4,
            a_5,
            word,
            row,
        )?;

        Ok((word, (spread_var_lo.dense, spread_var_hi.dense)))
    }
}
