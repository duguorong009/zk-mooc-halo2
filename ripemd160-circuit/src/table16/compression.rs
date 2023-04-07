use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::pallas,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
};

use crate::constants::{BLOCK_SIZE, DIGEST_SIZE, ROUNDS};

use super::{
    spread_table::SpreadInputs, AssignedBits, BlockWord, Table16Assignment, NUM_ADVICE_COLS,
};

mod compression_gates;
mod compression_util;
mod subregion_digest;
mod subregion_initial;
mod subregion_main;

#[derive(Debug, Clone)]
pub struct RoundWordDense(AssignedBits<16>, AssignedBits<16>);

impl From<(AssignedBits<16>, AssignedBits<16>)> for RoundWordDense {
    fn from(halves: (AssignedBits<16>, AssignedBits<16>)) -> Self {
        Self(halves.0, halves.1)
    }
}

impl RoundWordDense {
    pub fn value(&self) -> Value<u32> {
        self.0
            .value_u16()
            .zip(self.1.value_u16())
            .map(|(lo, hi)| lo as u32 + (1 << 16) * hi as u32)
    }
}

#[derive(Debug, Clone)]
pub struct RoundWordSpread(AssignedBits<32>, AssignedBits<32>);

impl From<(AssignedBits<32>, AssignedBits<32>)> for RoundWordSpread {
    fn from(halves: (AssignedBits<32>, AssignedBits<32>)) -> Self {
        Self(halves.0, halves.1)
    }
}

impl RoundWordSpread {
    pub fn value(&self) -> Value<u64> {
        self.0
            .value_u32()
            .zip(self.1.value_u32())
            .map(|(lo, hi)| lo as u64 + (1 << 32) * hi as u64)
    }
}

#[derive(Debug, Clone)]
pub struct RoundWord {
    dense_halves: RoundWordDense,
    spread_halves: RoundWordSpread,
}

impl RoundWord {
    pub fn new(dense_halves: RoundWordDense, spread_halves: RoundWordSpread) -> Self {
        RoundWord {
            dense_halves,
            spread_halves,
        }
    }
}

/// Internal state for RIPEMD160
#[derive(Debug, Clone)]
pub struct State {
    a: Option<StateWord>,
    b: Option<StateWord>,
    c: Option<StateWord>,
    d: Option<StateWord>,
    e: Option<StateWord>,
}

impl State {
    pub fn new(a: StateWord, b: StateWord, c: StateWord, d: StateWord, e: StateWord) -> Self {
        State {
            a: Some(a),
            b: Some(b),
            c: Some(c),
            d: Some(d),
            e: Some(e),
        }
    }

    pub fn empty_state() -> Self {
        State {
            a: None,
            b: None,
            c: None,
            d: None,
            e: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum StateWord {
    A(RoundWordDense),
    B(RoundWord),
    C(RoundWord),
    D(RoundWord),
    E(RoundWordDense),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoundSide {
    Left,
    Right,
}

#[derive(Debug, Clone)]
pub(super) struct CompressionConfig {
    lookup: SpreadInputs,
    advice: [Column<Advice>; NUM_ADVICE_COLS],

    s_decompose_word: Selector,
    s_f1: Selector,
    s_f2f4: Selector,
    s_f3f5: Selector,
    s_rotate_left: [Selector; 11], // Rotate left with shifts from 5 to 15(inclusive)
    s_sum_afxk: Selector,
    s_sum_re: Selector,
    s_sum_combine_ilr: Selector,
}

impl Table16Assignment for CompressionConfig {}

impl CompressionConfig {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        lookup: SpreadInputs,
        advice: [Column<Advice>; NUM_ADVICE_COLS],
        s_decompose_word: Selector,
    ) -> Self {
        todo!()
    }

    /// Initialize compression with a constant IV of 32-byte words.
    /// Returns an initialized state.
    pub(super) fn init_with_iv(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        init_state: [u32; DIGEST_SIZE],
    ) -> Result<State, Error> {
        let mut new_state = State::empty_state();
        layouter.assign_region(
            || "init_with_iv",
            |mut region| {
                new_state = self.init_iv(&mut region, init_state)?;
                Ok(())
            },
        )?;
        Ok(new_state)
    }

    /// Given an initialized state and a message schedule, perform 80 compression rounds.
    pub(super) fn compress(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        initialized_state: State,
        w_halves: [(AssignedBits<16>, AssignedBits<16>); BLOCK_SIZE],
    ) -> Result<State, Error> {
        let mut left_state = State::empty_state();
        let mut right_state = State::empty_state();
        let mut final_state = State::empty_state();

        layouter.assign_region(
            || "compress",
            |mut region| {
                let mut row: usize = 0;
                left_state = initialized_state.clone();
                right_state = initialized_state.clone();
                for idx in 0..ROUNDS {
                    left_state = self.assign_round(
                        &mut region,
                        idx,
                        left_state.clone(),
                        w_halves.clone(),
                        &mut row,
                        RoundSide::Left,
                    )?;
                    right_state = self.assign_round(
                        &mut region,
                        idx,
                        right_state.clone(),
                        w_halves.clone(),
                        &mut row,
                        RoundSide::Right,
                    )?;
                }
                final_state = self.assign_combine_ilr(
                    &mut region,
                    initialized_state.clone(),
                    left_state.clone(),
                    right_state.clone(),
                    &mut row,
                )?;
                Ok(())
            },
        )?;
        Ok(final_state)
    }

    /// After the final round, convert the state into the final digest.
    pub(super) fn digest(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: State,
    ) -> Result<[BlockWord; DIGEST_SIZE], Error> {
        let mut digest = [BlockWord(Value::known(0)); DIGEST_SIZE];
        layouter.assign_region(
            || "digest",
            |mut region| {
                digest = self.assign_digest(&mut region, state.clone())?;
                Ok(())
            },
        )?;

        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::circuit::Value;
    use halo2_proofs::halo2curves::pasta::pallas;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    use crate::constants::{BLOCK_SIZE, BLOCK_SIZE_BYTES, DIGEST_SIZE, INITIAL_VALUES};
    use crate::ref_impl::{hash, pad_message_bytes};
    use crate::table16::util::convert_byte_slice_to_u32_slice;
    use crate::table16::{AssignedBits, BlockWord, Table16Chip, Table16Config};

    #[test]
    fn test_compression() {
        struct MyCircuit {}

        impl Circuit<pallas::Base> for MyCircuit {
            type Config = Table16Config;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {}
            }

            fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
                Table16Chip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                Table16Chip::load(config.clone(), &mut layouter)?;

                // Test vector: "abc"
                let input_bytes = b"abc";
                let input: [u32; BLOCK_SIZE] =
                    convert_byte_slice_to_u32_slice::<BLOCK_SIZE_BYTES, BLOCK_SIZE>(
                        pad_message_bytes(input_bytes.to_vec())[0],
                    );
                let output: [u32; DIGEST_SIZE] =
                    convert_byte_slice_to_u32_slice(hash(input_bytes.to_vec()));

                let (_, w_halves) = config
                    .message_schedule
                    .process(&mut layouter, input.map(|x| BlockWord(Value::known(x))))?;

                let compression = config.compression.clone();
                let initial_state = compression.init_with_iv(&mut layouter, INITIAL_VALUES)?;

                let state = config
                    .compression
                    .compress(&mut layouter, initial_state, w_halves)?;
                let (a, b, c, d, e) = match_state(state.clone());

                let a_3 = config.compression.advice[0];
                let a_4 = config.compression.advice[1];
                let a_5 = config.compression.advice[2];

                layouter.assign_region(
                    || "check digest",
                    |mut region| {
                        let mut row: usize = 0;
                        config
                            .compression
                            .s_decompose_word
                            .enable(&mut region, row)?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected_a_lo",
                            a_3,
                            row,
                            a.0.value_u16(),
                        )?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected_a_hi",
                            a_4,
                            row,
                            a.1.value_u16(),
                        )?;
                        AssignedBits::<32>::assign(
                            &mut region,
                            || "actual a",
                            a_5,
                            row,
                            Value::known(output[row]),
                        )?;

                        row += 1;
                        config
                            .compression
                            .s_decompose_word
                            .enable(&mut region, row)?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected_b_lo",
                            a_3,
                            row,
                            b.dense_halves.0.value_u16(),
                        )?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected_b_hi",
                            a_4,
                            row,
                            b.dense_halves.1.value_u16(),
                        )?;
                        AssignedBits::<32>::assign(
                            &mut region,
                            || "actual b",
                            a_5,
                            row,
                            Value::known(output[row]),
                        )?;

                        row += 1;
                        config
                            .compression
                            .s_decompose_word
                            .enable(&mut region, row)?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected c_lo",
                            a_3,
                            row,
                            c.dense_halves.0.value_u16(),
                        )?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected c_hi",
                            a_4,
                            row,
                            c.dense_halves.1.value_u16(),
                        )?;
                        AssignedBits::<32>::assign(
                            &mut region,
                            || "actual c",
                            a_5,
                            row,
                            Value::known(output[row]),
                        )?;

                        row += 1;
                        config
                            .compression
                            .s_decompose_word
                            .enable(&mut region, row)?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected d_lo",
                            a_3,
                            row,
                            d.dense_halves.0.value_u16(),
                        )?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected d_hi",
                            a_4,
                            row,
                            d.dense_halves.1.value_u16(),
                        )?;
                        AssignedBits::<32>::assign(
                            &mut region,
                            || "actual d",
                            a_5,
                            row,
                            Value::known(output[row]),
                        )?;

                        row += 1;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected e_lo",
                            a_3,
                            row,
                            e.0.value_u16(),
                        )?;
                        AssignedBits::<16>::assign(
                            &mut region,
                            || "expected e_hi",
                            a_4,
                            row,
                            e.1.value_u16(),
                        )?;
                        AssignedBits::<32>::assign(
                            &mut region,
                            || "actual e",
                            a_5,
                            row,
                            Value::known(output[row]),
                        )?;

                        Ok(())
                    },
                )?;

                let digest = config.compression.digest(&mut layouter, state)?;
                for (idx, digest_word) in digest.iter().enumerate() {
                    digest_word.0.assert_if_known(|v| *v == output[idx]);
                }

                Ok(())
            }
        }

        let circuit: MyCircuit = MyCircuit {};

        let prover = match MockProver::<pallas::Base>::run(17, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
