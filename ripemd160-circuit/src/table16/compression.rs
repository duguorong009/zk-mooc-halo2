use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    constants::{BLOCK_SIZE, DIGEST_SIZE, ROUNDS},
    table16::{compression::compression_gates::CompressionGate, gates::Gate},
};

use super::{
    spread_table::SpreadInputs, AssignedBits, BlockWord, Table16Assignment, NUM_ADVICE_COLS,
};

mod compression_gates;
mod compression_util;
mod subregion_digest;
mod subregion_initial;
mod subregion_main;

#[derive(Debug, Clone)]
pub struct RoundWordDense<F: FieldExt>(AssignedBits<16, F>, AssignedBits<16, F>);

impl<F: FieldExt> From<(AssignedBits<16, F>, AssignedBits<16, F>)> for RoundWordDense<F> {
    fn from(halves: (AssignedBits<16, F>, AssignedBits<16, F>)) -> Self {
        Self(halves.0, halves.1)
    }
}

impl<F: FieldExt> RoundWordDense<F> {
    pub fn value(&self) -> Value<u32> {
        self.0
            .value_u16()
            .zip(self.1.value_u16())
            .map(|(lo, hi)| lo as u32 + (1 << 16) * hi as u32)
    }
}

#[derive(Debug, Clone)]
pub struct RoundWordSpread<F: FieldExt>(AssignedBits<32, F>, AssignedBits<32, F>);

impl<F: FieldExt> From<(AssignedBits<32, F>, AssignedBits<32, F>)> for RoundWordSpread<F> {
    fn from(halves: (AssignedBits<32, F>, AssignedBits<32, F>)) -> Self {
        Self(halves.0, halves.1)
    }
}

impl<F: FieldExt> RoundWordSpread<F> {
    pub fn value(&self) -> Value<u64> {
        self.0
            .value_u32()
            .zip(self.1.value_u32())
            .map(|(lo, hi)| lo as u64 + (1 << 32) * hi as u64)
    }
}

#[derive(Debug, Clone)]
pub struct RoundWord<F: FieldExt> {
    dense_halves: RoundWordDense<F>,
    spread_halves: RoundWordSpread<F>,
}

impl<F: FieldExt> RoundWord<F> {
    pub fn new(dense_halves: RoundWordDense<F>, spread_halves: RoundWordSpread<F>) -> Self {
        RoundWord {
            dense_halves,
            spread_halves,
        }
    }
}

/// Internal state for RIPEMD160
#[derive(Debug, Clone)]
pub struct State<F: FieldExt> {
    a: Option<StateWord<F>>,
    b: Option<StateWord<F>>,
    c: Option<StateWord<F>>,
    d: Option<StateWord<F>>,
    e: Option<StateWord<F>>,
}

impl<F: FieldExt> State<F> {
    pub fn new(
        a: StateWord<F>,
        b: StateWord<F>,
        c: StateWord<F>,
        d: StateWord<F>,
        e: StateWord<F>,
    ) -> Self {
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
pub enum StateWord<F: FieldExt> {
    A(RoundWordDense<F>),
    B(RoundWord<F>),
    C(RoundWord<F>),
    D(RoundWord<F>),
    E(RoundWordDense<F>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoundSide {
    Left,
    Right,
}

#[derive(Debug, Clone)]
pub(super) struct CompressionConfig<F: FieldExt> {
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

    _marker: PhantomData<F>,
}

impl<F: FieldExt> Table16Assignment<F> for CompressionConfig<F> {}

impl<F: FieldExt> CompressionConfig<F> {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<F>,
        lookup: SpreadInputs,
        advice: [Column<Advice>; NUM_ADVICE_COLS],
        s_decompose_word: Selector,
    ) -> Self {
        let s_f1 = meta.selector();
        let s_f2f4 = meta.selector();
        let s_f3f5 = meta.selector();
        let s_rotate_left = [
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
        ];
        let s_sum_afxk = meta.selector();
        let s_sum_re = meta.selector();
        let s_sum_combine_ilr = meta.selector();

        let a_0 = lookup.tag;
        let a_1 = lookup.dense;
        let a_2 = lookup.spread;
        let a_3 = advice[0];
        let a_4 = advice[1];
        let a_5 = advice[2];

        // s_decompose_word for all words
        // s_decompose_word  | a_0 |   a_1    |    a_2    |    a_3    |    a_4    |    a_5    |
        //         1         |     |          |           | lo        | hi        |  word     |
        //
        meta.create_gate("s_decompose_word", |meta| {
            let s_decompose_word = meta.query_selector(s_decompose_word);
            let lo = meta.query_advice(a_3, Rotation::cur());
            let hi = meta.query_advice(a_4, Rotation::cur());
            let word = meta.query_advice(a_5, Rotation::cur());

            Gate::s_decompose_word(s_decompose_word, lo, hi, word)
        });

        // s_f1 on b, c, d words
        // s_f1   | a_0 |   a_1    |       a_2       |    a_3       |    a_4      |    a_5           |
        //   1    |     |          | spread_r_0_even | spread_X_lo  | spread_Y_lo | spread_Z_lo      |
        //        |     |          | spread_r_0_odd  | spread_X_hi  | spread_Y_hi | spread_Z_hi      |
        //        |     |          | spread_r_1_even |              |             |                  |
        //        |     |          | spread_r_1_odd  |              |             |                  |
        //
        meta.create_gate("s_f1", |meta| {
            let s_f1 = meta.query_selector(s_f1);
            let spread_r0_even = meta.query_advice(a_2, Rotation(0));
            let spread_r0_odd = meta.query_advice(a_2, Rotation(1));
            let spread_r1_even = meta.query_advice(a_2, Rotation(2));
            let spread_r1_odd = meta.query_advice(a_2, Rotation(3));
            let spread_b_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_3, Rotation::next());
            let spread_c_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_c_hi = meta.query_advice(a_4, Rotation::next());
            let spread_d_lo = meta.query_advice(a_5, Rotation::cur());
            let spread_d_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::f1_gate(
                s_f1,
                spread_r0_even,
                spread_r0_odd,
                spread_r1_even,
                spread_r1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_c_lo,
                spread_c_hi,
                spread_d_lo,
                spread_d_hi,
            )
        });

        // s_f2 on b, c, d words
        // The f4 gate is the same as the f2 gate with arguments (D, B, C) instead of (B, C, D)
        // s_f2f4 | a_0 |   a_1    |       a_2       |    a_3       |    a_4      |    a_5           |
        //   1    |     | P_0_even | spread_P_0_even | spread_X_lo  | spread_Y_lo |                  |
        //        |     | P_0_odd  | spread_P_0_odd  | spread_X_hi  | spread_Y_hi |                  |
        //        |     | P_1_even | spread_P_1_even |              |             |                  |
        //        |     | P_1_odd  | spread_P_1_odd  |              |             |                  |
        //        |     | Q_0_even | spread_Q_0_even |              | spread_Z_lo | spread_neg_X_lo  |
        //        |     | Q_0_odd  | spread_Q_0_odd  |              | spread_Z_hi | spread_neg_X_hi  |
        //        |     | Q_1_even | spread_Q_1_even | sum_lo       | carry       |                  |
        //        |     | Q_1_odd  | spread_Q_1_odd  | sum_hi       |             |                  |
        //
        meta.create_gate("s_f2f4", |meta| {
            let s_f2f4 = meta.query_selector(s_f2f4);
            let spread_p0_even = meta.query_advice(a_2, Rotation(0));
            let spread_p0_odd = meta.query_advice(a_2, Rotation(1));
            let p0_odd = meta.query_advice(a_1, Rotation(1));
            let spread_p1_even = meta.query_advice(a_2, Rotation(2));
            let spread_p1_odd = meta.query_advice(a_2, Rotation(3));
            let p1_odd = meta.query_advice(a_1, Rotation(3));
            let spread_q0_even = meta.query_advice(a_2, Rotation(4));
            let spread_q0_odd = meta.query_advice(a_2, Rotation(5));
            let q0_odd = meta.query_advice(a_1, Rotation(5));
            let spread_q1_even = meta.query_advice(a_2, Rotation(6));
            let spread_q1_odd = meta.query_advice(a_2, Rotation(7));
            let q1_odd = meta.query_advice(a_1, Rotation(7));
            let spread_b_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_3, Rotation::next());
            let spread_c_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_c_hi = meta.query_advice(a_4, Rotation::next());
            let spread_d_lo = meta.query_advice(a_4, Rotation(4));
            let spread_d_hi = meta.query_advice(a_4, Rotation(5));
            let spread_b_neg_lo = meta.query_advice(a_5, Rotation(4));
            let spread_b_neg_hi = meta.query_advice(a_5, Rotation(5));
            let sum_lo = meta.query_advice(a_3, Rotation(6));
            let sum_hi = meta.query_advice(a_3, Rotation(7));
            let carry = meta.query_advice(a_4, Rotation(6));

            CompressionGate::f2_gate(
                s_f2f4,
                spread_p0_even,
                spread_p0_odd,
                spread_p1_even,
                spread_p1_odd,
                p0_odd,
                p1_odd,
                spread_q0_even,
                spread_q0_odd,
                spread_q1_even,
                spread_q1_odd,
                q0_odd,
                q1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_c_lo,
                spread_c_hi,
                spread_d_lo,
                spread_d_hi,
                spread_b_neg_lo,
                spread_b_neg_hi,
                sum_lo,
                sum_hi,
                carry,
            )
        });

        // s_f3 on b, c, d words
        // The f5 gate is the same as the f3 gate with arguments (C, D, B) instead of (B, C, D)
        // (b | !c) ^ d
        // s_f3f5 | a_0 |   a_1    |       a_2         |    a_3           |    a_4      |    a_5           |
        //   1    |     |          | spread_sum_0_even | spread_c_neg_lo  | spread_b_lo | spread_c_lo      |
        //        |     |          | spread_sum_0_odd  | spread_c_neg_hi  | spread_b_hi | spread_c_hi      |
        //        |     |          | spread_sum_1_even |                  |             |                  |
        //        |     |          | spread_sum_1_odd  |                  |             |                  |
        //        |     |          | spread_or_lo      | spread_d_lo      |             |                  |
        //        |     |          | spread_or_hi      | spread_d_hi      |             |                  |
        //        |     |          | spread_r_0_even   |                  |             |                  |
        //        |     |          | spread_r_0_odd    |                  |             |                  |
        //        |     |          | spread_r_1_even   |                  |             |                  |
        //        |     |          | spread_r_1_odd    |                  |             |                  |
        //
        meta.create_gate("s_f3f5", |meta| {
            let s_f3f5 = meta.query_selector(s_f3f5);
            let spread_sum0_even = meta.query_advice(a_2, Rotation(0));
            let spread_sum0_odd = meta.query_advice(a_2, Rotation(1));
            let spread_sum1_even = meta.query_advice(a_2, Rotation(2));
            let spread_sum1_odd = meta.query_advice(a_2, Rotation(3));
            let spread_or_lo = meta.query_advice(a_2, Rotation(4));
            let spread_or_hi = meta.query_advice(a_2, Rotation(5));
            let spread_r0_even = meta.query_advice(a_2, Rotation(6));
            let spread_r0_odd = meta.query_advice(a_2, Rotation(7));
            let spread_r1_even = meta.query_advice(a_2, Rotation(8));
            let spread_r1_odd = meta.query_advice(a_2, Rotation(9));
            let spread_c_neg_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_c_neg_hi = meta.query_advice(a_3, Rotation::next());
            let spread_b_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_4, Rotation::next());
            let spread_c_lo = meta.query_advice(a_5, Rotation::cur());
            let spread_c_hi = meta.query_advice(a_5, Rotation::next());
            let spread_d_lo = meta.query_advice(a_3, Rotation(4));
            let spread_d_hi = meta.query_advice(a_3, Rotation(5));

            CompressionGate::f3_gate(
                s_f3f5,
                spread_r0_even,
                spread_r0_odd,
                spread_r1_even,
                spread_r1_odd,
                spread_or_lo,
                spread_or_hi,
                spread_sum0_even,
                spread_sum0_odd,
                spread_sum1_even,
                spread_sum1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_c_lo,
                spread_c_hi,
                spread_c_neg_lo,
                spread_c_neg_hi,
                spread_d_lo,
                spread_d_hi,
            )
        });

        // rotate_left_5 on a, b, c words
        // s_rol5 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1    |  1  |  b       |        | a_lo       | word_lo     | rol_word_lo      |
        //        |     |  c       |        | a_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("rotate_left_5", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[0]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_5_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_6 on a, b, c words
        // s_rol6 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1    |  1  |  b       |        | a_lo       | word_lo     | rol_word_lo      |
        //        |     |  c       |        | a_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("rotate_left_6", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[1]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_6_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_7 on a, b, c words
        // s_rol7 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1    |  1  |  b       |        | a_lo       | word_lo     | rol_word_lo      |
        //        |     |  c       |        | a_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("rotate_left_7", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[2]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_7_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_8 on a, b, c words
        // s_rol8 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1    |  1  |  b       |        | a_lo       | word_lo     | rol_word_lo      |
        //        |     |  c       |        | a_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("rotate_left_8", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[3]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_8_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_9 on a, b, c words
        // s_rol9 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1    |  1  |  a       |        | b_lo       | word_lo     | rol_word_lo      |
        //        |     |  c       |        | b_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("s_rotate_left_9", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[4]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_9_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_10 on a, b, c words
        // s_rol10 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1     |  1  |  a       |        | b_lo       | word_lo     | rol_word_lo      |
        //         |     |  c       |        | b_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("s_rotate_left_10", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[5]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_10_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_11 on a, b, c words
        // s_rol11 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1     |  1  |  a       |        | b_lo       | word_lo     | rol_word_lo      |
        //         |     |  c       |        | b_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("s_rotate_left_11", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[6]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_11_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_12 on a, b, c words
        // s_rol12 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1     |  1  |  a       |        | b_lo       | word_lo     | rol_word_lo      |
        //         |     |  c       |        | b_hi       | word_hi     | rol_word_hi      |
        //
        meta.create_gate("s_rotate_left_12", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[7]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_12_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_13 on a, b, c words
        // s_rol13 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1     |  1  |  a       |        | b          | word_lo     | rol_word_lo      |
        //         |     |  c       |        |            | word_hi     | rol_word_hi      |
        //
        meta.create_gate("s_rotate_left_13", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[8]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b = meta.query_advice(a_3, Rotation::cur());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_13_gate(
                s_rotate_left,
                a,
                tag_a,
                b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_14 on a, b, c words
        // s_rol14 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1     |  1  |  a       |        | b          | word_lo     | rol_word_lo      |
        //         |     |  c       |        |            | word_hi     | rol_word_hi      |
        //
        meta.create_gate("s_rotate_left_14", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[9]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b = meta.query_advice(a_3, Rotation::cur());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_14_gate(
                s_rotate_left,
                a,
                tag_a,
                b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // rotate_left_15 on a, b, c words
        // s_rol15 | a_0 |   a_1    |   a_2  |    a_3     |    a_4      |    a_5           |
        //   1     |  1  |  a       |        | b          | word_lo     | rol_word_lo      |
        //         |     |  c       |        |            | word_hi     | rol_word_hi      |
        //
        meta.create_gate("s_rotate_left_15", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[10]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b = meta.query_advice(a_3, Rotation::cur());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());

            CompressionGate::rotate_left_15_gate(
                s_rotate_left,
                a,
                tag_a,
                b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        // s_sum_afxk
        // s_sum_afxk | a_0 |   a_1    |  a_2  |    a_3   |    a_4   |    a_5    |
        //   1        |     | sum_lo   |       | a_lo     | f_lo     | x_lo      |
        //            |     | sum_hi   |       | a_hi     | f_hi     | x_hi      |
        //            |     |          |       | k_lo     | k_hi     | carry     |
        //
        meta.create_gate("s_sum_afxk", |meta| {
            let s_sum_afxk = meta.query_selector(s_sum_afxk);
            let sum_lo = meta.query_advice(a_1, Rotation::cur());
            let sum_hi = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let f_lo = meta.query_advice(a_4, Rotation::cur());
            let f_hi = meta.query_advice(a_4, Rotation::next());
            let x_lo = meta.query_advice(a_5, Rotation::cur());
            let x_hi = meta.query_advice(a_5, Rotation::next());

            let k_lo = meta.query_advice(a_3, Rotation(2));
            let k_hi = meta.query_advice(a_4, Rotation(2));
            let carry = meta.query_advice(a_5, Rotation(2));

            CompressionGate::sum_afxk_gate(
                s_sum_afxk, sum_lo, sum_hi, carry, a_lo, a_hi, f_lo, f_hi, x_lo, x_hi, k_lo, k_hi,
            )
        });

        // s_sum_re
        // s_sum_re | a_0 |   a_1    |  a_2  |    a_3   |    a_4   |    a_5   |
        //   1      |     | sum_lo   |       | rol_lo   | e_lo     | carry    |
        //          |     | sum_hi   |       | rol_hi   | e_hi     |          |
        //
        meta.create_gate("s_sum_re", |meta| {
            let s_sum_re = meta.query_selector(s_sum_re);
            let sum_lo = meta.query_advice(a_1, Rotation::cur());
            let sum_hi = meta.query_advice(a_1, Rotation::next());
            let rol_lo = meta.query_advice(a_3, Rotation::cur());
            let rol_hi = meta.query_advice(a_3, Rotation::next());
            let e_lo = meta.query_advice(a_4, Rotation::cur());
            let e_hi = meta.query_advice(a_4, Rotation::next());
            let carry = meta.query_advice(a_5, Rotation::cur());

            CompressionGate::sum_re_gate(
                s_sum_re, sum_lo, sum_hi, carry, rol_lo, rol_hi, e_lo, e_hi,
            )
        });

        // s_sum_combine_ilr
        // s_sum_combine_ilr | a_0 |   a_1    |  a_2  |       a_3     |       a_4      |       a_5      |
        //   1               |     | sum_lo   |       | init_state_lo | left_state_lo  | right_state_lo |
        //                   |     | sum_hi   |       | init_state_hi | left_state_hi  | right_state_hi |
        //                   |     |          |       |               |                | carry          |
        //
        meta.create_gate("s_sum_combine_ilr", |meta| {
            let s_sum_ilr = meta.query_selector(s_sum_combine_ilr);
            let sum_lo = meta.query_advice(a_1, Rotation::cur());
            let sum_hi = meta.query_advice(a_1, Rotation::next());
            let init_state_lo = meta.query_advice(a_3, Rotation::cur());
            let init_state_hi = meta.query_advice(a_3, Rotation::next());
            let left_state_lo = meta.query_advice(a_4, Rotation::cur());
            let left_state_hi = meta.query_advice(a_4, Rotation::next());
            let right_state_lo = meta.query_advice(a_5, Rotation::cur());
            let right_state_hi = meta.query_advice(a_5, Rotation::next());
            let carry = meta.query_advice(a_3, Rotation(2));

            CompressionGate::sum_combine_ilr(
                s_sum_ilr,
                sum_lo,
                sum_hi,
                carry,
                init_state_lo,
                init_state_hi,
                left_state_lo,
                left_state_hi,
                right_state_lo,
                right_state_hi,
            )
        });

        CompressionConfig {
            lookup,
            advice,
            s_decompose_word,
            s_f1,
            s_f2f4,
            s_f3f5,
            s_rotate_left,
            s_sum_afxk,
            s_sum_re,
            s_sum_combine_ilr,
            _marker: PhantomData,
        }
    }

    /// Initialize compression with a constant IV of 32-byte words.
    /// Returns an initialized state.
    pub(super) fn init_with_iv(
        &self,
        layouter: &mut impl Layouter<F>,
        init_state: [u32; DIGEST_SIZE],
    ) -> Result<State<F>, Error> {
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
        layouter: &mut impl Layouter<F>,
        initialized_state: State<F>,
        w_halves: [(AssignedBits<16, F>, AssignedBits<16, F>); BLOCK_SIZE],
    ) -> Result<State<F>, Error> {
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
        layouter: &mut impl Layouter<F>,
        state: State<F>,
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
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::halo2curves::FieldExt;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    use crate::constants::{BLOCK_SIZE, BLOCK_SIZE_BYTES, DIGEST_SIZE, INITIAL_VALUES};
    use crate::ref_impl::{hash, pad_message_bytes};
    use crate::table16::compression::compression_util::match_state;
    use crate::table16::util::convert_byte_slice_to_u32_slice;
    use crate::table16::{AssignedBits, BlockWord, Table16Chip, Table16Config};

    #[test]
    fn test_compression() {
        struct MyCircuit {}

        impl<F: FieldExt> Circuit<F> for MyCircuit {
            type Config = Table16Config<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {}
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                Table16Chip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
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
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected_a_lo",
                            a_3,
                            row,
                            a.0.value_u16(),
                        )?;
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected_a_hi",
                            a_4,
                            row,
                            a.1.value_u16(),
                        )?;
                        AssignedBits::<32, F>::assign(
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
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected_b_lo",
                            a_3,
                            row,
                            b.dense_halves.0.value_u16(),
                        )?;
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected_b_hi",
                            a_4,
                            row,
                            b.dense_halves.1.value_u16(),
                        )?;
                        AssignedBits::<32, F>::assign(
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
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected c_lo",
                            a_3,
                            row,
                            c.dense_halves.0.value_u16(),
                        )?;
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected c_hi",
                            a_4,
                            row,
                            c.dense_halves.1.value_u16(),
                        )?;
                        AssignedBits::<32, F>::assign(
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
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected d_lo",
                            a_3,
                            row,
                            d.dense_halves.0.value_u16(),
                        )?;
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected d_hi",
                            a_4,
                            row,
                            d.dense_halves.1.value_u16(),
                        )?;
                        AssignedBits::<32, F>::assign(
                            &mut region,
                            || "actual d",
                            a_5,
                            row,
                            Value::known(output[row]),
                        )?;

                        row += 1;
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected e_lo",
                            a_3,
                            row,
                            e.0.value_u16(),
                        )?;
                        AssignedBits::<16, F>::assign(
                            &mut region,
                            || "expected e_hi",
                            a_4,
                            row,
                            e.1.value_u16(),
                        )?;
                        AssignedBits::<32, F>::assign(
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

        let prover = match MockProver::<Fr>::run(17, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
