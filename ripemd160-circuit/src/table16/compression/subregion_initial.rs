use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::Error,
};

use crate::constants::DIGEST_SIZE;
use crate::table16::Table16Assignment;

use super::{CompressionConfig, RoundWord, RoundWordDense, RoundWordSpread, State, StateWord};

impl<F: FieldExt> CompressionConfig<F> {
    pub fn init_iv(
        &self,
        region: &mut Region<'_, F>,
        iv: [u32; DIGEST_SIZE],
    ) -> Result<State<F>, Error> {
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];

        let mut row: usize = 0;
        self.s_decompose_word.enable(region, row)?;
        let (_, (a_lo, a_hi)) = self.assign_word_and_halves(
            || "assign iv[0]",
            region,
            &self.lookup,
            a_3,
            a_4,
            a_5,
            Value::known(iv[0]),
            row,
        )?;
        let a = RoundWordDense(a_lo.dense, a_hi.dense);

        row += 3;
        self.s_decompose_word.enable(region, row)?;
        let (_, (b_lo, b_hi)) = self.assign_word_and_halves(
            || "assign iv[1]",
            region,
            &self.lookup,
            a_3,
            a_4,
            a_5,
            Value::known(iv[1]),
            row,
        )?;
        let b = RoundWord {
            dense_halves: RoundWordDense(b_lo.dense, b_hi.dense),
            spread_halves: RoundWordSpread(b_lo.spread, b_hi.spread),
        };

        row += 3;
        self.s_decompose_word.enable(region, row)?;
        let (_, (c_lo, c_hi)) = self.assign_word_and_halves(
            || "assign iv[2]",
            region,
            &self.lookup,
            a_3,
            a_4,
            a_5,
            Value::known(iv[2]),
            row,
        )?;
        let c = RoundWord {
            dense_halves: RoundWordDense(c_lo.dense, c_hi.dense),
            spread_halves: RoundWordSpread(c_lo.spread, c_hi.spread),
        };

        row += 3;
        self.s_decompose_word.enable(region, row)?;
        let (_, (d_lo, d_hi)) = self.assign_word_and_halves(
            || "assign iv[3]",
            region,
            &self.lookup,
            a_3,
            a_4,
            a_5,
            Value::known(iv[3]),
            row,
        )?;
        let d = RoundWord {
            dense_halves: RoundWordDense(d_lo.dense, d_hi.dense),
            spread_halves: RoundWordSpread(d_lo.spread, d_hi.spread),
        };

        row += 3;
        self.s_decompose_word.enable(region, row)?;
        let (_, (e_lo, e_hi)) = self.assign_word_and_halves(
            || "assign iv[4]",
            region,
            &self.lookup,
            a_3,
            a_4,
            a_5,
            Value::known(iv[4]),
            row,
        )?;
        let e = RoundWordDense(e_lo.dense, e_hi.dense);

        Ok(State::new(
            StateWord::A(a),
            StateWord::B(b),
            StateWord::C(c),
            StateWord::D(d),
            StateWord::E(e),
        ))
    }
}
