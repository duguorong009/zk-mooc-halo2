use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Constraints, Expression},
};
use std::marker::PhantomData;

use crate::table16::{gates::Gate, util::MASK_EVEN_32};

pub struct CompressionGate<F: FieldExt>(PhantomData<F>);

impl<F: FieldExt> CompressionGate<F> {
    fn ones() -> Expression<F> {
        Expression::Constant(F::one())
    }

    // Gate for B ^ C ^ D; XOR of three 32 bit words
    // Output is in R_0_even, R_1_even
    //
    // s_f1 | a_0 |   a_1    |       a_2       |    a_3      |    a_4      |    a_5      |
    //   1  |     | R_0_even | spread_R_0_even | spread_B_lo | spread_C_lo | spread_D_lo |
    //      |     | R_0_odd  | spread_R_0_odd  | spread_B_hi | spread_C_hi | spread_D_hi |
    //      |     | R_1_even | spread_R_1_even |             |             |             |
    //      |     | R_1_odd  | spread_R_1_odd  |             |             |             |
    //
    pub fn f1_gate(
        s_f1: Expression<F>,
        spread_r0_even: Expression<F>,
        spread_r0_odd: Expression<F>,
        spread_r1_even: Expression<F>,
        spread_r1_odd: Expression<F>,
        spread_b_lo: Expression<F>,
        spread_b_hi: Expression<F>,
        spread_c_lo: Expression<F>,
        spread_c_hi: Expression<F>,
        spread_d_lo: Expression<F>,
        spread_d_hi: Expression<F>,
    ) -> Option<(&'static str, Expression<F>)> {
        let xor_even = spread_r0_even + spread_r1_even * F::from(1 << 32);
        let xor_odd = spread_r0_odd + spread_r1_odd * F::from(1 << 32);
        let xor = xor_even + xor_odd * F::from(2);

        let b = spread_b_lo + spread_b_hi * F::from(1 << 32);
        let c = spread_c_lo + spread_c_hi * F::from(1 << 32);
        let d = spread_d_lo + spread_d_hi * F::from(1 << 32);

        let sum = b + c + d;

        Some(("maj", s_f1 * (sum - xor)))
    }

    // Gate for f2(B, C, D) = (B & C) | (!B & D)
    // Used also for f4
    // f4(B, C, D) = (B & D) | (C & !D)
    // Output is in sum_lo, sum_hi
    //
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
    // Output is sum_lo, sum_hi
    pub fn f2_gate(
        s_f2f4: Expression<F>,
        spread_p0_even: Expression<F>,
        spread_p0_odd: Expression<F>,
        spread_p1_even: Expression<F>,
        spread_p1_odd: Expression<F>,
        p0_odd: Expression<F>,
        p1_odd: Expression<F>,
        spread_q0_even: Expression<F>,
        spread_q0_odd: Expression<F>,
        spread_q1_even: Expression<F>,
        spread_q1_odd: Expression<F>,
        q0_odd: Expression<F>,
        q1_odd: Expression<F>,
        spread_b_lo: Expression<F>,
        spread_b_hi: Expression<F>,
        spread_c_lo: Expression<F>,
        spread_c_hi: Expression<F>,
        spread_d_lo: Expression<F>,
        spread_d_hi: Expression<F>,
        spread_b_neg_lo: Expression<F>,
        spread_b_neg_hi: Expression<F>,
        sum_lo: Expression<F>,
        sum_hi: Expression<F>,
        carry: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let p_lhs_lo = spread_b_lo.clone() + spread_c_lo;
        let p_lhs_hi = spread_b_hi.clone() + spread_c_hi;
        let p_lhs = p_lhs_lo + p_lhs_hi * F::from(1 << 32);

        let p_rhs_even = spread_p0_even + spread_p1_even * F::from(1 << 32);
        let p_rhs_odd = spread_p0_odd.clone() + spread_p1_odd.clone() * F::from(1 << 32);
        let p_rhs = p_rhs_even + p_rhs_odd * F::from(2);

        let p_check = p_lhs + p_rhs * -F::one();

        let neg_check = {
            let evens = Self::ones() * F::from(MASK_EVEN_32 as u64);
            // evens - spread_x_lo = spread_neg_x_lo
            let lo_check = spread_b_neg_lo.clone() + spread_b_lo + (evens.clone()) * (-F::one());
            // evens - spread_x_hi = spread_neg_x_hi
            let hi_check = spread_b_neg_hi.clone() + spread_b_hi + (evens * (-F::one()));

            std::iter::empty()
                .chain(Some(("lo_check", lo_check)))
                .chain(Some(("hi_check", hi_check)))
        };

        let q_lhs_lo = spread_b_neg_lo + spread_b_lo;
        let q_lhs_hi = spread_b_neg_hi + spread_b_hi;
        let q_lhs = q_lhs_lo + q_lhs_hi * F::from(1 << 32);

        let q_rhs_even = spread_q0_even + spread_q1_even * F::from(1 << 32);
        let q_rhs_odd = spread_q0_odd.clone() + spread_q1_odd.clone() * F::from(1 << 32);
        let q_rhs = q_rhs_even + q_rhs_odd * F::from(2);

        let q_check = q_lhs + q_rhs * -F::one();

        let range_check_carry = Gate::range_check(carry.clone(), 0, 0);

        let lo = p0_odd + q0_odd;
        let hi = p1_odd + q1_odd;
        let sum = lo + hi * F::from(1 << 16);
        let mod_sum = sum_lo + sum_hi * F::from(1 << 16);

        let sum_check = sum - (carry * F::from(1 << 32)) - mod_sum;

        Constraints::with_selector(
            s_f2f4,
            std::itr::empty()
                .chain(neg_check)
                .chain(Some(("p_check", p_check)))
                .chain(Some(("q_check", q_check)))
                .chain(Some(("sum_f2f4", sum_check)))
                .chain(Some(("range_check_carry", range_check_carry))),
        )
    }

    // Gate for (X | !Y ) ^ Z
    // Used in both f3 and f5
    // f3(X, Y, Z) = (X | !Y ) ^ Z
    // f5(X, Y, Z) = X ^ (Y | !Z)
    // Output is in R_0_even, R_1_even
    //
    // s_f3f5 | a_0 |   a_1       |       a_2         |    a_3          |    a_4      |    a_5      |
    //   1    |     | sum_0_even  | spread_sum_0_even | spread_neg_Y_lo | spread_X_lo | spread_Y_lo |
    //        |     | sum_0_odd   | spread_sum_0_odd  | spread_neg_Y_hi | spread_X_hi | spread_Y_hi |
    //        |     | sum_1_even  | spread_sum_1_even |                 |             |             |
    //        |     | sum_1_odd   | spread_sum_1_odd  |                 |             |             |
    //        |     | or_lo       | spread_or_lo      | spread_Z_lo     |             |             |
    //        |     | or_hi       | spread_or_hi      | spread_Z_hi     |             |             |
    //        |     | R_0_even    | spread_R_0_even   |                 |             |             |
    //        |     | R_0_odd     | spread_R_0_odd    |                 |             |             |
    //        |     | R_1_even    | spread_R_1_even   |                 |             |             |
    //        |     | R_1_odd     | spread_R_1_odd    |                 |             |             |
    pub fn f3_gate(
        s_f3f5: Expression<F>,
        spread_r0_even: Expression<F>,
        spread_r0_odd: Expression<F>,
        spread_r1_even: Expression<F>,
        spread_r1_odd: Expression<F>,
        spread_or_lo: Expression<F>,
        spread_or_hi: Expression<F>,
        spread_sum0_even: Expression<F>,
        spread_sum0_odd: Expression<F>,
        spread_sum1_even: Expression<F>,
        spread_sum1_odd: Expression<F>,
        spread_x_lo: Expression<F>,
        spread_x_hi: Expression<F>,
        spread_y_lo: Expression<F>,
        spread_y_hi: Expression<F>,
        spread_y_neg_lo: Expression<F>,
        spread_y_neg_hi: Expression<F>,
        spread_z_lo: Expression<F>,
        spread_z_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let checks = {
            let evens = Self::ones() * F::from(MASK_EVEN_32 as u64);
            // evens - spread_y_lo = spread_y_neg_lo
            let lo_check = spread_y_neg_lo.clone() + spread_y_lo + (evens.clone() * (-F::one()));
            // evens - spread_y_hi = spread_y_neg_hi
            let hi_check = spread_y_neg_hi.clone() + spread_y_hi + (evens * (-F::one()));

            std::iter::empty()
                .chain(Some(("y_lo_check", lo_check)))
                .chain(Some(("y_hi_check", hi_check)))
        };

        // X + !Y
        let sum_lhs_lo = spread_x_lo + spread_y_neg_lo;
        let sum_lhs_hi = spread_x_hi + spread_y_neg_hi;
        let sum_lhs = sum_lhs_lo + sum_lhs_hi * F::from(1 << 32);

        let sum_rhs_even = spread_sum0_even.clone() + spread_sum1_even.clone() * F::from(1 << 32);
        let sum_rhs_odd = spread_sum0_odd.clone() + spread_sum1_odd.clone() * F::from(1 << 32);
        let sum_rhs = sum_rhs_even + sum_rhs_odd * F::from(2);

        // X | !Y
        // OR gate output is obtained as the sum of the spread versions of even and odd parts of X + !Y
        let or_lhs_lo = spread_sum0_even + spread_sum0_odd;
        let or_lhs_hi = spread_sum1_even + spread_sum1_odd;
        let or_lhs = or_lhs_lo + or_lhs_hi * F::from(1 << 32);

        let or_rhs = spread_or_lo.clone() + spread_or_hi.clone() * F::from(1 << 32);

        let xor_even = spread_r0_even + spread_r1_even * F::from(1 << 32);
        let xor_odd = spread_r0_odd + spread_r1_odd * F::from(1 << 32);
        let xor = xor_even + xor_odd * F::from(2);

        let or = spread_or_lo + spread_or_hi * F::from(1 << 32);
        let z = spread_z_lo + spread_z_hi * F::from(1 << 32);
        let sum = or + z;

        Constraints::with_selector(
            s_f3f5,
            checks
                .chain(Some(("sum_x_not_y", sum_lhs - sum_rhs)))
                .chain(Some(("or_x_not_y", or_lhs - or_rhs)))
                .chain(Some(("or_x_not_y_xor_z", sum - xor))),
        )
    }

    // Gate for rotate_left(W, 5)
    // word = (a,b,c) = (5, 11, 16) chunks with a = (a_hi, a_lo) = (3, 2) chunks
    pub fn rotate_left_5_gate(
        s_rotate_left_5: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_5_word_lo: Expression<F>,
        rol_5_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 3); // tag <= 3 => b < 2^11
        let range_check_a_lo = Gate::two_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::three_bit_range(a_hi.clone());

        let word_check = c.clone()
            + b.clone() * F::from(1 << 16)
            + a_lo.clone() * F::from(1 << 27)
            + a_hi.clone() * F::from(1 << 29)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_5_word_check = a_lo
            + a_hi * F::from(1 << 2)
            + c * F::from(1 << 5)
            + b * F::from(1 << 21)
            + rol_5_word_lo * (-F::one())
            + rol_5_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_5,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_5_word_check", rol_5_word_check))),
        )
    }

    // Gate for rotate_left(W, 6)
    // word = (a,b,c) = (6, 10, 16) chunks with a = (a_hi, a_lo) = (3, 3) chunks
    pub fn rotate_left_6_gate(
        s_rotate_left_6: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_6_word_lo: Expression<F>,
        rol_6_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 2); // tag <= 2 => b < 2^10
        let range_check_a_lo = Gate::three_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::three_bit_range(a_hi.clone());

        let word_check = c.clone()
            + b.clone() * F::from(1 << 16)
            + a_lo.clone() * F::from(1 << 26)
            + a_hi.clone() * F::from(1 << 29)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_6_word_check = a_lo
            + a_hi * F::from(1 << 3)
            + c * F::from(1 << 6)
            + b * F::from(1 << 22)
            + rol_6_word_lo * (-F::one())
            + rol_6_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_6,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_6_word_check", rol_6_word_check))),
        )
    }

    // Gate for rotate_left(W, 7)
    // word = (a,b,c) = (7, 9, 16) chunks with a = (a_hi, a_lo) = (4, 3) chunks
    pub fn rotate_left_7_gate(
        s_rotate_left_7: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_7_word_lo: Expression<F>,
        rol_7_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 1); // tag <= 1 => b < 2^9
        let range_check_a_lo = Gate::three_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::four_bit_range(a_hi.clone());

        let word_check = c.clone()
            + b.clone() * F::from(1 << 16)
            + a_lo.clone() * F::from(1 << 25)
            + a_hi.clone() * F::from(1 << 28)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_7_word_check = a_lo
            + a_hi * F::from(1 << 3)
            + c * F::from(1 << 7)
            + b * F::from(1 << 23)
            + rol_7_word_lo * (-F::one())
            + rol_7_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_7,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_7_word_check", rol_7_word_check))),
        )
    }

    // Gate for rotate_left(W, 8)
    // word = (a,b,c) = (8, 8, 16) chunks with a = (a_hi, a_lo) = (4, 4) chunks
    pub fn rotate_left_8_gate(
        s_rotate_left_8: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_8_word_lo: Expression<F>,
        rol_8_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 0); // tag = 0 => b < 2^8
        let range_check_a_lo = Gate::four_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::four_bit_range(a_hi.clone());

        let word_check = c.clone()
            + b.clone() * F::from(1 << 16)
            + a_lo.clone() * F::from(1 << 24)
            + a_hi.clone() * F::from(1 << 28)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_8_word_check = a_lo
            + a_hi * F::from(1 << 4)
            + c * F::from(1 << 8)
            + b * F::from(1 << 24)
            + rol_8_word_lo * (-F::one())
            + rol_8_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_8,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_8_word_check", rol_8_word_check))),
        )
    }

    // Gate for rotate_left(W, 9)
    // word = (a,b,c) = (9, 7, 16) chunks with b = (b_hi, b_lo) = (4, 3) chunks
    pub fn rotate_left_9_gate(
        s_rotate_left_9: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_9_word_lo: Expression<F>,
        rol_9_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 1); // tag <= 1 => a < 2^9
        let range_check_b_lo = Gate::three_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::four_bit_range(b_hi.clone());

        let word_check = c.clone()
            + b_lo.clone() * F::from(1 << 16)
            + b_hi.clone() * F::from(1 << 19)
            + a.clone() * F::from(1 << 23)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_9_word_check = a
            + c * F::from(1 << 9)
            + b_lo * F::from(1 << 25)
            + b_hi * F::from(1 << 28)
            + rol_9_word_lo * (-F::one())
            + rol_9_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_9,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_9_word_check", rol_9_word_check))),
        )
    }

    // Gate for rotate_left(W, 10)
    // word = (a,b,c) = (10, 6, 16) chunks with b = (b_hi, b_lo) = (3, 3) chunks
    pub fn rotate_left_10_gate(
        s_rotate_left_10: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_10_word_lo: Expression<F>,
        rol_10_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 2); // tag <= 2 => a < 2^10
        let range_check_b_lo = Gate::three_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::three_bit_range(b_hi.clone());

        let word_check = c.clone()
            + b_lo.clone() * F::from(1 << 16)
            + b_hi.clone() * F::from(1 << 19)
            + a.clone() * F::from(1 << 22)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_10_word_check = a
            + c * F::from(1 << 10)
            + b_lo * F::from(1 << 26)
            + b_hi * F::from(1 << 29)
            + rol_10_word_lo * (-F::one())
            + rol_10_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_10,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_10_word_check", rol_10_word_check))),
        )
    }

    // Gate for rotate_left(W, 11)
    // word = (a,b,c) = (11, 5, 16) chunks with b = (b_hi, b_lo) = (3, 2) chunks
    pub fn rotate_left_11_gate(
        s_rotate_left_11: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_11_word_lo: Expression<F>,
        rol_11_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 3); // tag <= 3 => a < 2^11
        let range_check_b_lo = Gate::two_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::three_bit_range(b_hi.clone());

        let word_check = c.clone()
            + b_lo.clone() * F::from(1 << 16)
            + b_hi.clone() * F::from(1 << 18)
            + a.clone() * F::from(1 << 21)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_11_word_check = a
            + c * F::from(1 << 11)
            + b_lo * F::from(1 << 27)
            + b_hi * F::from(1 << 29)
            + rol_11_word_lo * (-F::one())
            + rol_11_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_11,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_11_word_check", rol_11_word_check))),
        )
    }

    // Gate for rotate_left(W, 12)
    // word = (a,b,c) = (12, 4, 16) chunks with b = (b_hi, b_lo) = (2, 2) chunks
    pub fn rotate_left_12_gate(
        s_rotate_left_12: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_12_word_lo: Expression<F>,
        rol_12_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 4); // tag <= 4 => a < 2^12
        let range_check_b_lo = Gate::two_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::two_bit_range(b_hi.clone());

        let word_check = c.clone()
            + b_lo.clone() * F::from(1 << 16)
            + b_hi.clone() * F::from(1 << 18)
            + a.clone() * F::from(1 << 20)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_12_word_check = a
            + c * F::from(1 << 12)
            + b_lo * F::from(1 << 28)
            + b_hi * F::from(1 << 30)
            + rol_12_word_lo * (-F::one())
            + rol_12_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_12,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_12_word_check", rol_12_word_check))),
        )
    }

    // Gate for rotate_left(W, 13)
    // word = (a,b,c) = (13, 3, 16) chunks
    pub fn rotate_left_13_gate(
        s_rotate_left_13: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_13_word_lo: Expression<F>,
        rol_13_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 5); // tag <= 5 => a < 2^13
        let range_check_b = Gate::three_bit_range(b.clone());

        let word_check = c.clone()
            + b.clone() * F::from(1 << 16)
            + a.clone() * F::from(1 << 19)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_13_word_check = a
            + c * F::from(1 << 13)
            + b * F::from(1 << 29)
            + rol_13_word_lo * (-F::one())
            + rol_13_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_13,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_13_word_check", rol_13_word_check))),
        )
    }

    // Gate for rotate_left(W, 14)
    // word = (a,b,c) = (14, 2, 16) chunks
    pub fn rotate_left_14_gate(
        s_rotate_left_14: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_14_word_lo: Expression<F>,
        rol_14_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 6); // tag <= 6 => a < 2^14
        let range_check_b = Gate::two_bit_range(b.clone());

        let word_check = c.clone()
            + b.clone() * F::from(1 << 16)
            + a.clone() * F::from(1 << 18)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_14_word_check = a
            + c * F::from(1 << 14)
            + b * F::from(1 << 30)
            + rol_14_word_lo * (-F::one())
            + rol_14_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_14,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_14_word_check", rol_14_word_check))),
        )
    }

    // Gate for rotate_left(W, 14)
    // word = (a,b,c) = (15, 1, 16) chunks
    pub fn rotate_left_15_gate(
        s_rotate_left_15: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_15_word_lo: Expression<F>,
        rol_15_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 7); // tag <= 7 => a < 2^15
        let range_check_b = Gate::range_check(b.clone(), 0, 1);

        let word_check = c.clone()
            + b.clone() * F::from(1 << 16)
            + a.clone() * F::from(1 << 17)
            + word_lo * (-F::one())
            + word_hi * F::from(1 << 16) * (-F::one());

        let rol_15_word_check = a
            + c * F::from(1 << 15)
            + b * F::from(1 << 31)
            + rol_15_word_lo * (-F::one())
            + rol_15_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_15,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(Some(("range_check_b", range_check_b)))
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_15_word_check", rol_15_word_check))),
        )
    }

    // Gate for  A + f(j, B, C, D) + X[r[j]] + K[j]  where r is the rotate amount array
    pub fn sum_afxk_gate(
        s_sum_afxk: Expression<F>,
        sum_lo: Expression<F>,
        sum_hi: Expression<F>,
        carry: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        f_lo: Expression<F>,
        f_hi: Expression<F>,
        x_lo: Expression<F>,
        x_hi: Expression<F>,
        k_lo: Expression<F>,
        k_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let range_check_carry = Gate::range_check(carry.clone(), 0, 2);

        let lo = a_lo + f_lo + x_lo + k_lo;
        let hi = a_hi + f_hi + x_hi + k_hi;
        let sum = lo + hi * F::from(1 << 16);
        let mod_sum = sum_lo + sum_hi * F::from(1 << 16);

        let sum_check = sum - (carry * F::from(1 << 32)) - mod_sum;

        Constraints::with_selector(
            s_sum_afxk,
            std::iter::empty()
                .chain(Some(("range_check_carry", range_check_carry)))
                .chain(Some(("sum_afxk", sum_check))),
        )
    }

    // Gate for T = rol + E  where rol is
    // the rotated version of A + f(j, B,C,D) + X[r[j]] + K[j]
    pub fn sum_re_gate(
        s_sum_re: Expression<F>,
        sum_lo: Expression<F>,
        sum_hi: Expression<F>,
        carry: Expression<F>,
        rol_lo: Expression<F>,
        rol_hi: Expression<F>,
        e_lo: Expression<F>,
        e_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let range_check_carry = Gate::range_check(carry.clone(), 0, 1);

        let lo = rol_lo + e_lo;
        let hi = rol_hi + e_hi;
        let sum = lo + hi * F::from(1 << 16);
        let mod_sum = sum_lo + sum_hi * F::from(1 << 16);

        let sum_check = sum - (carry * F::from(1 << 32)) - mod_sum;

        Constraints::with_selector(
            s_sum_re,
            std::iter::empty()
                .chain(Some(("range_check_carry", range_check_carry)))
                .chain(Some(("sum_re", sum_check))),
        )
    }

    // Gate for combining the initial, left, and right states of RIPEMD160
    // after the 80 rounds
    pub fn sum_combine_ilr(
        s_sum_re: Expression<F>,
        sum_lo: Expression<F>,
        sum_hi: Expression<F>,
        carry: Expression<F>,
        init_state_lo: Expression<F>,
        init_state_hi: Expression<F>,
        left_state_lo: Expression<F>,
        left_state_hi: Expression<F>,
        right_state_lo: Expression<F>,
        right_state_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let range_check_carry = Gate::range_check(carry.clone(), 0, 1);

        let lo = init_state_lo + left_state_lo + right_state_lo;
        let hi = init_state_hi + left_state_hi + right_state_hi;
        let sum = lo + hi * F::from(1 << 16);
        let mod_sum = sum_lo + sum_hi * F::from(1 << 16);

        let sum_check = sum - (carry * F::from(1 << 32)) - mod_sum;

        Constraints::with_selector(
            s_sum_re,
            std::iter::empty()
                .chain(Some(("range_check_carry", range_check_carry)))
                .chain(Some(("sum_re", sum_check))),
        )
    }
}
