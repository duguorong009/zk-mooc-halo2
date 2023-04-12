/*
Modified version of code from https://github.com/privacy-scaling-explorations/halo2/blob/8c945507ceca5f4ed6e52da3672ea0308bcac812/halo2_gadgets/src/sha256/table16/spread_table.rs
*/

use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
    poly::Rotation,
};

use crate::table16::util::{lebs2ip, spread_bits};

use super::AssignedBits;

const BITS_8: usize = 1 << 8;
const BITS_9: usize = 1 << 9;
const BITS_10: usize = 1 << 10;
const BITS_11: usize = 1 << 11;
const BITS_12: usize = 1 << 12;
const BITS_13: usize = 1 << 13;
const BITS_14: usize = 1 << 14;
const BITS_15: usize = 1 << 15;

/// An input word into a lookup, containing (tag, dense, spread)
#[derive(Copy, Clone, Debug)]
pub(super) struct SpreadWord<const DENSE: usize, const SPREAD: usize> {
    pub tag: u8,
    pub dense: [bool; DENSE],
    pub spread: [bool; SPREAD],
}

/// Helper function that returns tag of 16-bit input
pub fn get_tag(input: u16) -> u8 {
    let input = input as usize;
    if input < BITS_8 {
        0
    } else if input < BITS_9 {
        1
    } else if input < BITS_10 {
        2
    } else if input < BITS_11 {
        3
    } else if input < BITS_12 {
        4
    } else if input < BITS_13 {
        5
    } else if input < BITS_14 {
        6
    } else if input < BITS_15 {
        7
    } else {
        8
    }
}

impl<const DENSE: usize, const SPREAD: usize> SpreadWord<DENSE, SPREAD> {
    pub(super) fn new(dense: [bool; DENSE]) -> Self {
        assert!(DENSE <= 16);
        SpreadWord {
            tag: get_tag(lebs2ip(&dense) as u16),
            dense,
            spread: spread_bits(dense),
        }
    }

    pub(super) fn try_new<T: TryInto<[bool; DENSE]> + std::fmt::Debug>(dense: T) -> Self
    where
        <T as TryInto<[bool; DENSE]>>::Error: std::fmt::Debug,
    {
        assert!(DENSE <= 16);
        let dense: [bool; DENSE] = dense.try_into().unwrap();
        SpreadWord {
            tag: get_tag(lebs2ip(&dense) as u16),
            dense,
            spread: spread_bits(dense),
        }
    }
}

/// Variable stored in advice columns corresponding to a row of [`SpreadTableConfig`].
#[derive(Debug, Clone)]
pub(super) struct SpreadVar<const DENSE: usize, const SPREAD: usize, F: FieldExt> {
    pub tag: Value<u8>,
    pub dense: AssignedBits<DENSE, F>,
    pub spread: AssignedBits<SPREAD, F>,
}

impl<const DENSE: usize, const SPREAD: usize, F: FieldExt> SpreadVar<DENSE, SPREAD, F> {
    pub(super) fn with_lookup(
        region: &mut Region<'_, F>,
        cols: &SpreadInputs,
        row: usize,
        word: Value<SpreadWord<DENSE, SPREAD>>,
    ) -> Result<Self, Error> {
        let tag = word.map(|word| word.tag);
        let dense_val = word.map(|word| word.dense);
        let spread_val = word.map(|word| word.spread);

        region.assign_advice(
            || "tag",
            cols.tag,
            row,
            || tag.map(|tag| F::from(tag as u64)),
        )?;

        let dense =
            AssignedBits::<DENSE, F>::assign_bits(region, || "dense", cols.dense, row, dense_val)?;

        let spread = AssignedBits::<SPREAD, F>::assign_bits(
            region,
            || "spread",
            cols.spread,
            row,
            spread_val,
        )?;

        Ok(SpreadVar { tag, dense, spread })
    }

    pub(super) fn without_lookup(
        region: &mut Region<'_, F>,
        dense_col: Column<Advice>,
        dense_row: usize,
        spread_col: Column<Advice>,
        spread_row: usize,
        word: Value<SpreadWord<DENSE, SPREAD>>,
    ) -> Result<Self, Error> {
        let tag = word.map(|word| word.tag);
        let dense_val = word.map(|word| word.dense);
        let spread_val = word.map(|word| word.spread);

        let dense = AssignedBits::<DENSE, F>::assign_bits(
            region,
            || "dense",
            dense_col,
            dense_row,
            dense_val,
        )?;

        let spread = AssignedBits::<SPREAD, F>::assign_bits(
            region,
            || "spread",
            spread_col,
            spread_row,
            spread_val,
        )?;

        Ok(SpreadVar { tag, dense, spread })
    }
}

#[derive(Clone, Debug)]
pub(super) struct SpreadInputs {
    pub(super) tag: Column<Advice>,
    pub(super) dense: Column<Advice>,
    pub(super) spread: Column<Advice>,
}

#[derive(Clone, Debug)]
pub(super) struct SpreadTable {
    pub(super) tag: TableColumn,
    pub(super) dense: TableColumn,
    pub(super) spread: TableColumn,
}

#[derive(Clone, Debug)]
pub(super) struct SpreadTableConfig {
    pub input: SpreadInputs,
    pub table: SpreadTable,
}

#[derive(Debug, Clone)]
pub(super) struct SpreadTableChip<F: FieldExt> {
    config: SpreadTableConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for SpreadTableChip<F> {
    type Config = SpreadTableConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> SpreadTableChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        input_tag: Column<Advice>,
        input_dense: Column<Advice>,
        input_spread: Column<Advice>,
    ) -> <Self as Chip<F>>::Config {
        let table_tag = meta.lookup_table_column();
        let table_dense = meta.lookup_table_column();
        let table_spread = meta.lookup_table_column();

        meta.lookup("Bitlength lookup", |meta| {
            let tag_cur = meta.query_advice(input_tag, Rotation::cur());
            let dense_cur = meta.query_advice(input_dense, Rotation::cur());
            let spread_cur = meta.query_advice(input_spread, Rotation::cur());

            vec![
                (tag_cur, table_tag),
                (dense_cur, table_dense),
                (spread_cur, table_spread),
            ]
        });

        SpreadTableConfig {
            input: SpreadInputs {
                tag: input_tag,
                dense: input_dense,
                spread: input_spread,
            },
            table: SpreadTable {
                tag: table_tag,
                dense: table_dense,
                spread: table_spread,
            },
        }
    }

    pub fn load(
        config: SpreadTableConfig,
        layouter: &mut impl Layouter<F>,
    ) -> Result<<Self as Chip<F>>::Loaded, Error> {
        layouter.assign_table(
            || "spread table",
            |mut table| {
                // We generate the row values lazily (we only need them during keygen).
                let mut rows = SpreadTableConfig::generate::<F>();

                for index in 0..(1 << 16) {
                    let mut row = None;
                    table.assign_cell(
                        || "tag",
                        config.table.tag,
                        index,
                        || {
                            row = rows.next();
                            Value::known(row.map(|(tag, _, _)| tag).unwrap())
                        },
                    )?;
                    table.assign_cell(
                        || "dense",
                        config.table.dense,
                        index,
                        || Value::known(row.map(|(_, dense, _)| dense).unwrap()),
                    )?;
                    table.assign_cell(
                        || "spread",
                        config.table.spread,
                        index,
                        || Value::known(row.map(|(_, _, spread)| spread).unwrap()),
                    )?;
                }
                Ok(())
            },
        )
    }
}

impl SpreadTableConfig {
    fn generate<F: FieldExt>() -> impl Iterator<Item = (F, F, F)> {
        (1..=(1 << 16)).scan(
            (F::zero(), F::zero(), F::zero()),
            |(tag, dense, spread), i| {
                // We computed this table row in the previous iteration.
                let res = (*tag, *dense, *spread);

                // i holds the zero-indexed row number for the next table row.
                match i {
                    BITS_8 | BITS_9 | BITS_10 | BITS_11 | BITS_12 | BITS_13 | BITS_14 | BITS_15 => {
                        *tag += F::one()
                    }
                    _ => (),
                }
                *dense += F::one();
                if i & 1 == 0 {
                    // On even-numbered rows we recompute the spread.
                    *spread = F::zero();
                    for b in 0..16 {
                        if (i >> b) & 1 != 0 {
                            *spread += F::from(1 << (2 * b));
                        }
                    }
                } else {
                    // On odd-numbered rows we add one.
                    *spread += F::one();
                }
                Some(res)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        halo2curves::FieldExt,
        plonk::{Advice, Circuit, Column, Error},
    };

    use crate::table16::spread_table::{SpreadTableChip, SpreadTableConfig};

    #[test]
    fn lookup_table() {
        /// This represents an advice column at a certain row in the ConstraintSystem
        #[derive(Copy, Clone, Debug)]
        pub struct Variable(Column<Advice>, usize);

        struct MyCircuit {}

        impl<F: FieldExt> Circuit<F> for MyCircuit {
            type Config = SpreadTableConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {}
            }

            fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
                let input_tag = meta.advice_column();
                let input_dense = meta.advice_column();
                let input_spread = meta.advice_column();

                SpreadTableChip::configure(meta, input_tag, input_dense, input_spread)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl halo2_proofs::circuit::Layouter<F>,
            ) -> Result<(), halo2_proofs::plonk::Error> {
                SpreadTableChip::load(config.clone(), &mut layouter)?;

                layouter.assign_region(
                    || "spread_test",
                    |mut gate| {
                        let row = 0;
                        let mut add_row = |tag, dense, spread| -> Result<(), Error> {
                            gate.assign_advice(
                                || "tag",
                                config.input.tag,
                                row,
                                || Value::known(tag),
                            )?;
                            gate.assign_advice(
                                || "dense",
                                config.input.dense,
                                row,
                                || Value::known(dense),
                            )?;
                            gate.assign_advice(
                                || "spread",
                                config.input.spread,
                                row,
                                || Value::known(spread),
                            )?;

                            Ok(())
                        };

                        // Test the first few small values.
                        add_row(F::zero(), F::from(0b000), F::from(0b000000))?;
                        add_row(F::zero(), F::from(0b001), F::from(0b000001))?;
                        add_row(F::zero(), F::from(0b010), F::from(0b000100))?;
                        add_row(F::zero(), F::from(0b011), F::from(0b000101))?;
                        add_row(F::zero(), F::from(0b100), F::from(0b010000))?;
                        add_row(F::zero(), F::from(0b101), F::from(0b010001))?;

                        // Test the tag boundaries:
                        // 8-bit
                        add_row(
                            F::zero(),
                            F::from(0b1111_1111),
                            F::from(0b0101_0101_0101_0101),
                        )?;
                        add_row(
                            F::one(),
                            F::from(0b1_0000_0000),
                            F::from(0b01_0000_0000_0000_0000),
                        )?;
                        // 9-bit
                        add_row(
                            F::one(),
                            F::from(0b1_1111_1111),
                            F::from(0b01_0101_0101_0101_0101),
                        )?;
                        add_row(
                            F::from(2),
                            F::from(0b10_0000_0000),
                            F::from(0b0100_0000_0000_0000_0000),
                        )?;
                        // - 10-bit
                        add_row(
                            F::from(2),
                            F::from(0b11_1111_1111),
                            F::from(0b0101_0101_0101_0101_0101),
                        )?;
                        add_row(
                            F::from(3),
                            F::from(0b100_0000_0000),
                            F::from(0b01_0000_0000_0000_0000_0000),
                        )?;
                        // - 11-bit
                        add_row(
                            F::from(3),
                            F::from(0b111_1111_1111),
                            F::from(0b0101010101010101010101),
                        )?;
                        add_row(
                            F::from(4),
                            F::from(0b1000_0000_0000),
                            F::from(0b0100_0000_0000_0000_0000_0000),
                        )?;
                        // - 12-bit
                        add_row(
                            F::from(4),
                            F::from(0b1111_1111_1111),
                            F::from(0b0101_0101_0101_0101_0101_0101),
                        )?;
                        add_row(
                            F::from(5),
                            F::from(0b1_0000_0000_0000),
                            F::from(0b01_0000_0000_0000_0000_0000_0000),
                        )?;
                        // - 13-bit
                        add_row(
                            F::from(5),
                            F::from(0b1_1111_1111_1111),
                            F::from(0b01010101010101010101010101),
                        )?;
                        add_row(
                            F::from(6),
                            F::from(0b10_0000_0000_0000),
                            F::from(0b0100000000000000000000000000),
                        )?;
                        // - 14-bit
                        add_row(
                            F::from(6),
                            F::from(0b11_1111_1111_1111),
                            F::from(0b0101_0101_0101_0101_0101_0101_0101),
                        )?;
                        add_row(
                            F::from(7),
                            F::from(0b100_0000_0000_0000),
                            F::from(0b01_0000_0000_0000_0000_0000_0000_0000),
                        )?;
                        // - 15-bit
                        add_row(
                            F::from(7),
                            F::from(0b111_1111_1111_1111),
                            F::from(0b010101_0101_0101_0101_0101_0101_0101),
                        )?;
                        add_row(
                            F::from(8),
                            F::from(0b1000_0000_0000_0000),
                            F::from(0b0100_0000_0000_0000_0000_0000_0000_0000),
                        )?;

                        Ok(())
                    },
                )
            }
        }
    }
}
