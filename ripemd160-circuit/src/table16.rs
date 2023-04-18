/*
Based on code from https://github.com/privacy-scaling-explorations/halo2/blob/8c945507ceca5f4ed6e52da3672ea0308bcac812/halo2_gadgets/src/sha256/table16.rs
*/

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Any, Assigned, Column, ConstraintSystem, Error},
};

mod compression;
mod gates;
mod message_schedule;
mod spread_table;
pub(crate) mod util;

use compression::*;
use message_schedule::*;
use spread_table::*;
use util::*;

use crate::{constants::INITIAL_VALUES, RIPEMD160Instructions};

/// A word in `Table16` message block.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockWord(pub Value<u32>);

impl From<u32> for BlockWord {
    fn from(x: u32) -> Self {
        BlockWord(Value::known(x))
    }
}

/// Little-endian bits (up to 64 bits)
#[derive(Debug, Clone)]
pub struct Bits<const LEN: usize>([bool; LEN]);

impl<const LEN: usize> Bits<LEN> {
    fn spread<const SPREAD: usize>(&self) -> [bool; SPREAD] {
        spread_bits(self.0)
    }
}

impl<const LEN: usize> std::ops::Deref for Bits<LEN> {
    type Target = [bool; LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> From<[bool; LEN]> for Bits<LEN> {
    fn from(bits: [bool; LEN]) -> Self {
        Self(bits)
    }
}

impl<const LEN: usize> From<&Bits<LEN>> for [bool; LEN] {
    fn from(bits: &Bits<LEN>) -> Self {
        bits.0
    }
}

impl<const LEN: usize, F: FieldExt> From<&Bits<LEN>> for Assigned<F> {
    fn from(bits: &Bits<LEN>) -> Self {
        assert!(LEN <= 64);
        F::from(lebs2ip(&bits.0)).into()
    }
}

impl From<&Bits<16>> for u16 {
    fn from(bits: &Bits<16>) -> Self {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<16> {
    fn from(value: u16) -> Self {
        Bits(i2lebsp::<16>(value.into()))
    }
}

impl From<&Bits<32>> for u32 {
    fn from(bits: &Bits<32>) -> Self {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<32> {
    fn from(value: u32) -> Self {
        Bits(i2lebsp::<32>(value.into()))
    }
}

#[derive(Debug, Clone)]
pub struct AssignedBits<const LEN: usize, F: FieldExt>(AssignedCell<Bits<LEN>, F>);

impl<const LEN: usize, F: FieldExt> std::ops::Deref for AssignedBits<LEN, F> {
    type Target = AssignedCell<Bits<LEN>, F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize, F: FieldExt> AssignedBits<LEN, F> {
    fn assign_bits<A, AR, T: TryInto<[bool; LEN]> + std::fmt::Debug + Clone>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<T>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
        <T as TryInto<[bool; LEN]>>::Error: std::fmt::Debug,
    {
        let value: Value<[bool; LEN]> = value.map(|v| v.try_into().unwrap());
        let value: Value<Bits<LEN>> = value.map(|v| v.into());

        let column: Column<Any> = column.into();
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl<F: FieldExt> AssignedBits<16, F> {
    fn value_u16(&self) -> Value<u16> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u16>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<16>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl<F: FieldExt> AssignedBits<32, F> {
    fn value_u32(&self) -> Value<u32> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u32>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<32>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

/// Configuration of [`Table16Chip`]
#[derive(Clone, Debug)]
pub struct Table16Config<F: FieldExt> {
    lookup: SpreadTableConfig,
    message_schedule: MessageScheduleConfig<F>,
    compression: CompressionConfig<F>,
}

/// A chip that implement the RIPEMD-160 with a maximum lookup table size of $2^16$.
#[derive(Debug, Clone)]
pub struct Table16Chip<F: FieldExt> {
    config: Table16Config<F>,
}

impl<F: FieldExt> Chip<F> for Table16Chip<F> {
    type Config = Table16Config<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> Table16Chip<F> {
    /// Reconstructs this chip from the given config.
    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self { config }
    }

    /// Configure a circuit to include this chip.
    pub fn configure(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
        // columns required for this chip
        let advice = meta.advice_column();

        // Three advice columns to interact with lookup tables
        let input_tag = meta.advice_column();
        let input_dense = meta.advice_column();
        let input_spread = meta.advice_column();

        let lookup = SpreadTableChip::configure(meta, input_tag, input_dense, input_spread);
        let lookup_inputs = lookup.input.clone();

        // Rename these here for ease of matching the gates to the specification.
        let _a_0 = lookup_inputs.tag;
        let a_1 = lookup_inputs.dense;
        let a_2 = lookup_inputs.spread;
        let a_3 = advice;

        // Add all advice columns to permutation
        for col in [a_1, a_2, a_3].iter() {
            meta.enable_equality(*col);
        }

        let s_decompose_word = meta.selector();

        let compression =
            CompressionConfig::configure(meta, lookup_inputs.clone(), advice, s_decompose_word);

        let message_schedule =
            MessageScheduleConfig::configure(meta, lookup_inputs, advice, s_decompose_word);

        Table16Config {
            lookup,
            message_schedule,
            compression,
        }
    }

    /// Loads the lookup table required by this chip into the circuit
    pub fn load(config: Table16Config<F>, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        SpreadTableChip::load(config.lookup, layouter)
    }
}

impl<F: FieldExt> RIPEMD160Instructions<F> for Table16Chip<F> {
    type State = State<F>;
    type BlockWord = BlockWord;

    fn init_vector(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error> {
        self.config()
            .compression
            .init_with_iv(layouter, INITIAL_VALUES)
    }

    // Given an initialized state and an input message block, compress the
    // message block and return the final state
    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        initialized_state: &Self::State,
        input: [Self::BlockWord; crate::constants::BLOCK_SIZE],
    ) -> Result<Self::State, Error> {
        let config = self.config();
        let (_, w_halves) = config.message_schedule.process(layouter, input)?;
        config
            .compression
            .compress(layouter, initialized_state.clone(), w_halves)
    }

    fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
    ) -> Result<[Self::BlockWord; crate::constants::DIGEST_SIZE], Error> {
        // Copy the dense forms of the state variable chunks down to this gate.
        // Reconstruct the 32-bit dense words.
        self.config().compression.digest(layouter, state.clone())
    }
}

/// Common assignment patterns used by Table16 regions.
trait Table16Assignment<F: FieldExt> {
    fn assign_word_and_halves<A, AR>(
        &self,
        annotation: A,
        region: &mut Region<'_, F>,
        lookup: &SpreadInputs,
        a_3: Column<Advice>,
        word: Value<u32>,
        row: usize,
    ) -> Result<
        (
            AssignedBits<32, F>,
            (SpreadVar<16, 32, F>, SpreadVar<16, 32, F>),
        ),
        Error,
    >
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let w_lo_val = word.map(|word| word as u16);
        let w_lo_bvec: Value<[bool; 16]> = w_lo_val.map(|x| i2lebsp(x.into()));
        let spread_w_lo = w_lo_bvec.map(SpreadWord::<16, 32>::new);
        let spread_w_lo = SpreadVar::with_lookup(region, &lookup, row, spread_w_lo)?;
        spread_w_lo
            .dense
            .copy_advice(&annotation, region, a_3, row)?;

        let w_hi_val = word.map(|word| (word >> 16) as u16);
        let w_hi_bvec = w_hi_val.map(|x| i2lebsp(x.into()));
        let spread_w_hi = w_hi_bvec.map(SpreadWord::<16, 32>::new);
        let spread_w_hi = SpreadVar::with_lookup(region, &lookup, row + 1, spread_w_hi)?;
        spread_w_hi
            .dense
            .copy_advice(&annotation, region, a_3, row + 1)?;

        let w = AssignedBits::<32, F>::assign(region, annotation, a_3, row + 2, word)?;

        Ok((w, (spread_w_lo, spread_w_hi)))
    }
}
