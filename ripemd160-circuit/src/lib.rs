#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

use std::{fmt, marker::PhantomData};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::{ConstraintSystem, Error},
};

mod constants;
mod ref_impl;
mod table16;

use constants::{BLOCK_SIZE, DIGEST_SIZE};

/// The set of circuit instructions required to use the [`RIPEMD160`] gadget.
pub trait RIPEMD160Instructions<F: FieldExt>: Chip<F> {
    /// Variable represening the RIPEMD-160 internal state.
    type State: Clone + fmt::Debug;
    /// Variable representing a 32-bit word of the input block to the RIPEMD-160 compression function
    type BlockWord: Copy + fmt::Debug + Default;

    /// Places the RIPEMD-160 IV in the circuit, returning the initial state variable
    fn init_vector(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error>;

    /// Starting from the given initialized state, processes a block of input and returns the final state
    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        initialized_state: &Self::State,
        input: [Self::BlockWord; BLOCK_SIZE],
    ) -> Result<Self::State, Error>;

    /// Converts the given state into a message digest
    fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
    ) -> Result<[Self::BlockWord; DIGEST_SIZE], Error>;
}

/// The output of a RIPEMD-160 circuit
#[derive(Debug)]
pub struct RIPEMD160Digest<BlockWord>([BlockWord; DIGEST_SIZE]);

/// A gadget that constrains a RIPEMD-160.
#[derive(Debug)]
pub struct RIPEMD160<F: FieldExt, CS: RIPEMD160Instructions<F>> {
    chip: CS,
    state: CS::State,
}

impl<F: FieldExt, Ripemd160Chip: RIPEMD160Instructions<F>> RIPEMD160<F, Ripemd160Chip> {
    /// Create a new hasher instance
    pub fn new(chip: Ripemd160Chip, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
        let state = chip.init_vector(&mut layouter)?;
        Ok(RIPEMD160 { chip, state })
    }

    /// Update the internal state by consuming all message blocks
    /// The input is assumed to be already padded to a multiple of 16 Blockwords
    pub fn update(
        &mut self,
        mut layouter: impl Layouter<F>,
        data: &Vec<[Ripemd160Chip::BlockWord; BLOCK_SIZE]>,
    ) -> Result<(), Error> {
        // Process all blocks
        for block in data {
            self.state = self.chip.compress(&mut layouter, &self.state, *block)?;
        }

        Ok(())
    }

    /// Retrieve result and consume hasher instance.
    pub fn finalize(
        self,
        mut layouter: impl Layouter<F>,
    ) -> Result<RIPEMD160Digest<Ripemd160Chip::BlockWord>, Error> {
        self.chip
            .digest(&mut layouter, &self.state)
            .map(RIPEMD160Digest)
    }

    /// Util function to compute hash of the data
    pub fn digest(
        chip: Ripemd160Chip,
        mut layouter: impl Layouter<F>,
        data: &Vec<[Ripemd160Chip::BlockWord; BLOCK_SIZE]>,
    ) -> Result<RIPEMD160Digest<Ripemd160Chip::BlockWord>, Error> {
        let mut hasher = Self::new(chip, layouter.namespace(|| "init"))?;
        hasher.update(layouter.namespace(|| "update"), data)?;
        hasher.finalize(layouter.namespace(|| "finalize"))
    }
}

#[cfg(any(feature = "test", test))]
pub mod dev {
    use crate::{
        constants::BLOCK_SIZE_BYTES,
        ref_impl::pad_message_bytes,
        table16::{
            util::{convert_byte_slice_to_blockword_slice, convert_byte_slice_to_u32_slice},
            BlockWord, Table16Chip, Table16Config,
        },
    };

    use super::*;

    use ethers_core::types::H160;
    use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
    use std::str::FromStr;

    lazy_static::lazy_static! {
        pub static ref INPUTS_OUTPUTS: (Vec<Vec<u8>>, Vec<H160>) = {
            [
                ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
                ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
                (
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                    "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
                ),
                (
                    "abcdefghijklmnopqrstuvwxyz",
                    "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
                ),
            ]
            .iter()
            .map(|(input, output)| {
                (
                    input.as_bytes().to_vec(),
                    H160::from_str(output).expect("ripemd-160 hash is 20-bytes"),
                )
            })
            .unzip()
        };
    }

    #[derive(Default)]
    pub struct Ripemd160TestCircuit<F> {
        pub inputs: Vec<Vec<u8>>,
        pub outputs: Vec<H160>,
        pub _marker: PhantomData<F>,
    }

    impl<F: FieldExt> Circuit<F> for Ripemd160TestCircuit<F> {
        type Config = Table16Config<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Table16Chip::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = Table16Chip::construct(config.clone());
            Table16Chip::load(config, &mut layouter)?;

            for (input, output) in self.inputs.iter().zip(self.outputs.iter()) {
                // Preprocessing data
                let data: Vec<[BlockWord; BLOCK_SIZE]> = pad_message_bytes(input.clone())
                    .into_iter()
                    .map(convert_byte_slice_to_blockword_slice::<BLOCK_SIZE_BYTES, BLOCK_SIZE>)
                    .collect();

                // Hash the data
                let digest =
                    RIPEMD160::digest(chip.clone(), layouter.namespace(|| "digest"), &data)?;

                // Assert check
                let expected: [u32; DIGEST_SIZE] =
                    convert_byte_slice_to_u32_slice(output.0.clone());
                for (i, digest) in digest.0.iter().enumerate() {
                    digest.0.assert_if_known(|v| *v == expected[i]);
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::marker::PhantomData;

    use crate::dev::{Ripemd160TestCircuit, INPUTS_OUTPUTS};

    #[test]
    fn test_ripemd160_circuit() {
        let (inputs, outputs) = INPUTS_OUTPUTS.clone();

        let circuit: Ripemd160TestCircuit<Fr> = Ripemd160TestCircuit {
            inputs,
            outputs,
            _marker: PhantomData,
        };

        let k = 17;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // Add circuit layout diagram
        use plotters::prelude::*;

        let root = BitMapBackend::new("ripemd160.png", (1024, 512)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Ripemd160 hash Layout", ("sans-serif", 30))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }
}
