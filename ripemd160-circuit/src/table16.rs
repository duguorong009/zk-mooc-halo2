/*
Based on code from https://github.com/privacy-scaling-explorations/halo2/blob/8c945507ceca5f4ed6e52da3672ea0308bcac812/halo2_gadgets/src/sha256/table16.rs
*/

use halo2_proofs::circuit::Value;

pub(crate) mod util;

use util::*;

/// A word in `Table16` message block.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockWord(pub Value<u32>);

impl From<u32> for BlockWord {
    fn from(x: u32) -> Self {
        BlockWord(Value::known(x))
    }
}
