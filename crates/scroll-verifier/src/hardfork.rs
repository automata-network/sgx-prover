use std::collections::BTreeMap;

use lazy_static::lazy_static;
use scroll_executor::{
    eth_types::forks::{hardfork_heights, HardforkId},
    revm::{primitives::SpecId, Database, DatabaseCommit},
};

lazy_static! {
/// Hardfork heights for Scroll networks, grouped by chain id.
static ref HARDFORK_HEIGHTS: BTreeMap<u64, BTreeMap<SpecId, u64>> = generate_hardfork();
}

fn generate_hardfork() -> BTreeMap<u64, BTreeMap<SpecId, u64>> {
    let heights = hardfork_heights();
    let mut out = BTreeMap::new();
    for (fork_id, chain_id, block_height) in heights {
        let chain_spec = out.entry(chain_id).or_insert_with(BTreeMap::new);
        let fork_id = match fork_id {
            HardforkId::Bernoulli => SpecId::BERNOULLI,
            HardforkId::Curie => SpecId::CURIE,
        };
        chain_spec.entry(fork_id).or_insert(block_height);
    }
    out
}

/// Hardfork configuration for Scroll networks.
#[derive(Debug, Default, Copy, Clone)]
pub struct HardforkConfig {
    bernoulli_block: u64,
    curie_block: u64,
}

impl HardforkConfig {
    /// Get the default hardfork configuration for a chain id.
    pub fn default_from_chain_id(chain_id: u64) -> Self {
        if let Some(heights) = HARDFORK_HEIGHTS.get(&chain_id) {
            Self {
                bernoulli_block: heights.get(&SpecId::BERNOULLI).copied().unwrap_or(0),
                curie_block: heights.get(&SpecId::CURIE).copied().unwrap_or(0),
            }
        } else {
            log::warn!(
                "Chain id {} not found in hardfork heights, all forks are enabled by default",
                chain_id
            );
            Self::default()
        }
    }

    /// Get the hardfork spec id for a block number.
    pub fn get_spec_id(&self, block_number: u64) -> SpecId {
        match block_number {
            n if n < self.bernoulli_block => SpecId::PRE_BERNOULLI,
            n if n < self.curie_block => SpecId::BERNOULLI,
            _ => SpecId::CURIE,
        }
    }

    /// Migrate the database to a new hardfork.
    pub fn migrate<DB: Database + DatabaseCommit>(
        &self,
        block_number: u64,
        _db: &mut DB,
    ) -> Result<(), DB::Error> {
        if block_number == self.curie_block {
            panic!("unsupported curie migrate at height #{}", block_number);
        };
        Ok(())
    }

    pub fn batch_version(&self, number: u64) -> u8 {
        match self.get_spec_id(number) {
            SpecId::CURIE => 2,
            SpecId::BERNOULLI => 1,
            SpecId::PRE_BERNOULLI => 0,
            spec => unreachable!("unknown block number: {}, spec: {}", number, spec as u8),
        }
    }
}
