use std::collections::{BTreeMap, BTreeSet};

use prover_types::{Pob, PobBlock, PobData};
use scroll_executor::{
    eth_types::l2_types::StorageTrace, revm::primitives::alloy_primitives::U64, BlockTrace, Bytes,
    B256, U256,
};

pub fn block_trace_to_pob(trace: BlockTrace) -> Option<Pob<Bytes>> {
    let pob_hash = B256::default();
    let trace_header = &trace.header;

    let txs = {
        let block_hash = trace.header.hash;
        let block_number = trace.header.number;
        let base_fee_per_gas = trace.header.base_fee_per_gas;
        trace
            .transactions
            .iter()
            .enumerate()
            .map(move |(idx, tx)| {
                let tx = tx.to_eth_tx(block_hash, block_number, Some(idx.into()), base_fee_per_gas);
                Bytes::copy_from_slice(&tx.rlp())
            })
            .collect()
    };

    let block = PobBlock {
        miner: trace_header.author?.0.into(),
        state_root: trace_header.state_root.0.into(),
        difficulty: U256::from_limbs(trace_header.difficulty.0),
        number: U64::from_limbs(trace_header.number?.0),
        gas_limit: U64::from_limbs([trace_header.gas_limit.as_u64()]),
        timestamp: U64::from_limbs([trace_header.timestamp.as_u64()]),
        mix_hash: trace_header.mix_hash?.0.into(),
        base_fee_per_gas: trace_header.base_fee_per_gas.map(|n| U256::from_limbs(n.0)),
        block_hash: trace_header.hash?.0.into(),
        transactions: txs,
    };
    let codes = trace
        .codes
        .into_iter()
        .map(|code| Bytes::copy_from_slice(&code.code))
        .collect();

    let prev_state_root = trace.storage_trace.root_before.0.into();
    let mpt_nodes = collect_mpt_nodes(trace.storage_trace);

    let data = PobData {
        chain_id: trace.chain_id,
        coinbase: trace.coinbase.address.0.into(),
        prev_state_root,
        block_hashes: BTreeMap::new(),
        mpt_nodes,
        codes,
        start_l1_queue_index: trace.start_l1_queue_index,
        withdrawal_root: trace.withdraw_trie_root.0.into(),
    };
    Some(Pob {
        block,
        data,
        hash: pob_hash,
    })
}

fn collect_mpt_nodes(storage: StorageTrace) -> Vec<Bytes> {
    let mut out = BTreeSet::new();
    for (_, proofs) in storage.proofs {
        out.extend(proofs);
    }
    for (_, storages) in storage.storage_proofs {
        for (_, proofs) in storages {
            out.extend(proofs);
        }
    }
    out.extend(storage.deletion_proofs);

    out.into_iter()
        .map(|n| Bytes::copy_from_slice(&n))
        .collect()
}
