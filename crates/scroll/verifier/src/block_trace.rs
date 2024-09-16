use std::collections::{BTreeMap, BTreeSet};

use base::PrimitivesConvert;
use prover_types::{Pob, PobBlock, PobData};
use scroll_executor::{
    eth_types::l2_types::StorageTrace, BlockTrace, Bytes, EthPrimitivesConvert, B256,
};

pub fn block_trace_to_pob(trace: BlockTrace) -> Option<Pob<Bytes>> {
    let pob_hash = B256::default();
    let trace_header = trace.header;

    let txs = {
        let block_hash = trace_header.hash;
        let block_number = trace_header.number;
        let base_fee_per_gas = trace_header.base_fee_per_gas;
        trace
            .transactions
            .iter()
            .enumerate()
            .map(move |(idx, tx)| {
                let tx = tx.to_eth_tx(block_hash, block_number, Some(idx.into()), base_fee_per_gas);
                tx.rlp().to()
            })
            .collect()
    };

    let block = PobBlock {
        miner: trace_header.author?.to(),
        state_root: trace_header.state_root.to(),
        difficulty: trace_header.difficulty.to(),
        number: trace_header.number?.to(),
        gas_limit: trace_header.gas_limit.as_u64().to(),
        timestamp: trace_header.timestamp.as_u64().to(),
        mix_hash: trace_header.mix_hash?.to(),
        base_fee_per_gas: trace_header.base_fee_per_gas.to(),
        block_hash: Some(trace_header.hash?.to()),
        transactions: txs,
        extra_data: trace_header.extra_data.to(),
        gas_used: trace_header.gas_used.to(),
        logs_bloom: trace_header.logs_bloom.unwrap().to(),
        nonce: trace_header.nonce.unwrap().to(),
        parent_hash: trace_header.parent_hash.to(),
        receipts_root: trace_header.receipts_root.to(),
        transactions_root: trace_header.transactions_root.to(),
        uncles_hash: trace_header.uncles_hash.to(),
    };
    let codes = trace.codes.into_iter().map(|code| code.code.to()).collect();

    let prev_state_root = trace.storage_trace.root_before.0.into();
    let mpt_nodes = collect_mpt_nodes(trace.storage_trace);

    let data = PobData {
        chain_id: trace.chain_id,
        coinbase: Some(trace.coinbase.address.to()),
        prev_state_root,
        block_hashes: BTreeMap::new(),
        mpt_nodes,
        codes,
        start_l1_queue_index: trace.start_l1_queue_index,
        withdrawal_root: trace.withdraw_trie_root.0.into(),
        linea_proofs: vec![],
        linea_traces: vec![],
        linea_zkroot: B256::default(),
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

    out.into_iter().map(|n| n.to()).collect()
}
