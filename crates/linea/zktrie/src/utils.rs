use alloy::primitives::{B256, Address};

pub fn prefix_len(a: &[u8], b: &[u8]) -> usize {
    let len = a.len().min(b.len());
    for i in 0..len {
        if a[i] != b[i] {
            return i;
        }
    }
    len
}

pub fn parse_prefix(n: &[u8]) -> Address {
    let mut addr = Address::default();
    if n.len() > 20 {
        addr.0.copy_from_slice(&n[..20]);
    } else {
        addr.0[20-n.len()..].copy_from_slice(n);
    }
    addr
}

pub fn hash(msg: &[u8]) -> B256 {
    linea_mimc::sum(msg).unwrap().into()
}

pub fn format_node_index(node_index: u64) -> B256 {
    let mut n = B256::default();
    n.0[24..].copy_from_slice(&node_index.to_be_bytes());
    n
}

pub fn parse_node_index(n: &[u8]) -> u64 {
    if n.len() == 0 {
        return 0;
    }
    let mut tmp = [0_u8; 8];
    tmp.copy_from_slice(&n[n.len() - 8..]);
    u64::from_be_bytes(tmp)
}

pub fn get_leaf_path(idx: u64) -> [u8; ZK_TRIE_DEPTH + 2] {
    const SUB_TRIE_ROOT_PATH: u8 = 1;
    let mut path = [0_u8; ZK_TRIE_DEPTH + 2];
    path[0] = SUB_TRIE_ROOT_PATH;
    let mut value = idx;

    let mut i = path.len() - 2;
    loop {
        path[i] = (value & 1) as u8;
        value = value >> 1;
        i -= 1;
        if value <= 0 {
            break;
        }
    }
    path[path.len() - 1] = LeafType::Value as u8;
    path
}

#[cfg(test)]
mod test {
    use alloy::primitives::B256;

    pub fn create_dum_digest(n: u32) -> B256 {
        let mut val = B256::default();
        let n = n.to_be_bytes();
        val.0[28..].copy_from_slice(&n);
        val
    }
}

#[cfg(test)]
pub use test::*;

use crate::{LeafType, ZK_TRIE_DEPTH};
