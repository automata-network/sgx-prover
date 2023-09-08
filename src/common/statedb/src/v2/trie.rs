use std::prelude::v1::*;

use crate::TrieStore;
use core::borrow::Borrow;
use crypto::keccak_hash;
use eth_types::{HexBytes, SH256};

use lazy_static::lazy_static;
use std::sync::Arc;

lazy_static! {
    pub static ref NIL_NODE_HASH: SH256 =
        "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".into();
}

#[derive(Debug)]
pub enum TrieNodeUpdateResult {
    NewRoot(TrieNode),
    NoChanged,
    Reduction(SH256),
    MissingNode(SH256),
}

impl TrieNodeUpdateResult {
    pub fn new_node<S>(store: &mut S, n: TrieNode) -> Self
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        Self::NewRoot(store.staging(n))
    }
}

#[derive(Debug)]
pub enum TrieUpdateResult {
    NoChanged,
    NewTrie(Trie),
    ReductionNode(SH256),
    MissingNode(SH256),
}

#[derive(Clone, Debug)]
pub struct Trie(TrieNode);

impl Trie {
    pub fn new(mut root: TrieNode) -> Self {
        if let TrieNode::Hash(hash) = root {
            if hash.as_bytes() == NIL_NODE_HASH.as_bytes() {
                root = TrieNode::Nil
            }
        }
        Self(root)
    }

    pub fn from_proofs<S>(store: &mut S, proofs: &[HexBytes]) -> Result<Self, rlp::DecoderError>
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let nodes = TrieNode::from_proofs(store, proofs)?;
        let root = nodes[0].clone();
        store.add_nodes(nodes);
        Ok(Self(root))
    }

    pub fn root(&self) -> &TrieNode {
        &self.0
    }

    pub fn update<S>(&self, store: &mut S, origin_key: &[u8], value: Vec<u8>) -> TrieUpdateResult
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let value_hex = HexBytes::from(value.as_slice());
        let result = self.update_raw(store, origin_key, &keccak_hash(origin_key), value);
        glog::debug!(target: "trie_update",
            "trie update: key:{}, value: {}, result: {:?}",
            HexBytes::from(origin_key),
            value_hex,
            result,
        );
        result
    }

    fn update_raw<S>(
        &self,
        store: &mut S,
        _origin_key: &[u8],
        hash_key: &[u8],
        value: Vec<u8>,
    ) -> TrieUpdateResult
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let k = key_misc::key_bytes_to_hex(hash_key);
        if value.len() > 0 {
            let value = TrieNode::with_value(value.into());
            let mut new_nodes = vec![];
            let nn = self.0.insert(&mut new_nodes, store, &[], &k, value.clone());
            match nn {
                TrieNodeUpdateResult::NewRoot(nn) => {
                    store.add_nodes(new_nodes);
                    nn.embedded().map(|item| store.add_node(item));
                    TrieUpdateResult::NewTrie(Trie(nn))
                }
                TrieNodeUpdateResult::NoChanged => TrieUpdateResult::NoChanged,
                TrieNodeUpdateResult::MissingNode(hash) => TrieUpdateResult::MissingNode(hash),
                TrieNodeUpdateResult::Reduction(_) => unreachable!(),
            }
        } else {
            let mut new_nodes = vec![];
            match self.0.delete(&mut new_nodes, store, &[], &k) {
                TrieNodeUpdateResult::NoChanged => TrieUpdateResult::NoChanged,
                TrieNodeUpdateResult::NewRoot(nn) => {
                    store.add_nodes(new_nodes);
                    nn.embedded().map(|item| store.add_node(item));
                    TrieUpdateResult::NewTrie(Trie(nn))
                }
                TrieNodeUpdateResult::MissingNode(hash) => TrieUpdateResult::MissingNode(hash),
                TrieNodeUpdateResult::Reduction(node) => TrieUpdateResult::ReductionNode(node),
            }
        }
    }

    // fn fetch_and_check_key<S>(
    //     &self,
    //     store: &mut S,
    //     missing_hash: &H256,
    //     origin_key: &[u8],
    //     key: &[u8],
    // ) -> Result<(), String>
    // where
    //     S: TrieStore,
    // {
    //     let hashes = self.fetch_key(store, origin_key, key)?;
    //     assert!(hashes.contains(missing_hash));
    //     Ok(())
    // }

    // fn fetch_key<S>(
    //     &self,
    //     store: &mut S,
    //     origin_key: &[u8],
    //     key: &[u8],
    // ) -> Result<Vec<H256>, String>
    // where
    //     S: TrieStore,
    // {
    //     let proofs = store.fetch_proofs(origin_key)?;
    //     let proof_nodes =
    //         TrieNode::from_proofs_rev(store, &proofs).map_err(|err| format!("{:?}", err))?;
    //     for node in &proof_nodes {
    //         store.add_node(node.embedded().expect("should be embedded node"));
    //     }
    //     // sanity check?
    //     Ok(proof_nodes.iter().map(|n| n.hash().clone()).collect())
    // }

    pub fn try_get<'a, S>(&'a self, store: &S, origin_key: &[u8]) -> TrieData
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let key = key_misc::key_bytes_to_hex(&keccak_hash(origin_key));
        let (_, nn) = self.0.get_data(store, &key);
        nn
    }

    pub fn get<S>(&self, store: &S, origin_key: &[u8]) -> TrieData
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let hash_key = keccak_hash(origin_key);
        let key = key_misc::key_bytes_to_hex(&hash_key);

        let (_, data) = self.0.get_data(store, &key);
        data
        // let (key_rest, nn) = self.0.get_data(store, &key);
        // match nn {
        //     TrieData::Value(n) => return Ok(n),
        //     TrieData::Nil => return Ok(&[]),
        //     TrieData::Missing(hash) => return Err(hash),
        // }

        // let (key_rest, nn) = self.0.get_data(store, &key);
        // match nn {
        //     TrieData::Value(n) => return Ok(n),
        //     TrieData::Nil => return Ok(&[]),
        //     TrieData::Missing(hash) => {
        //         glog::info!("{:?}", self);
        //         unreachable!(
        //             "origin_key={}, key={}, key_rest={}, missing hash: {:?}",
        //             HexBytes::from(origin_key),
        //             HexBytes::from(&hash_key[..]),
        //             HexBytes::from(key_rest),
        //             hash,
        //         )
        //     }
        // }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrieData {
    Nil,
    Missing(SH256),
    Value(Arc<TrieStorageNode>),
}

impl TrieData {
    pub fn get_data(&self) -> Result<&[u8], SH256> {
        match self {
            Self::Nil => Ok(&[]),
            Self::Value(node) => Ok(node.get_value().unwrap()),
            Self::Missing(hash) => Err(*hash),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrieNode {
    Nil,
    Hash(SH256),
    Embedded(Arc<TrieStorageNode>),
}

impl From<SH256> for TrieNode {
    fn from(val: SH256) -> Self {
        Self::Hash(val)
    }
}

impl From<Arc<TrieStorageNode>> for TrieNode {
    fn from(node: Arc<TrieStorageNode>) -> Self {
        Self::Embedded(node)
    }
}

impl From<TrieStorageNode> for TrieNode {
    fn from(node: TrieStorageNode) -> Self {
        Self::Embedded(Arc::new(node))
    }
}

impl rlp::Encodable for TrieNode {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            Self::Nil => s.append(&""),
            Self::Hash(hash) => s.append(hash),
            Self::Embedded(value_node) => s.append(value_node.as_ref()),
        };
    }
}

impl rlp::Decodable for TrieNode {
    fn decode(decoder: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        if decoder.is_list() {
            let item_count = decoder.item_count()?;
            let value_node = match item_count {
                17 => TrieStorageNode::full(TrieValueFull::decode(decoder)?),
                2 => TrieStorageNode::short(TrieValueShort::decode(decoder)?),
                _ => unreachable!(),
            };
            return Ok(TrieNode::Embedded(Arc::new(value_node)));
        }
        if !decoder.is_data() {
            return Err(rlp::DecoderError::Custom("unexpected data: not data"));
        }
        let data = decoder.data()?;
        if data.len() == 0 {
            return Ok(TrieNode::Nil);
        } else if data.len() == 32 {
            // maybe it's a value node
            let mut hash = SH256::default();
            hash.0.copy_from_slice(data);
            return Ok(TrieNode::Hash(hash));
        }
        glog::info!("data: {:?}", HexBytes::from(data));
        unreachable!()
    }
}

impl TrieNode {
    pub fn from_proofs<S>(
        store: &S,
        proofs: &[HexBytes],
    ) -> Result<Vec<TrieNode>, rlp::DecoderError>
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let mut nodes = Vec::with_capacity(proofs.len());
        for proof in proofs.iter() {
            let hash = keccak_hash(proof).into();
            let node = match store.get(&hash) {
                Some(storege_node) => storege_node.into(),
                None => rlp::decode(&proof)?,
            };
            nodes.push(node);
            glog::debug!(target: "trie_proof", "add node: {:?}", nodes.last().unwrap());
        }
        Ok(nodes)
    }

    pub fn is_nil(&self) -> bool {
        matches!(self, TrieNode::Nil)
    }

    pub fn embedded_full(&self) -> Option<&TrieValueFull> {
        match self.embedded() {
            Some(embedded) => match &embedded.val {
                TrieValue::Full(node) => Some(node),
                _ => None,
            },
            None => None,
        }
    }

    pub fn hash(&self) -> &SH256 {
        match self {
            Self::Nil => &NIL_NODE_HASH,
            Self::Hash(hash) => hash,
            Self::Embedded(node) => &node.hash,
        }
    }

    pub fn embedded(&self) -> Option<&Arc<TrieStorageNode>> {
        match self {
            Self::Nil => None,
            Self::Hash(_) => None,
            Self::Embedded(node) => Some(node),
        }
    }

    pub fn should_fix(&self) -> bool {
        match self.embedded() {
            Some(n) => !n.should_embedded(),
            None => false,
        }
    }

    pub fn fix(&mut self, store: &mut Vec<TrieNode>) {
        match self.embedded() {
            Some(embedded) => {
                if !embedded.should_embedded() {
                    let mut new = TrieNode::Hash(*self.hash());
                    std::mem::swap(&mut new, self);
                    store.push(new);
                }
            }
            None => {}
        }
    }

    // pub fn unwrap_embedded<S: TrieStore>(self, store: &mut S) -> Arc<TrieStorageNode> {
    //     let storage_node = self.embedded().unwrap().clone();
    //     drop(self);
    //     // store.remove_staging_node(&storage_node);
    //     // match Arc::try_unwrap(storage_node) {
    //     //     Ok(unwrap) => unwrap,
    //     //     Err(old) => {
    //     //         store.add_node(&old);
    //     //         old.as_ref().clone()
    //     //     }
    //     // }
    // }

    pub fn with_value(data: HexBytes) -> TrieNode {
        Self::Embedded(TrieStorageNode::value(data).into())
    }

    pub fn with_short(new_nodes: &mut Vec<TrieNode>, mut node: TrieValueShort) -> TrieNode {
        node.val.fix(new_nodes);
        Self::Embedded(TrieStorageNode::short(node).into())
    }

    pub fn with_full(new_nodes: &mut Vec<TrieNode>, mut node: TrieValueFull) -> TrieNode {
        for child in &mut node.0 {
            child.fix(new_nodes);
        }
        let trie = Self::Embedded(TrieStorageNode::full(node).into());
        trie
    }

    pub fn with_short_key(new_nodes: &mut Vec<TrieNode>, key: HexBytes, val: TrieNode) -> TrieNode {
        Self::with_short(new_nodes, TrieValueShort { key, val })
    }

    pub fn get_value(&self) -> Option<&[u8]> {
        match self {
            Self::Embedded(storage) => storage.get_value(),
            _ => None,
        }
    }

    pub fn get_data<'a, 'b, S>(&'a self, store: &S, mut key: &'b [u8]) -> (&'b [u8], TrieData)
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        use std::borrow::Cow;
        let mut tn = Cow::Borrowed(self);
        loop {
            let nn = match tn.borrow() {
                Self::Embedded(embedded) => match TrieStorageNode::get_data(embedded, key) {
                    Ok(node) => return (&[], node),
                    Err((nkey, ntn)) => {
                        key = nkey;
                        Cow::Owned(ntn.clone())
                    }
                },
                Self::Hash(hash) => match store.get(hash) {
                    Some(node) => match TrieStorageNode::get_data(&node, key) {
                        Ok(node) => return (&[], node),
                        Err((nkey, ntn)) => {
                            key = nkey;
                            Cow::Owned(ntn.clone())
                        }
                    },
                    None => return (key, TrieData::Missing(hash.clone())),
                },
                Self::Nil => return (key, TrieData::Nil),
            };
            tn = nn;
        }
    }

    pub fn insert<S>(
        &self,
        new_nodes: &mut Vec<TrieNode>,
        store: &S,
        prefix: &[u8],
        key: &[u8],
        value: TrieNode,
    ) -> TrieNodeUpdateResult
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        if key.len() == 0 {
            if let (Some(new), Some(old)) = (value.get_value(), self.get_value()) {
                return match new.eq(old) {
                    true => TrieNodeUpdateResult::NoChanged,
                    false => TrieNodeUpdateResult::NewRoot(value),
                };
            }
            return TrieNodeUpdateResult::NewRoot(value);
        }
        let storage_node = match self {
            TrieNode::Nil => {
                let nn = TrieValueShort {
                    key: key.into(),
                    val: value,
                };
                let nn = TrieNode::with_short(new_nodes, nn);
                return TrieNodeUpdateResult::NewRoot(nn);
            }
            TrieNode::Hash(hash) => match store.get(hash) {
                Some(node) => node,
                None => return TrieNodeUpdateResult::MissingNode(*hash),
            },
            TrieNode::Embedded(node) => node.clone(),
        };
        match &storage_node.val {
            TrieValue::Short(n) => {
                let matchlen = key_misc::prefix_len(key, &n.key);
                if matchlen == n.key.len() {
                    let prefix = [prefix, &key[..matchlen]].concat();
                    let nn = match n
                        .val
                        .insert(new_nodes, store, &prefix, &key[matchlen..], value)
                    {
                        TrieNodeUpdateResult::NewRoot(n) => n,
                        other => return other,
                    };
                    let nn = TrieNode::with_short_key(new_nodes, n.key.clone(), nn);
                    return TrieNodeUpdateResult::NewRoot(nn);
                }

                // Otherwise branch out at the index where they differ.
                let mut branch = TrieValueFull::new();
                branch.0[n.key[matchlen] as usize] = match TrieNode::Nil.insert(
                    new_nodes,
                    store,
                    &[prefix, &n.key[..matchlen + 1]].concat(),
                    &n.key[matchlen + 1..],
                    n.val.clone(),
                ) {
                    TrieNodeUpdateResult::NewRoot(n) => n,
                    other => return other,
                };
                branch.0[key[matchlen] as usize] = match TrieNode::Nil.insert(
                    new_nodes,
                    store,
                    &[prefix, &n.key[..matchlen + 1]].concat(),
                    &key[matchlen + 1..],
                    value,
                ) {
                    TrieNodeUpdateResult::NewRoot(n) => n,
                    other => return other,
                };

                let branch = TrieNode::with_full(new_nodes, branch);

                return TrieNodeUpdateResult::NewRoot(match matchlen {
                    0 => branch, // Replace this shortNode with the branch if it occurs at index 0.
                    _ => TrieNode::with_short_key(new_nodes, key[..matchlen].into(), branch),
                });
            }
            TrieValue::Full(n) => {
                let nn = match n.0[key[0] as usize].insert(
                    new_nodes,
                    store,
                    &[prefix, &key[..1]].concat(),
                    &key[1..],
                    value,
                ) {
                    TrieNodeUpdateResult::NewRoot(n) => n,
                    other => return other,
                };
                let mut n = n.clone();
                n.0[key[0] as usize] = nn;
                return TrieNodeUpdateResult::NewRoot(TrieNode::with_full(new_nodes, n));
            }
            TrieValue::Value(_) => unreachable!(),
        }
    }

    pub fn delete<S>(
        &self,
        new_nodes: &mut Vec<TrieNode>,
        store: &S,
        prefix: &[u8],
        key: &[u8],
    ) -> TrieNodeUpdateResult
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let storage_node = match self {
            TrieNode::Nil => return TrieNodeUpdateResult::NoChanged,
            TrieNode::Hash(hash) => match store.get(hash) {
                Some(node) => node,
                None => return TrieNodeUpdateResult::MissingNode(*hash),
            },
            TrieNode::Embedded(node) => node.clone(),
        };
        match &storage_node.val {
            TrieValue::Value(_) => TrieNodeUpdateResult::NewRoot(TrieNode::Nil),
            TrieValue::Full(n) => {
                let nn = match n.0[key[0] as usize].delete(
                    new_nodes,
                    store,
                    &[prefix, &key[..1]].concat(),
                    &key[1..],
                ) {
                    TrieNodeUpdateResult::NewRoot(nn) => nn,
                    other => return other,
                };
                let is_nil = nn.is_nil();
                let mut n = n.clone();
                n.0[key[0] as usize] = nn;
                if !is_nil {
                    let nn = TrieNode::with_full(new_nodes, n);
                    return TrieNodeUpdateResult::NewRoot(nn);
                }

                // Reduction
                // -1 => no non-nil
                // -2 => non-nil > 1
                // _  => only one non-nil, convert to shortNode
                let mut pos: i8 = -1;
                for (i, cld) in n.0.iter().enumerate() {
                    if !cld.is_nil() {
                        if pos == -1 {
                            pos = i as _;
                        } else {
                            pos = -2;
                            break;
                        }
                    }
                }
                if pos >= 0 {
                    let pos = pos as u8;
                    if pos != 16 {
                        let child = &n.0[pos as usize];
                        let cnode = match child.embedded() {
                            Some(cnode) => cnode.clone(),
                            None => match store.get(child.hash()) {
                                Some(cnode) => cnode,
                                None => return TrieNodeUpdateResult::Reduction(*child.hash()),
                            },
                        };
                        if let TrieValue::Short(node) = &cnode.val {
                            let k = [&[pos], node.key.as_bytes()].concat();
                            // glog::info!("new node: {:?}", TrieShortNode::new(k.clone().into(), node.val.clone()));
                            let nn =
                                TrieNode::with_short_key(new_nodes, k.into(), node.val.clone());
                            return TrieNodeUpdateResult::NewRoot(nn);
                        }
                    }
                    let nn = TrieNode::with_short_key(
                        new_nodes,
                        vec![pos].into(),
                        n.0[pos as usize].clone(),
                    );
                    return TrieNodeUpdateResult::NewRoot(nn);
                }
                TrieNodeUpdateResult::NewRoot(TrieNode::with_full(new_nodes, n))
            }
            TrieValue::Short(n) => {
                let matchlen = key_misc::prefix_len(key, &n.key);
                if matchlen < n.key.len() {
                    return TrieNodeUpdateResult::NoChanged; // not_dirty & return n;
                }
                if matchlen == key.len() {
                    return TrieNodeUpdateResult::NewRoot(TrieNode::Nil);
                }
                let child = match n.val.delete(
                    new_nodes,
                    store,
                    &[prefix, &key[..n.key.len()]].concat(),
                    &key[n.key.len()..],
                ) {
                    TrieNodeUpdateResult::NewRoot(node) => node,
                    other => return other,
                };
                if child.embedded().is_none() {
                    // glog::info!("{}", self.format(store));

                    match &child {
                        TrieNode::Hash(hash) => {
                            let node = new_nodes.iter().find(|n| n.hash() == hash);
                            glog::info!("child(store): {:?}", node);
                        }
                        _ => {}
                    }
                    glog::info!(
                        "child: {:?}, delete_key: {:?}",
                        child,
                        HexBytes::from(&key[n.key.len()..])
                    );
                }
                let child_storage_node = child.embedded().unwrap();
                match &child_storage_node.val {
                    TrieValue::Short(child) => {
                        // TODO: the origin node is leaking;
                        let new_key = [n.key.as_bytes(), child.key.as_bytes()].concat();
                        let mut new_child = child.clone();
                        new_child.key = new_key.into();
                        TrieNodeUpdateResult::NewRoot(TrieNode::with_short(new_nodes, new_child))
                    }
                    _ => {
                        // we need to put the child node to the store again
                        let nn = TrieNode::with_short_key(new_nodes, n.key.clone(), child);
                        TrieNodeUpdateResult::NewRoot(nn)
                    }
                }
            }
        }
    }

    pub fn walk<S, F>(&self, store: &S, stack: &[&TrieNode], idx: usize, mut f: F)
    where
        F: FnMut(usize, &[&TrieNode]) + Copy,

        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let mut stack = stack.to_owned();
        let storage_node = match self {
            TrieNode::Nil => {
                stack.push(self);
                f(idx, &stack);
                return;
            }
            TrieNode::Hash(hash) => match store.get(hash) {
                Some(node) => node,
                None => {
                    stack.push(self);
                    f(idx, &stack);
                    return;
                }
            },
            TrieNode::Embedded(embedded) => embedded.clone(),
        };

        let tmp = storage_node.clone().into();
        stack.push(&tmp);
        f(idx, &stack);

        match &storage_node.val {
            TrieValue::Full(node) => {
                for (idx, child) in node.0.iter().enumerate() {
                    child.walk(store, &stack, idx, f);
                }
            }
            TrieValue::Short(node) => {
                node.val.walk(store, &stack, 0, f);
            }
            TrieValue::Value(_) => return,
        }
    }

    pub fn format<S>(&self, store: &S) -> String
    where
        S: TrieStore<StorageNode = TrieStorageNode, Node = TrieNode>,
    {
        let buf = std::cell::RefCell::new(String::new());
        use std::fmt::Write;
        let _ = writeln!(buf.borrow_mut(), "");
        self.walk(store, &[], 0, |idx, parents| {
            let mut buf = buf.borrow_mut();
            let node = parents.last().unwrap().clone();
            let parent = if parents.len() >= 2 {
                Some(parents[parents.len() - 2])
            } else {
                None
            };
            let index = parent
                .map(|node| {
                    if node.embedded_full().is_some() {
                        format!(" [{:x}]", idx)
                    } else {
                        format!("")
                    }
                })
                .unwrap_or("".into());
            let mut prefix = format!("{}{}", "-->".repeat(parents.len() - 1), index);
            if prefix.len() != 0 {
                prefix += " ";
            }

            let _ = match node {
                TrieNode::Hash(hash) => writeln!(buf, "{}(hash) {:?}", prefix, hash),
                TrieNode::Nil => writeln!(buf, "{}nil", prefix),
                TrieNode::Embedded(embedded) => match &embedded.val {
                    TrieValue::Full(_) => {
                        writeln!(buf, "{}(full) {:?}", prefix, embedded.hash)
                    }
                    TrieValue::Short(short) => {
                        writeln!(
                            buf,
                            "{}(short) key={}, hash={:?}",
                            prefix,
                            HexBytes::from(key_misc::hex_to_compact(&short.key)),
                            embedded.hash
                        )
                    }
                    TrieValue::Value(value) => {
                        writeln!(buf, "{}(value) {}", prefix, value.0)
                    }
                },
            };
        });
        buf.take()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrieStorageNode {
    pub val: TrieValue,
    pub raw_len: u32,
    pub hash: SH256,
}

impl rlp::Encodable for TrieStorageNode {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match &self.val {
            TrieValue::Full(node) => {
                if !self.should_embedded() {
                    s.append(&self.hash);
                } else {
                    s.append(node);
                }
            }
            TrieValue::Short(node) => {
                if !self.should_embedded() {
                    s.append(&self.hash);
                } else {
                    s.append(node);
                }
            }
            TrieValue::Value(data) => {
                s.append(&data.0);
            }
        }
    }
}

impl TrieStorageNode {
    pub fn value(data: HexBytes) -> Self {
        Self::from_trie_value(TrieValue::Value(TrieValueBytes(data)))
    }

    // pub fn fix(&self) -> Option<Arc<TrieStorageNode>> {
    //     let fix_nodes = Vec::new();
    //     match &self.val {
    //         TrieValue::Full(node) => {
    //             let mut node = Cow::Borrowed(node);
    //             for child in &node.0 {
    //                 child.embedded().is_some()
    //             }
    //         }
    //         TrieValue::Short(node) => {}
    //         TrieValue::Value(node) => None,
    //     }
    // }

    pub fn should_embedded(&self) -> bool {
        match &self.val {
            TrieValue::Full(_) | TrieValue::Short(_) => {
                if self.raw_len >= 32 {
                    false
                } else {
                    true
                }
            }
            TrieValue::Value(_) => true,
        }
    }

    pub fn get_value(&self) -> Option<&[u8]> {
        match &self.val {
            TrieValue::Value(val) => Some(&val.0),
            _ => None,
        }
    }

    pub fn get_short(&self) -> Option<&TrieValueShort> {
        match &self.val {
            TrieValue::Short(node) => Some(node),
            _ => None,
        }
    }

    pub fn full(node: TrieValueFull) -> Self {
        Self::from_trie_value(TrieValue::Full(node))
    }

    pub fn short(node: TrieValueShort) -> Self {
        Self::from_trie_value(TrieValue::Short(node))
    }

    pub fn from_trie_value(val: TrieValue) -> Self {
        let raw: Vec<u8> = rlp::encode(&val).into();
        let raw_len = raw.len() as u32;
        let hash = keccak_hash(&raw).into();
        Self { val, raw_len, hash }
    }

    #[inline]
    pub fn get_data<'a, 'b>(
        this: &'a Arc<Self>,
        key: &'b [u8],
    ) -> Result<TrieData, (&'b [u8], &'a TrieNode)> {
        match &this.val {
            TrieValue::Full(node) => return Err((&key[1..], &node.0[key[0] as usize])),
            TrieValue::Short(n) => {
                if key.len() < n.key.len() || n.key != key[..n.key.len()] {
                    return Ok(TrieData::Nil);
                }
                return Err((&key[n.key.len()..], &n.val));
            }
            TrieValue::Value(_) => {
                assert_eq!(key.len(), 0);
                return Ok(TrieData::Value(this.clone()));
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrieValue {
    Full(TrieValueFull),
    Short(TrieValueShort),
    Value(TrieValueBytes),
}

impl rlp::Encodable for TrieValue {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            Self::Full(value) => s.append(value),
            Self::Short(value) => s.append(value),
            Self::Value(value) => s.append(value),
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrieValueFull(Vec<TrieNode>);

impl rlp::Encodable for TrieValueFull {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_unbounded_list();
        for i in 0..17 {
            let child = &self.0[i];
            if child.is_nil() {
                s.append(&"");
            } else {
                s.append(child);
            }
        }
        s.finalize_unbounded_list()
    }
}

impl rlp::Decodable for TrieValueFull {
    fn decode(decoder: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let item_count = decoder.item_count()?;
        if item_count != 17 {
            return Err(rlp::DecoderError::Custom("unexpected item count"));
        }
        // let hash = keccak_hash(decoder.as_raw());
        let mut children: Vec<TrieNode> = Vec::with_capacity(17);
        for i in 0..16 {
            children.push(decoder.at(i)?.as_val()?);
        }
        let value_child = decoder.at(16)?;
        if !value_child.is_data() {
            return Err(rlp::DecoderError::Custom("unexpected value node: no data"));
        }
        let data = value_child.data()?;
        if data.len() > 0 {
            children.push(TrieNode::with_value(data.into()));
        } else {
            children.push(TrieNode::Nil);
        }
        Ok(Self(children))
    }
}

impl TrieValueFull {
    pub fn new() -> Self {
        Self(vec![TrieNode::Nil; 17])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrieValueShort {
    pub key: HexBytes,
    pub val: TrieNode,
}

impl rlp::Encodable for TrieValueShort {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_unbounded_list();
        let key = key_misc::hex_to_compact(&self.key);
        s.append(&key);
        s.append(&self.val);
        s.finalize_unbounded_list();
    }
}

impl rlp::Decodable for TrieValueShort {
    fn decode(decoder: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        // let hash = keccak_hash(decoder.as_raw());
        let item_count = decoder.item_count()?;
        if item_count != 2 {
            return Err(rlp::DecoderError::Custom("unexpected item count"));
        }
        let key = decoder.at(0)?.data()?;
        let compact_key = key_misc::compact_to_hex(key);
        if compact_key.len() > 0 && compact_key[compact_key.len() - 1] == 16 {
            let value = decoder.at(1)?.data()?;
            return Ok(Self {
                key: compact_key.into(),
                val: TrieStorageNode::value(value.into()).into(),
            });
        }
        return Ok(Self {
            key: compact_key.into(),
            val: decoder.at(1)?.as_val()?,
        });
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrieValueBytes(pub HexBytes);

impl rlp::Encodable for TrieValueBytes {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.append(&self.0.as_bytes());
    }
}

pub mod key_misc {
    use std::prelude::v1::*;

    pub fn hex_to_compact(mut hex: &[u8]) -> Vec<u8> {
        let mut terminator = 0u8;
        if hex.len() > 0 && hex[hex.len() - 1] == 16 {
            terminator = 1;
            hex = &hex[..hex.len() - 1];
        }
        let mut buf = vec![0u8; hex.len() / 2 + 1];
        buf[0] = terminator << 5; // the flag byte
        if hex.len() & 1 == 1 {
            buf[0] |= 1 << 4; // odd flag
            buf[0] |= hex[0]; // first nibble is contained in the first byte
            hex = &hex[1..];
        }
        decode_nibbles(hex, &mut buf[1..]);
        return buf;
    }

    pub fn decode_nibbles(nibbles: &[u8], bytes: &mut [u8]) {
        let mut bi = 0;
        let mut ni = 0;
        while ni < nibbles.len() {
            bytes[bi] = nibbles[ni] << 4 | nibbles[ni + 1];
            bi += 1;
            ni += 2;
        }
    }

    pub fn compact_to_hex(compact: &[u8]) -> Vec<u8> {
        if compact.len() == 0 {
            return compact.into();
        }
        let mut base = key_bytes_to_hex(compact);
        // delete terminator flag
        if base[0] < 2 {
            base.truncate(base.len() - 1);
        }
        // apply odd flag
        let chop = 2 - (base[0] & 1);
        base.rotate_left(chop as _);
        base.truncate(base.len() - chop as usize);
        return base;
    }

    pub fn key_bytes_to_hex(val: &[u8]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(val.len() * 2 + 1);
        for b in val {
            nibbles.push(b / 16);
            nibbles.push(b % 16);
        }
        nibbles.push(16);
        return nibbles;
    }

    pub fn prefix_len(a: &[u8], b: &[u8]) -> usize {
        let len = a.len().min(b.len());
        for i in 0..len {
            if a[i] != b[i] {
                return i;
            }
        }
        len
    }
}
