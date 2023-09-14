use core::marker::PhantomData;
use std::prelude::v1::*;

use std::sync::Arc;

use eth_types::SU256;

use crate::{
    check_in_field, test_bit, to_secure_key, BranchHash, BranchType, Byte32, Database, Error, Hash,
    HashScheme, Node, NodeValue, ZERO,
};

#[derive(Clone)]
pub struct ZkTrie<H: HashScheme> {
    root: Hash,
    max_level: usize,
    phantom: PhantomData<H>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TrieData {
    NotFound,
    Node(Arc<Node>),
}

impl TrieData {
    pub fn get(&self) -> &[u8] {
        match self {
            Self::Node(node) => node.data(),
            Self::NotFound => &[],
        }
    }
}

impl<H: HashScheme> ZkTrie<H> {
    pub fn new(max_level: usize, root: Hash) -> Self {
        Self {
            root,
            max_level,
            phantom: PhantomData,
        }
    }

    pub fn hash(&self) -> &Hash {
        &self.root
    }

    pub fn get_data<D: Database>(&self, db: &mut D, key: &[u8]) -> Result<TrieData, Error> {
        let k = to_secure_key::<H>(key);
        match self.try_get_node(db, &k.into()) {
            Ok(node) => Ok(TrieData::Node(node)),
            Err(Error::KeyNotFound) => Ok(TrieData::NotFound),
            Err(err) => Err(err),
        }
    }

    fn try_get_node<D: Database>(&self, db: &mut D, node_key: &Hash) -> Result<Arc<Node>, Error> {
        let path = get_path(self.max_level, node_key.raw_bytes());
        let mut next_hash = self.root;
        for i in 0..self.max_level {
            let n = self
                .get_node(db, &next_hash)?
                .ok_or(Error::NodeNotFound((i, next_hash)))?;
            match n.value() {
                NodeValue::Empty => return Err(Error::KeyNotFound),
                NodeValue::Leaf(leaf) => {
                    if node_key == &leaf.key {
                        return Ok(n);
                    }
                    return Err(Error::KeyNotFound);
                }
                NodeValue::Branch(branch) => {
                    if path[i] {
                        next_hash = *branch.right.hash();
                    } else {
                        next_hash = *branch.left.hash();
                    }
                }
            }
        }
        return Err(Error::ReachedMaxLevel);
    }

    pub fn delete<D: Database>(&mut self, db: &mut D, key: &[u8]) -> Result<(), Error> {
        let k = to_secure_key::<H>(key);
        let key_hash = k.into();

        //mitigate the create-delete issue: do not delete unexisted key
        match self.try_get_node(db, &key_hash) {
            Ok(_) => {}
            Err(Error::KeyNotFound) => return Ok(()),
            Err(err) => return Err(err),
        }

        self.try_delete(db, &key_hash)
    }

    fn try_delete<D: Database>(&mut self, db: &mut D, node_key: &Hash) -> Result<(), Error> {
        if !check_in_field(&node_key.u256()) {
            return Err(Error::InvalidField);
        }
        let path = get_path(self.max_level, node_key.raw_bytes());
        let mut next_hash = self.root;
        let mut siblings = Vec::new();
        for i in 0..self.max_level {
            let n = match self.get_node(db, &next_hash)? {
                Some(n) => n,
                None => return Err(Error::KeyNotFound),
            };

            match n.value() {
                NodeValue::Empty => return Err(Error::KeyNotFound),
                NodeValue::Leaf(leaf) => {
                    if &leaf.key == node_key {
                        // remove and go up with sibling
                        self.rm_and_upload(db, &path, node_key, &siblings)?;
                        return Ok(());
                    }
                    return Err(Error::KeyNotFound);
                }
                NodeValue::Branch(branch) => {
                    if path[i] {
                        next_hash = *branch.right.hash();
                        siblings.push((branch.ty(), *branch.left.hash()));
                    } else {
                        next_hash = *branch.left.hash();
                        siblings.push((branch.ty(), *branch.right.hash()));
                    }
                }
            }
        }
        return Err(Error::KeyNotFound);
    }

    fn rm_and_upload<D: Database>(
        &mut self,
        db: &mut D,
        path: &[bool],
        _key: &Hash,
        siblings: &[(BranchType, Hash)],
    ) -> Result<Hash, Error> {
        if siblings.len() == 0 {
            self.root = *(ZERO.as_ref());
            return Ok(self.root);
        }

        if siblings.last().unwrap().0 != BranchType::BothTerminal {
            let nn = Node::new_empty();
            self.root = self.recalculate_path_until_root(db, path, nn, siblings)?;
            return Ok(self.root);
        }

        if siblings.len() == 1 {
            self.root = siblings[0].1;
            return Ok(self.root);
        }

        let (_, to_upload) = &siblings[siblings.len() - 1];

        for i in (0..siblings.len() - 1).rev() {
            if siblings[i].1 == Hash::default() {
                continue;
            }
            let new_node_type = siblings[i].0.deduce_downgrade(path[i]);
            let new_node = if path[i] {
                Node::new_branch_ty::<H>(new_node_type, siblings[i].1, *to_upload)
            } else {
                Node::new_branch_ty::<H>(new_node_type, *to_upload, siblings[i].1)
            };
            match self.add_node(db, &new_node) {
                Err(Error::NodeKeyAlreadyExists) | Ok(_) => {}
                Err(err) => return Err(err),
            }
            // glog::info!("ty: {:?} new_node: {:?}", new_node_type, new_node);
            self.root = self.recalculate_path_until_root(db, path, new_node, &siblings[..i])?;
            return Ok(self.root);
        }

        self.root = *to_upload;
        return Ok(self.root);
    }

    pub fn update<D: Database>(
        &mut self,
        db: &mut D,
        key: &[u8],
        v_flag: u32,
        v_preimage: Vec<Byte32>,
    ) -> Result<(), Error> {
        let k = to_secure_key::<H>(key);
        self.update_preimage(db, key, &k);
        let key_hash = k.into();
        self.try_update(db, &key_hash, v_flag, v_preimage)?;
        Ok(())
    }

    fn update_preimage<D: Database>(&mut self, db: &mut D, preimage: &[u8], hash_field: &SU256) {
        db.update_preimage(preimage, hash_field)
    }

    fn try_update<D: Database>(
        &mut self,
        db: &mut D,
        key: &Hash,
        v_flag: u32,
        v_preimage: Vec<Byte32>,
    ) -> Result<(), Error> {
        if !check_in_field(&key.u256()) {
            return Err(Error::InvalidField);
        }

        let new_leaf_node = Node::new_leaf::<H>(key.clone(), v_flag, v_preimage);
        let path = get_path(self.max_level, key.raw_bytes());
        let root = self.root.clone();
        // glog::info!("try update node: {:?}", new_leaf_node);
        let new_root_result = self.add_leaf(db, new_leaf_node, &root, 0, &path, true);
        let new_root = match new_root_result {
            Err(Error::EntryIndexAlreadyExists) => {
                panic!("Encounter unexpected errortype: ErrEntryIndexAlreadyExists")
            }
            Err(err) => return Err(err),
            Ok(new_root) => new_root,
        };
        // glog::info!("old root {:?} -> new root {:?}", self.root, new_root);
        self.root = *(new_root.hash());
        Ok(())
    }

    // GetNode gets a node by node hash from the MT.  Empty nodes are not stored in the
    // tree; they are all the same and assumed to always exist.
    // <del>for non exist key, return (NewEmptyNode(), nil)</del>
    pub fn get_node<D: Database>(
        &self,
        db: &mut D,
        hash: &Hash,
    ) -> Result<Option<Arc<Node>>, Error> {
        if hash.is_zero() {
            return Ok(Some(Node::empty()));
        }
        Ok(match db.get_node(hash)? {
            Some(node) => Some(node),
            None => None,
        })
    }

    fn recalculate_path_until_root<D: Database>(
        &mut self,
        db: &mut D,
        path: &[bool],
        mut node: Node,
        siblings: &[(BranchType, Hash)],
    ) -> Result<Hash, Error> {
        for i in (0..siblings.len()).rev() {
            let node_hash = *node.hash();
            node = if path[i] {
                Node::new_branch_ty::<H>(siblings[i].0, siblings[i].1, node_hash)
            } else {
                Node::new_branch_ty::<H>(siblings[i].0, node_hash, siblings[i].1)
            };
            match self.add_node(db, &node) {
                Err(Error::NodeKeyAlreadyExists) | Ok(_) => {}
                Err(err) => return Err(err),
            }
        }
        return Ok(*node.hash());
    }

    // addLeaf recursively adds a newLeaf in the MT while updating the path, and returns the node hash
    // of the new added leaf.
    pub fn add_leaf<D: Database>(
        &mut self,
        db: &mut D,
        new_leaf: Node,
        curr_node_hash: &Hash,
        lvl: usize,
        path: &[bool],
        force_update: bool,
    ) -> Result<BranchHash, Error> {
        if lvl > self.max_level - 1 {
            return Err(Error::ReachedMaxLevel);
        }
        let n = match self.get_node(db, curr_node_hash)? {
            Some(node) => node,
            None => return Err(Error::NodeNotFound((lvl, *curr_node_hash))),
        };
        match n.value() {
            NodeValue::Empty => {
                let nn = self.add_node(db, &new_leaf)?;
                return Ok(BranchHash::Ternimal(nn));
            }
            NodeValue::Leaf(old_leaf) => {
                let new_leaf_value = new_leaf.leaf().unwrap();
                if old_leaf.key == new_leaf_value.key {
                    if new_leaf.hash() == n.hash() {
                        return Ok(BranchHash::Ternimal(*n.hash()));
                    } else if force_update {
                        let hash = self.update_node(db, new_leaf)?;
                        return Ok(BranchHash::Ternimal(hash));
                    }
                    return Err(Error::EntryIndexAlreadyExists);
                }
                let path_old_leaf = get_path(self.max_level, old_leaf.key.raw_bytes());
                let hash = self.push_leaf(db, new_leaf, &n, lvl, &path, &path_old_leaf)?;
                return Ok(BranchHash::Branch(hash));
            }
            NodeValue::Branch(branch) => {
                let new_parent_node = if path[lvl] {
                    // go right
                    let new_node_hash = self.add_leaf(
                        db,
                        new_leaf,
                        branch.right.hash(),
                        lvl + 1,
                        path,
                        force_update,
                    )?;
                    Node::new_branch::<H>(branch.left.clone(), new_node_hash)
                } else {
                    // go left
                    let new_node_hash = self.add_leaf(
                        db,
                        new_leaf,
                        branch.left.hash(),
                        lvl + 1,
                        path,
                        force_update,
                    )?;
                    Node::new_branch::<H>(new_node_hash, branch.right.clone())
                };
                // glog::info!("[{}] add in branch: {:?}, new_leaf: ", lvl, new_parent_node);
                let hash = self.add_node(db, &new_parent_node)?;
                Ok(BranchHash::Branch(hash))
            }
        }
    }

    // pushLeaf recursively pushes an existing oldLeaf down until its path diverges
    // from newLeaf, at which point both leafs are stored, all while updating the
    // path. pushLeaf returns the node hash of the parent of the oldLeaf and newLeaf
    pub fn push_leaf<D: Database>(
        &mut self,
        db: &mut D,
        new_leaf: Node,
        old_leaf: &Node,
        lvl: usize,
        path_new_leaf: &[bool],
        path_old_leaf: &[bool],
    ) -> Result<Hash, Error> {
        if lvl > self.max_level - 2 {
            return Err(Error::ReachedMaxLevel);
        }
        if path_new_leaf[lvl] == path_old_leaf[lvl] {
            let next_node_hash = self.push_leaf(
                db,
                new_leaf,
                old_leaf,
                lvl + 1,
                path_new_leaf,
                path_old_leaf,
            )?;
            let new_parent_node = if path_new_leaf[lvl] {
                // go right
                Node::new_branch::<H>(BranchHash::empty(), BranchHash::Branch(next_node_hash))
            } else {
                // go left
                Node::new_branch::<H>(BranchHash::Branch(next_node_hash), BranchHash::empty())
            };
            return self.add_node(db, &new_parent_node);
        }
        let new_parent_node = if path_new_leaf[lvl] {
            Node::new_branch::<H>(
                BranchHash::Ternimal(*old_leaf.hash()),
                BranchHash::Ternimal(*new_leaf.hash()),
            )
        } else {
            Node::new_branch::<H>(
                BranchHash::Ternimal(*new_leaf.hash()),
                BranchHash::Ternimal(*old_leaf.hash()),
            )
        };
        self.add_node(db, &new_leaf)?;
        let new_parent_hash = self.add_node(db, &new_parent_node)?;
        Ok(new_parent_hash)
    }

    // addNode adds a node into the MT and returns the node hash. Empty nodes are
    // not stored in the tree since they are all the same and assumed to always exist.
    pub fn add_node<D: Database>(&mut self, db: &mut D, n: &Node) -> Result<Hash, Error> {
        let hash = n.hash();
        if n.is_empty() {
            return Ok(*hash);
        }

        match db.get_node(hash)? {
            Some(old) => {
                if old.as_ref() != n {
                    return Err(Error::NodeKeyAlreadyExists);
                }
                Ok(*hash)
            }
            None => {
                let n = db.update_node(n.clone())?;
                Ok(*n.hash())
            }
        }
    }

    // updateNode updates an existing node in the MT.  Empty nodes are not stored
    // in the tree; they are all the same and assumed to always exist.
    pub fn update_node<D: Database>(&mut self, db: &mut D, n: Node) -> Result<Hash, Error> {
        let hash = n.hash();
        if n.is_empty() {
            return Ok(*hash);
        }
        let n = db.update_node(n)?;
        Ok(*n.hash())
    }
}

fn get_path(num_level: usize, k: &[u8]) -> Vec<bool> {
    let mut path = Vec::with_capacity(num_level);
    for n in 0..num_level {
        path.push(test_bit(k, n));
    }
    path
}
