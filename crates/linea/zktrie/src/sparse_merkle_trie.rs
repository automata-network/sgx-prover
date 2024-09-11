use std::prelude::v1::*;

use crate::{prefix_len, utils, Error, FlattenedLeaf, KeyRange, Node, NodeValue};
use alloy::primitives::{Bytes, B256};
use std::sync::Arc;

pub const ZK_TRIE_DEPTH: usize = 40;

pub trait Database {
    type Node;
    fn get_node(&self, key: &B256) -> Result<Option<Arc<Self::Node>>, Error>;
    fn update_node(&mut self, key: B256, node: Self::Node) -> Result<Arc<Self::Node>, Error>;
    fn get_nearest_keys(&self, root: &B256, k: &B256) -> Result<KeyRange, Error>;
    fn update_index(&mut self, k: B256, v: FlattenedLeaf);
    fn remove_index(&mut self, k: &B256);
    fn get_code(&self, hash: &B256) -> Option<Arc<Bytes>>;
    fn set_code(&mut self, hash: B256, code: Arc<Bytes>);
}

#[derive(Debug)]
pub struct SpareMerkleTrie {
    root_hash: B256,
}

impl SpareMerkleTrie {
    pub fn new(root_hash: B256) -> Self {
        Self { root_hash }
    }

    pub fn root_hash(&self) -> &B256 {
        &self.root_hash
    }

    pub fn root_node<D: Database<Node = Node>>(&self, db: &D) -> Result<Arc<Node>, Error> {
        let node = db
            .get_node(&self.root_hash)?
            .ok_or_else(|| Error::RootNodeNotFound(self.root_hash))?;
        Ok(node)
    }

    pub fn sub_root_hash<D: Database<Node = Node>>(&self, db: &D) -> Result<B256, Error> {
        let root_node = self.root_node(db)?;
        let branch_node = root_node
            .raw()
            .branch()
            .ok_or_else(|| Error::RootNodeExpectToBeBranchNode(root_node.clone()))?;
        Ok(branch_node.right)
    }

    pub fn next_free_node<D: Database<Node = Node>>(&self, db: &D) -> Result<u64, Error> {
        let root_node = self.root_node(db).map_err(Error::GetNextFreeNode())?;
        let branch_node = root_node
            .raw()
            .branch()
            .ok_or_else(|| Error::RootNodeExpectToBeBranchNode(root_node.clone()))?;
        let next_free_node = utils::parse_node_index(branch_node.left.as_slice());
        Ok(next_free_node)
    }

    pub fn set_next_free_node<D: Database<Node = Node>>(
        &mut self,
        db: &mut D,
        free: u64,
    ) -> Result<(), Error> {
        let root_node = self.root_node(db)?;
        let branch_node = root_node
            .raw()
            .branch()
            .ok_or_else(|| Error::RootNodeExpectToBeBranchNode(root_node.clone()))?;
        let root = Node::root_node(free, branch_node.right);
        let root = db.update_node(*root.hash(), root)?;
        self.root_hash = *root.hash();
        Ok(())
    }

    pub fn put<D: Database<Node = Node>>(
        &mut self,
        db: &mut D,
        path: &[u8],
        value: Vec<u8>,
    ) -> Result<(), Error> {
        let root = self.add_leaf(db, 0, &self.root_hash, path, value)?;
        self.root_hash = *root.hash();
        Ok(())
    }

    pub fn remove<D: Database<Node = Node>>(
        &mut self,
        db: &mut D,
        path: &[u8],
    ) -> Result<(), Error> {
        let root_hash = self.root_hash;
        let root = self.remove_leaf(db, 0, &root_hash, path)?;
        self.root_hash = *root.hash();
        Ok(())
    }

    fn remove_leaf<D: Database<Node = Node>>(
        &mut self,
        db: &mut D,
        lvl: usize,
        current: &B256,
        path: &[u8],
    ) -> Result<Arc<Node>, Error> {
        if lvl >= ZK_TRIE_DEPTH + 2 {
            return Err(Error::ReachedMaxLevel);
        }
        let n = match db.get_node(current)? {
            Some(n) => n,
            None => return Err(Error::NodeNotFound(lvl, *current)),
        };
        Ok(match n.raw() {
            NodeValue::Branch(branch) => {
                let child = branch.child(path[lvl]).into();
                let updated_child = self.remove_leaf(db, lvl + 1, child, path)?;
                self.db_add(
                    db,
                    branch.new_replace(path[lvl], *updated_child.hash()).into(),
                )?
            }
            NodeValue::Leaf(_) => Node::empty_leaf(),
            NodeValue::EmptyLeaf => Node::empty_leaf(),
            NodeValue::NextFree(_) => Node::empty_leaf(),
        })
    }

    fn add_leaf<D: Database<Node = Node>>(
        &self,
        db: &mut D,
        lvl: usize,
        current: &B256,
        path: &[u8],
        value: Vec<u8>,
    ) -> Result<Arc<Node>, Error> {
        if lvl >= ZK_TRIE_DEPTH + 2 {
            return Err(Error::ReachedMaxLevel);
        }
        let n = match db.get_node(current)? {
            Some(n) => n,
            None => return Err(Error::NodeNotFound(lvl, *current)),
        };
        Ok(match n.raw() {
            NodeValue::Branch(branch) => {
                let child = branch.child(path[lvl]).into();
                let updated_child = self.add_leaf(db, lvl + 1, child, path, value)?;
                self.db_add(
                    db,
                    branch.new_replace(path[lvl], *updated_child.hash()).into(),
                )?
            }
            NodeValue::Leaf(leaf) => {
                let common_path_len = prefix_len(&leaf.path, &path[lvl..]);
                if common_path_len == leaf.path.len() {
                    self.db_add(db, Node::leaf(path[lvl..].to_vec(), value))?
                } else {
                    log::info!("leaf.path: {:?}, path:{:?}", &leaf.path, &path[lvl..]);
                    return Err(Error::PathNotAllow);
                }
            }
            NodeValue::EmptyLeaf => self.db_add(db, Node::leaf(path[lvl..].to_vec(), value))?,
            NodeValue::NextFree(node) => {
                let common_path_len = prefix_len(&node.path, &path[lvl..]);
                if common_path_len == node.path.len() {
                    self.db_add(db, Node::leaf(path[lvl..].to_vec(), value))?
                } else {
                    unreachable!()
                }
            }
        })
    }

    fn db_add<D: Database<Node = Node>>(&self, db: &mut D, node: Node) -> Result<Arc<Node>, Error> {
        db.update_node(*node.hash(), node)
    }

    pub fn get_node<D: Database<Node = Node>>(
        &self,
        db: &D,
        path: &[u8],
    ) -> Result<Option<Arc<Node>>, Error> {
        // let mut next_node = HashOrNode::Node(self.root.clone());
        let mut next_node_hash = self.root_hash;
        for i in 0..(ZK_TRIE_DEPTH + 2) {
            let n = match db.get_node(&next_node_hash)? {
                Some(node) => node,
                None => return Err(Error::NodeNotFound(i, next_node_hash)),
            };

            match n.raw() {
                NodeValue::Branch(node) => {
                    if path[i] == 0 {
                        next_node_hash = node.left;
                    } else {
                        next_node_hash = node.right;
                    }
                }
                NodeValue::EmptyLeaf => return Ok(None),
                NodeValue::Leaf(node) => {
                    if &node.path == &path[i..] {
                        return Ok(Some(n));
                    }
                    return Ok(None);
                }
                NodeValue::NextFree(node) => {
                    if &node.path == &path[i..] {
                        return Ok(Some(n));
                    }
                    unreachable!()
                }
            }
        }
        Err(Error::ReachedMaxLevel)
    }
}
