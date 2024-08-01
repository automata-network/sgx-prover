use core::marker::PhantomData;
use std::prelude::v1::*;

use eth_types::{HexBytes, SH160, SH256};

use crate::{
    init_world_state, trie_hash, utils, Database, Error, FlattenedLeaf, LeafOpening, MemStore,
    Node, PrefixDB, SpareMerkleTrie,
};

lazy_static::lazy_static! {
    pub static ref EMPTY_TRIE_NODE_HASH: SH256 = {
        let mut db = PrefixDB::new(SH160::default(), MemStore::new_on_init());
        let mut empty_trie = MemZkTrie::empty(&mut db).unwrap();
        *empty_trie.top_root_hash()
    };
    pub static ref EMPTY_DB: MemStore = {
        let mut db = PrefixDB::new(SH160::default(), MemStore::new_on_init());
        let mut empty_trie = MemZkTrie::empty(&mut db).unwrap();
        db.unwrap().unwrap()
    };
    pub static ref EMPTY_TRIE: MemZkTrie = MemZkTrie::new(*EMPTY_TRIE_NODE_HASH);
}

pub type MemZkTrie = ZkTrie<PrefixDB>;

#[derive(Debug)]
pub struct ZkTrie<D: Database<Node = Node>> {
    state: SpareMerkleTrie,
    _marker: PhantomData<D>,
}

impl<D: Database<Node = Node>> ZkTrie<D> {
    pub fn new(root: SH256) -> Self {
        ZkTrie {
            state: SpareMerkleTrie::new(root),
            _marker: PhantomData,
        }
    }

    // pub fn new_from_sub_root(next_free_node: u64, sub_root: SH256) -> Self {
    //     ZkTrie {
    //         state: SpareMerkleTrie::new_from_sub_root(next_free_node, sub_root),
    //         _marker: PhantomData,
    //     }
    // }

    pub fn empty(db: &mut D) -> Result<Self, Error> {
        let (empty_node, _) = init_world_state();
        let mut trie = Self::new(*empty_node.hash());
        trie.set_head_and_tail(db)?;
        let next_free_node = trie.next_free_node(db)?;

        let new_trie = Self::new(*trie.top_root_hash());
        glog::info!("create empty: {:?}", new_trie.next_free_node(db));
        Ok(trie)
    }

    fn set_head_and_tail(&mut self, db: &mut D) -> Result<(), Error> {
        let index = self.get_next_free_leaf_node(&db)?;
        let head_path = utils::get_leaf_path(index);
        self.state
            .put(db, &head_path, LeafOpening::head().to_bytes())?;
        db.update_index(LeafOpening::head().hkey, FlattenedLeaf::head().clone());
        self.increment_next_free_leaf_node_index(db)?;
        let tail_index = self.next_free_node(db)?;
        db.update_index(LeafOpening::tail().hkey, FlattenedLeaf::tail().clone());
        let tail_path = utils::get_leaf_path(tail_index);
        self.state
            .put(db, &tail_path, LeafOpening::tail().to_bytes())?;
        self.increment_next_free_leaf_node_index(db)?;
        Ok(())
    }

    pub fn top_root_hash(&self) -> &SH256 {
        self.state.root_hash()
    }

    pub fn sub_root_hash(&self, db: &D) -> Result<SH256, Error> {
        self.state.sub_root_hash(db)
    }

    pub fn next_free_node(&self, db: &D) -> Result<u64, Error> {
        self.state.next_free_node(db)
    }

    pub fn increment_next_free_leaf_node_index(&mut self, db: &mut D) -> Result<u64, Error> {
        let found_free_node = self.state.next_free_node(db)?;
        let next_free_node = found_free_node + 1;
        self.state
            .set_next_free_node(db, next_free_node)
            .map_err(Error::SetNextFreeNode(&next_free_node))?;
        Ok(next_free_node)
    }

    fn get_next_free_leaf_node(&self, db: &D) -> Result<u64, Error> {
        self.state.next_free_node(db)
    }

    fn parse_node<N, F: FnOnce(&[u8]) -> N>(&self, db: &D, key: &[u8], f: F) -> Result<N, Error> {
        match self.state.get_node(db, key) {
            Ok(Some(node)) => match node.value() {
                Some(data) => Ok(f(data)),
                None => Err(Error::ZkTrieParseNodeFail(key.into(), node.raw().ty())),
            },
            Ok(None) => Err(Error::ZKTrieKeyNotFound(key.into())),
            Err(err) => Err(err),
        }
    }

    pub fn remove(&mut self, db: &mut D, hkey: SH256, key: &[u8]) -> Result<(), Error> {
        let nearest_key = db.get_nearest_keys(self.top_root_hash(), &hkey);
        match &nearest_key.center {
            Some(current_flat_leaf_value) => {
                let left_leaf_path = nearest_key.left_path();
                let right_leaf_path = nearest_key.right_path();

                // UPDATE HKey- with HKey+ for next
                {
                    let prior_left_leaf =
                        self.parse_node(db, &left_leaf_path, LeafOpening::parse)?;
                    let new_left_leaf =
                        prior_left_leaf.new_next_leaf(nearest_key.right_index.into());
                    self.state
                        .put(db, &left_leaf_path, new_left_leaf.to_bytes())?;
                }

                // REMOVE hash(k)
                {
                    let leaf_path_to_delete =
                        utils::get_leaf_path(current_flat_leaf_value.leaf_index);
                    // let prior_deleted_leaf =
                    //     self.parse_node(db, &leaf_path_to_delete, LeafOpening::parse)?;
                    db.remove_index(&hkey);

                    self.state.remove(db, &leaf_path_to_delete)?;
                }

                // UPDATE HKey+ with HKey- for prev
                {
                    let prior_right_leaf =
                        self.parse_node(db, &right_leaf_path, LeafOpening::parse)?;
                    let new_right_leaf =
                        prior_right_leaf.new_prev_leaf(nearest_key.left_index.into());
                    self.state
                        .put(db, &right_leaf_path, new_right_leaf.to_bytes())?;
                }
            }
            None => (),
        }
        Ok(())
    }

    pub fn read(&self, db: &D, hkey: SH256, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        glog::info!(
            "[BEGIN] [root={:?}] read key={:?},hkey={:?}",
            self.top_root_hash(),
            HexBytes::from(key),
            hkey,
        );
        let nearest_keys = db.get_nearest_keys(self.top_root_hash(), &hkey);
        glog::info!(
            "[END] root={:?} index={:?}",
            self.state.root_hash(),
            nearest_keys
        );
        Ok(match nearest_keys.center {
            Some(leaf) => Some(leaf.leaf_value.into()),
            None => None,
        })
    }

    pub fn put(
        &mut self,
        db: &mut D,
        hkey: SH256,
        key: &[u8],
        hval: SH256,
        value: Vec<u8>,
    ) -> Result<(), Error> {
        let nearest_keys = db.get_nearest_keys(self.top_root_hash(), &hkey);
        match nearest_keys.center {
            None => {
                let left_leaf_path = nearest_keys.left_path();
                let right_leaf_path = nearest_keys.right_path();
                let next_free_node = self.state.next_free_node(db).map_err(Error::ZkTriePut())?;

                // UPDATE HKey- with hash(k) for next
                {
                    let prior_left_leaf = self
                        .parse_node(db, &left_leaf_path, LeafOpening::parse)
                        .map_err(Error::ParseLeftNode())?;
                    let new_left_leaf = prior_left_leaf.new_next_leaf(next_free_node.into());

                    self.state
                        .put(db, &left_leaf_path, new_left_leaf.to_bytes())
                        .map_err(Error::PutLeftLeaf())?;

                    let leaf_path_to_add = utils::get_leaf_path(next_free_node);
                    db.update_index(hkey, FlattenedLeaf::new(next_free_node, value.into()));

                    let new_leaf_value = LeafOpening::new(
                        nearest_keys.left_index,
                        nearest_keys.right_index,
                        hkey,
                        hval,
                    );

                    self.state
                        .put(db, &leaf_path_to_add, new_leaf_value.to_bytes())
                        .map_err(Error::PutCenterLeaf())?;
                }

                // UPDATE HKey+ with hash(k) for prev
                {
                    let prior_right_leaf = self
                        .parse_node(db, &right_leaf_path, LeafOpening::parse)
                        .map_err(Error::ParseRightNode())?;
                    let new_right_leaf = prior_right_leaf.new_prev_leaf(next_free_node.into());
                    self.state
                        .put(db, &right_leaf_path, new_right_leaf.to_bytes())
                        .map_err(Error::PutRightLeaf())?;
                }

                self.increment_next_free_leaf_node_index(db)?;
            }
            Some(current_flat_leaf_value) => {
                let leaf_path_to_update = current_flat_leaf_value.leaf_path();
                db.update_index(
                    hkey,
                    FlattenedLeaf::new(current_flat_leaf_value.leaf_index, value.into()),
                );

                let prior_updated_leaf =
                    self.parse_node(db, &leaf_path_to_update, LeafOpening::parse)?;

                let new_updated_leaf = prior_updated_leaf.new_hval(hval);

                self.state
                    .put(db, &leaf_path_to_update, new_updated_leaf.to_bytes())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use base::format::debug;
    use eth_types::{HexBytes, SH160};

    use crate::{
        init_world_state, mimc_safe, trie_hash, utils, LeafOpening, MemStore, NodeValue, Trace,
    };

    use super::*;

    #[test]
    fn test_worldstate_head_and_tail() {
        let val = LeafOpening::head().to_bytes();
        let hash = trie_hash(&val).unwrap();
        assert_eq!(
            hash,
            "0x0891fa77c3d0c9b745840d71d41dcb58b638d4734bb4f0bba4a3d1a2d847b672".into()
        );
        let val = LeafOpening::tail().to_bytes();
        let hash = trie_hash(&val).unwrap();
        assert_eq!(
            hash,
            "0x10ba2286f648a549b50ea5f1b6e1155d22c31eb4727c241e76c420200cd5dbe0".into()
        );
    }

    #[test]
    fn test_empty_worldstate() {
        let (default_node, _) = init_world_state();
        assert_eq!(
            *default_node.hash(),
            "0x09349798db316b1b222f291207e9e1368e9b887a234dcc73b433e6218a43f173".into()
        );
    }

    #[test]
    fn test_zktrie_empty_roothash() {
        glog::init_test();
        let prefix = SH160::default();
        let mut db = PrefixDB::new(prefix, MemStore::new());
        let mut empty_trie = MemZkTrie::empty(&mut db).unwrap();
        assert_eq!(
            empty_trie.top_root_hash(),
            &"0x07977874126658098c066972282d4c85f230520af3847e297fe7524f976873e5".into()
        );
        assert_eq!(
            empty_trie.sub_root_hash(&db).unwrap(),
            "0x0951bfcd4ac808d195af8247140b906a4379b3f2d37ec66e34d2f4a5d35fa166".into()
        );
    }

    // #[test]
    fn test_zktrie_insertion_root_hash() {
        glog::init_test();
        let prefix = SH160::default();
        let mut db = PrefixDB::new(prefix, MemStore::new());
        let mut trie = MemZkTrie::empty(&mut db).unwrap();
        let key = utils::create_dum_digest(58).0.to_vec();
        let value = utils::create_dum_digest(42).0.to_vec();
        let hval = trie_hash(&value).unwrap();
        let hkey = trie_hash(&key).unwrap();

        trie.put(&mut db, hkey, &key, hval, value).unwrap();
        assert_eq!(
            trie.sub_root_hash(&db).unwrap(),
            "0x0882afe875656680dceb7b17fcba7c136cec0c32becbe9039546c79f71c56d36".into()
        );
        assert_eq!(
            trie.top_root_hash(),
            &"0x0cfdc3990045390093be4e1cc9907b220324cccd1c8ea9ede980c7afa898ef8d".into()
        );
    }

    // #[test]
    fn test_zktrie_insertion_and_update_root_hash() {
        glog::init_test();
        let prefix = SH160::default();
        let mut db = PrefixDB::new(prefix, MemStore::new());
        let mut trie = MemZkTrie::empty(&mut db).unwrap();
        let key = utils::create_dum_digest(58).0.to_vec();
        let dum_value = utils::create_dum_digest(41).0.to_vec();
        let new_dum_value = utils::create_dum_digest(42).0.to_vec();
        let hval = trie_hash(&dum_value).unwrap();
        let hkey = trie_hash(&key).unwrap();

        trie.put(&mut db, hkey, &key, hval, dum_value).unwrap();
        assert_eq!(
            trie.sub_root_hash(&db).unwrap(),
            "0x02703cefa95c6dd143543c5e73b14e51a3b714dc73816c6830e4267a41792b1a".into()
        );
        assert_eq!(
            trie.top_root_hash(),
            &"0x03b9554192a170e9424f8cdcd5657ce1826123d93239b9aeb24a648d67522aa5".into()
        );

        let new_hval = trie_hash(&new_dum_value).unwrap();
        let hkey = trie_hash(&key).unwrap();
        trie.put(&mut db, hkey, &key, hval, new_dum_value).unwrap();

        assert_eq!(
            trie.sub_root_hash(&db).unwrap(),
            "0x0882afe875656680dceb7b17fcba7c136cec0c32becbe9039546c79f71c56d36".into()
        );
        assert_eq!(
            trie.top_root_hash(),
            &"0x0cfdc3990045390093be4e1cc9907b220324cccd1c8ea9ede980c7afa898ef8d".into()
        );
    }

    // #[test]
    fn test_zktrie_insertion_and_delete_root_hash() {
        let prefix = SH160::default();
        let mut db = PrefixDB::new(prefix, MemStore::new());
        let mut trie = MemZkTrie::empty(&mut db).unwrap();
        let key = utils::create_dum_digest(58).0.to_vec();
        let value = utils::create_dum_digest(41).0.to_vec();
        let hval = trie_hash(&value).unwrap();
        let hkey = trie_hash(&key).unwrap();
        trie.put(&mut db, hkey, &key, hval, value).unwrap();

        assert_eq!(
            trie.sub_root_hash(&db).unwrap(),
            "0x02703cefa95c6dd143543c5e73b14e51a3b714dc73816c6830e4267a41792b1a".into()
        );
        assert_eq!(
            trie.top_root_hash(),
            &"0x03b9554192a170e9424f8cdcd5657ce1826123d93239b9aeb24a648d67522aa5".into()
        );

        trie.remove(&mut db, hkey, &key).unwrap();
        assert_eq!(
            trie.sub_root_hash(&db).unwrap(),
            "0x0951bfcd4ac808d195af8247140b906a4379b3f2d37ec66e34d2f4a5d35fa166".into()
        );
        assert_eq!(
            trie.top_root_hash(),
            &"0x0bcb88342825fa7a079a5cf5f77d07b1590a140c311a35acd765080eea120329".into()
        );
    }

    fn get_traces(path: &str) -> Result<Vec<Trace>, String> {
        let data = std::fs::read_to_string(format!("testdata/{}.hex", path)).map_err(debug)?;
        let mut traces = Vec::new();
        for line in data.split("\n") {
            let line = HexBytes::from_hex(line.as_bytes()).map_err(debug)?;
            if line.len() == 0 {
                continue;
            }
            let trace = rlp::decode(&line).map_err(debug)?;
            traces.push(trace);
        }
        Ok(traces)
    }

    #[test]
    pub fn test_from_proof() {
        glog::init_test();
        let prefix = SH160::default();
        let traces = get_traces("from_proof").unwrap();
        let mut db = PrefixDB::new(prefix, MemStore::from_traces(&traces).unwrap());
        let root = Node::root_node(
            66,
            "0x108e0450f48e7b3a9420bc085a9da6704e1da76ac4898eef9db5afe4ff48b2ab".into(),
        );
        let root = db.update_node(*root.hash(), root).unwrap();
        let mut trie = MemZkTrie::new(*root.hash());

        assert_eq!(
            trie.top_root_hash(),
            &"0x0e321f8eb2495968e6367ea5c4c7617c91040f6cbcf8a2fba6096bcfded21f2a".into()
        );

        let key = utils::create_dum_digest(9).0.to_vec();
        let hkey = trie_hash(&key).unwrap();
        assert_eq!(trie.read(&db, hkey, &key), Ok(None));

        {
            // trace[1]: READ 10
            let key = utils::create_dum_digest(10).0.to_vec();
            let hkey = trie_hash(&key).unwrap();
            let result = trie.read(&db, hkey, &key).unwrap();
            assert_eq!(result, Some(utils::create_dum_digest(10).0.to_vec()));
        }

        {
            // trace[2]: UPDATE 12 => 120
            let key = utils::create_dum_digest(12).0.to_vec();
            let value = utils::create_dum_digest(120).0.to_vec();
            let hval = trie_hash(&value).unwrap();
            let hkey = trie_hash(&key).unwrap();
            trie.put(&mut db, hkey, &key, hval, value).unwrap();
            assert_eq!(
                trie.top_root_hash(),
                &"0x0540718e2b8049263ac9f7284c333a72cf9b7b0db99ee0f90d0985224d3f7789".into()
            );
        }
        {
            // trace[3]: INSERT 11 => 120
            let key = utils::create_dum_digest(11).0.to_vec();
            let value = utils::create_dum_digest(120).0.to_vec();
            let hval = trie_hash(&value).unwrap();
            let hkey = trie_hash(&key).unwrap();
            trie.put(&mut db, hkey, &key, hval, value).unwrap();
            assert_eq!(
                trie.top_root_hash(),
                &"0x0d01a39a97f703890fdf899ba1f8f6ce44dde04cabc32559bc79ed311e93a4a0".into()
            );
        }
        {
            // trace[4]: DELETE 14
            let key = utils::create_dum_digest(14).0.to_vec();
            let hkey = trie_hash(&key).unwrap();
            trie.remove(&mut db, hkey, &key).unwrap();
            assert_eq!(
                trie.top_root_hash(),
                &"0x035adf5e7ff80f4e60bf4f1d2d499343fcd0010e4fc7a1c9ca9281f01834f075".into()
            );
        }
        {
            // trace[5]: READ ZERO 14
            let key = utils::create_dum_digest(14).0.to_vec();
            let hkey = trie_hash(&key).unwrap();
            let result = trie.read(&mut db, hkey, &key).unwrap();
            assert_eq!(
                trie.top_root_hash(),
                &"0x035adf5e7ff80f4e60bf4f1d2d499343fcd0010e4fc7a1c9ca9281f01834f075".into()
            );
            assert_eq!(result, None);
        }
    }

    #[test]
    fn test_new_hkey() {
        glog::init_test();
        let prefix = SH160::default();
        let mut db = PrefixDB::new(prefix, MemStore::new());
        let mut zktrie = MemZkTrie::empty(&mut db).unwrap();
        let key = SH256::default();
        let hkey = mimc_safe(key.as_bytes()).unwrap();
        let val: SH256 =
            "0x0000000000000000000000000000000000000000000000000000000000000001".into();
        let hval = mimc_safe(val.as_bytes()).unwrap();
        zktrie
            .put(&mut db, hkey, key.as_bytes(), hval, val.as_bytes().into())
            .unwrap();
        assert_eq!(
            zktrie.top_root_hash(),
            &"0x0cb64b38d8631a95c7b57be839251759e73775b9cf09205eb33175915b3cb7fe".into()
        );
    }

    #[test]
    fn performance() {
        let prefix = SH160::default();
        let traces = get_traces("performance").unwrap();
        println!("{}", traces.len());
        let mut db = PrefixDB::new(prefix, MemStore::from_traces(&traces).unwrap());
        let root = Node::root_node(
            642,
            "0x09bb97d5c671eb0224bab1a44d8d60b35f5226253db52faddde77dcb228fd455".into(),
        );
        let root = db.update_node(*root.hash(), root).unwrap();
        let mut trie = MemZkTrie::new(*root.hash());
        println!("{:?}", trie.top_root_hash());

        let now = Instant::now();
        for i in (1..1281).step_by(2) {
            let key = utils::create_dum_digest(i).0;
            let value = utils::create_dum_digest(i).0.to_vec();
            let hval = trie_hash(&value).unwrap();
            let hkey = trie_hash(&key).unwrap();
            trie.put(&mut db, hkey, &key, hval, value).unwrap()
        }
        assert_eq!(
            trie.top_root_hash(),
            &"0x0bc22636292bf4e78e57136ed7b945fed0279aba402e911a6a326935dbba19c6".into()
        );
        println!("insert {:?}", now.elapsed());

        let now = Instant::now();
        for i in 1..1281 {
            let key = utils::create_dum_digest(i).0;
            let hkey = trie_hash(&key).unwrap();
            trie.read(&mut db, hkey, &key).unwrap();
        }
        assert_eq!(
            trie.top_root_hash(),
            &"0x0bc22636292bf4e78e57136ed7b945fed0279aba402e911a6a326935dbba19c6".into()
        );
        println!("read {:?}", now.elapsed());

        let now = Instant::now();
        for i in (1..1281).step_by(2) {
            let key = utils::create_dum_digest(i).0;
            let value = utils::create_dum_digest(i * 2).0.to_vec();
            let hval = trie_hash(&value).unwrap();
            let hkey = trie_hash(&key).unwrap();
            trie.put(&mut db, hkey, &key, hval, value).unwrap();
        }
        assert_eq!(
            trie.top_root_hash(),
            &"0x051a87b46bf3a6f9389eb6b04c663e9974457b8d3dfc89c8d780c53b195c747f".into()
        );
        println!("update {:?}", now.elapsed());

        let now = Instant::now();
        for i in (0..1280).step_by(2) {
            let key = utils::create_dum_digest(i).0;
            let hkey = trie_hash(&key).unwrap();
            trie.remove(&mut db, hkey, &key).unwrap();
        }
        assert_eq!(
            trie.top_root_hash(),
            &"0x08d09cb60beab4f503896ce7c8bbe20717d7369db730967870d3079b9068a435".into()
        );
        println!("remove {:?}", now.elapsed());

        let now = Instant::now();
        for i in (0..1280).step_by(2) {
            let key = utils::create_dum_digest(i).0;
            let hkey = trie_hash(&key).unwrap();
            trie.read(&mut db, hkey, &key).unwrap();
        }
        assert_eq!(
            trie.top_root_hash(),
            &"0x08d09cb60beab4f503896ce7c8bbe20717d7369db730967870d3079b9068a435".into()
        );
        println!("read zero {:?}", now.elapsed());
    }
}
