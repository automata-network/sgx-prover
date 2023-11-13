use std::prelude::v1::*;

use eth_types::SH256;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::byte32_test::TestHash;
use crate::{Byte32, Error, Hash, MemDB, Node, NodeValue, TrieData, ZkTrie, ZERO_HASH};

pub struct TestTrie(ZkTrie<TestHash>, MemDB<TestHash>);

impl TestTrie {
    pub fn new(max_level: usize) -> Self {
        let db = MemDB::new();
        let root = Hash::default();
        let trie = <ZkTrie<TestHash>>::new(max_level, root);
        Self(trie, db)
    }

    pub fn root(&self) -> &Hash {
        self.0.hash()
    }

    pub fn try_get(&mut self, key: &[u8]) -> Result<TrieData<TestHash>, Error> {
        match self.0.try_get_node(&mut self.1, &Hash::from_bytes(key)) {
            Ok(node) => Ok(TrieData::Node(node)),
            Err(Error::KeyNotFound) => Ok(TrieData::NotFound),
            Err(err) => Err(err),
        }
    }

    pub fn update_word(&mut self, key: Byte32, value: Byte32) -> Result<(), Error> {
        let key = Hash::from_bytes(key.bytes());
        self.0.try_update(&mut self.1, &key, 1, vec![value])
    }

    pub fn add_word(&mut self, key: Byte32, value: Byte32) -> Result<(), Error> {
        match self.try_get(key.bytes())? {
            TrieData::Node(_) => return Err(Error::EntryIndexAlreadyExists),
            TrieData::NotFound => {}
        }
        let node_key = Hash::from_bytes(key.bytes());
        self.0.try_update(&mut self.1, &node_key, 1, vec![value])?;
        Ok(())
    }

    pub fn get_leaf_node_by_word(
        &mut self,
        key_preimage: &Byte32,
    ) -> Result<Arc<Node<TestHash>>, Error> {
        self.0
            .try_get_node(&mut self.1, &Hash::from_bytes(key_preimage.bytes()))
    }

    pub fn delete_word(&mut self, key: &Byte32) -> Result<(), Error> {
        let new_key: Hash = key.into();
        self.0.try_delete(&mut self.1, &new_key)
    }
}

fn byte32_from_byte(b: u8) -> Byte32 {
    Byte32::from_bytes(&[b])
}

#[test]
fn test_zktrie_impl_update() {
    let k1 = byte32_from_byte(1);
    let k2 = byte32_from_byte(2);
    let k3 = byte32_from_byte(3);

    {
        // update 1
        let mut mt1 = TestTrie::new(10);
        mt1.add_word(k1, byte32_from_byte(1)).unwrap();
        let root1 = mt1.root().bytes();

        let mut mt2 = TestTrie::new(10);
        mt2.add_word(k1, byte32_from_byte(2)).unwrap();
        mt2.update_word(k1, byte32_from_byte(1)).unwrap();
        let root2 = mt2.root().bytes();

        assert_eq!(root1, root2);
        assert_eq!(
            root1,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 1, 0, 0,
                32, 0, 1, 0, 1
            ]
        );
    }

    {
        // update 2
        let mut mt1 = TestTrie::new(10);
        mt1.add_word(k1, byte32_from_byte(1)).unwrap();
        mt1.add_word(k2, byte32_from_byte(2)).unwrap();
        let root1 = mt1.root().bytes();

        let mut mt2 = TestTrie::new(10);
        mt2.add_word(k1, byte32_from_byte(1)).unwrap();
        mt2.add_word(k2, byte32_from_byte(3)).unwrap();
        mt2.update_word(k2, byte32_from_byte(2)).unwrap();
        let root2 = mt2.root().bytes();
        assert_eq!(
            root1,
            [
                34, 95, 229, 137, 232, 203, 223, 228, 36, 160, 50, 230, 226, 253, 17, 50, 118, 43,
                32, 121, 76, 255, 97, 240, 199, 14, 143, 117, 123, 106, 14, 215
            ]
        );
        assert_eq!(root1, root2);
    }

    {
        // update 1,2,3
        let mut mt1 = TestTrie::new(10);
        let mut mt2 = TestTrie::new(10);
        let keys = [k1, k2, k3];
        for (i, key) in keys.into_iter().enumerate() {
            mt1.add_word(key, byte32_from_byte(i as u8)).unwrap();
        }
        for (i, key) in keys.into_iter().enumerate() {
            mt2.add_word(key, byte32_from_byte((i + 3) as u8)).unwrap();
        }
        for (i, key) in keys.into_iter().enumerate() {
            mt1.update_word(key, byte32_from_byte((i + 6) as u8))
                .unwrap();
            mt2.update_word(key, byte32_from_byte((i + 6) as u8))
                .unwrap();
        }
        let root1 = mt1.root().bytes();
        let root2 = mt2.root().bytes();
        assert_eq!(
            root1,
            [
                25, 48, 90, 243, 147, 27, 34, 3, 233, 24, 50, 77, 134, 203, 220, 232, 124, 23, 204,
                92, 4, 114, 102, 187, 126, 213, 252, 140, 121, 211, 132, 76
            ]
        );
        assert_eq!(root1, root2);
    }

    {
        // update same value
        let mut mt = TestTrie::new(10);
        let keys = [k1, k2, k3];
        for key in keys {
            mt.add_word(key, byte32_from_byte(1)).unwrap();
            mt.update_word(key, byte32_from_byte(1)).unwrap();
            let node = mt.get_leaf_node_by_word(&key).unwrap();
            let leaf = node.leaf().unwrap();
            assert_eq!(leaf.value_preimage.len(), 1);
            assert_eq!(leaf.value_preimage[0], byte32_from_byte(1));
        }
    }

    {
        // update non-existent word
        let mut mt = TestTrie::new(10);
        mt.update_word(k1, byte32_from_byte(1)).unwrap();
        let node = mt.get_leaf_node_by_word(&k1).unwrap();
        let node = node.leaf().unwrap();
        assert_eq!(node.value_preimage.len(), 1);
        assert_eq!(node.value_preimage[0], byte32_from_byte(1));
    }
}

#[test]
fn test_zktrie_impl_add() {
    glog::init_test();
    let k1 = Byte32::from_bytes(&[1]);
    let k2 = Byte32::from_bytes(&[2]);
    let k3 = Byte32::from_bytes(&[3]);

    let kv_map = {
        let mut n = BTreeMap::new();
        n.insert(k1, k1);
        n.insert(k2, k2);
        n.insert(k3, k3);
        n
    };

    {
        // Add 1 and 2 in different orders
        let orders = vec![vec![k1, k2], vec![k2, k1]];

        let mut roots = vec![];
        for order in orders {
            let mut trie = TestTrie::new(10);
            for key in order {
                let value = kv_map.get(&key).unwrap();
                trie.add_word(key, value.clone()).unwrap();
            }
            roots.push(trie.0.hash().bytes());
        }
        assert_eq!(roots[0], roots[1]);
    }

    {
        // Add 1, 2, 3 in different orders
        let orders = vec![
            vec![k1, k2, k3],
            vec![k1, k3, k2],
            vec![k2, k1, k3],
            vec![k2, k3, k1],
            vec![k3, k1, k2],
            vec![k3, k2, k1],
        ];

        let mut roots = vec![];
        for order in orders {
            let mut trie = TestTrie::new(10);
            for key in order {
                let value = kv_map.get(&key).unwrap();
                trie.add_word(key, *value).unwrap();
            }
            roots.push(trie.0.hash().bytes());
        }

        for i in 1..roots.len() {
            assert_eq!(roots[0], roots[i]);
        }
    }

    {
        // Add twice
        let keys = vec![k1, k2, k3];

        let mut trie = TestTrie::new(10);
        for key in keys {
            trie.add_word(key, *kv_map.get(&key).unwrap()).unwrap();
            let err = trie.add_word(key, *kv_map.get(&key).unwrap());
            assert_eq!(err, Err(Error::EntryIndexAlreadyExists));
        }
    }
}

#[test]
fn test_zktrie_impl_delete() {
    let k1 = byte32_from_byte(1);
    let k2 = byte32_from_byte(2);
    let k3 = byte32_from_byte(3);
    let k4 = byte32_from_byte(4);

    {
        // Test deletion leads to empty tree
        let empty_mt = TestTrie::new(10);
        let mut mt1 = TestTrie::new(10);
        mt1.add_word(k1, byte32_from_byte(1)).unwrap();
        mt1.delete_word(&k1).unwrap();
        assert_eq!(mt1.root(), ZERO_HASH.as_ref());
        assert_eq!(empty_mt.root(), mt1.root());

        let keys = [k1, k2, k3, k4];
        let mut mt2 = TestTrie::new(10);
        for key in keys {
            mt2.add_word(key, byte32_from_byte(1)).unwrap();
        }
        for key in keys {
            mt2.delete_word(&key).unwrap();
        }
        assert_eq!(mt2.root(), ZERO_HASH.as_ref());
        assert_eq!(empty_mt.root(), mt2.root());

        let mut mt3 = TestTrie::new(10);
        for key in keys {
            mt3.add_word(key, byte32_from_byte(1)).unwrap();
        }
        for key in keys.iter().rev() {
            mt3.delete_word(key).unwrap();
        }
        assert_eq!(ZERO_HASH.as_ref(), mt3.root());
        assert_eq!(empty_mt.root(), mt3.root());
    }

    {
        // Test equivalen trees after deletion
        let keys = [k1, k2, k3, k4];
        let mut mt1 = TestTrie::new(10);
        for (i, key) in keys.iter().enumerate() {
            mt1.add_word(*key, byte32_from_byte(i as u8 + 1)).unwrap();
        }
        mt1.delete_word(&k1).unwrap();
        mt1.delete_word(&k2).unwrap();

        let mut mt2 = TestTrie::new(10);
        mt2.add_word(k3, byte32_from_byte(3)).unwrap();
        mt2.add_word(k4, byte32_from_byte(4)).unwrap();
        assert_eq!(mt1.root(), mt2.root());

        let mut mt3 = TestTrie::new(10);
        for (i, key) in keys.into_iter().enumerate() {
            mt3.add_word(key, byte32_from_byte(i as u8 + 1)).unwrap();
        }
        mt3.delete_word(&k1).unwrap();
        mt3.delete_word(&k3).unwrap();
        let mut mt4 = TestTrie::new(10);
        mt4.add_word(k2, byte32_from_byte(2)).unwrap();
        mt4.add_word(k4, byte32_from_byte(4)).unwrap();

        assert_eq!(mt3.root(), mt4.root());
    }

    {
        // Test repeat deletion
        let mut mt = TestTrie::new(10);
        mt.add_word(k1, byte32_from_byte(1)).unwrap();
        mt.delete_word(&k1).unwrap();
        assert_eq!(mt.delete_word(&k1), Err(Error::KeyNotFound));
    }

    {
        // Test deletion of non-existent node
        let mut mt = TestTrie::new(10);
        assert_eq!(mt.delete_word(&k1), Err(Error::KeyNotFound));
    }
}

#[test]
fn test_merkle_tree_add_update_get_word() {
    glog::init_test();
    struct TestData {
        key: u8,
        inital_val: u8,
        updated_val: u8,
    }
    impl TestData {
        pub fn new(key: u8, inital_val: u8, updated_val: u8) -> Self {
            Self {
                key,
                inital_val,
                updated_val,
            }
        }
    }
    let test_data = &[
        TestData::new(1, 2, 7),
        TestData::new(3, 4, 8),
        TestData::new(5, 6, 9),
    ];
    let mut mt = TestTrie::new(10);

    for td in test_data {
        let key = Byte32::from_bytes(&[td.key]);
        let value = Byte32::from_bytes_padding(&[td.inital_val]);
        mt.add_word(key, value).unwrap();

        let node = mt
            .get_leaf_node_by_word(&Byte32::from_bytes(&[td.key]))
            .unwrap();
        if let NodeValue::Leaf(leaf) = node.value() {
            assert_eq!(1, leaf.value_preimage.len());
            assert_eq!(value, leaf.value_preimage[0]);
        } else {
            unreachable!()
        }
    }

    let result = mt.add_word(Byte32::from_bytes(&[5]), Byte32::from_bytes_padding(&[7]));
    assert_eq!(result, Err(Error::EntryIndexAlreadyExists));

    for td in test_data {
        mt.update_word(
            Byte32::from_bytes(&[td.key]),
            Byte32::from_bytes_padding(&[td.updated_val]),
        )
        .unwrap();

        let node = mt
            .get_leaf_node_by_word(&Byte32::from_bytes(&[td.key]))
            .unwrap();
        if let NodeValue::Leaf(node) = node.value() {
            assert_eq!(node.value_preimage.len(), 1);
            assert_eq!(
                Byte32::from_bytes_padding(&[td.updated_val]),
                node.value_preimage[0]
            );
        } else {
            unreachable!();
        }
    }

    let result = mt.get_leaf_node_by_word(&Byte32::from_bytes_padding(&[100]));
    assert_eq!(result, Err(Error::KeyNotFound));
}

#[test]
fn test_merkle_tree_deletion() {
    glog::init_test();
    {
        // Check root consistency
        let mut trie = TestTrie::new(10);
        let mut hashes = vec![trie.0.hash().bytes()];

        let tmp = [0_u8; 32];
        for i in 0..6 {
            let key = Byte32::from_bytes(&{
                let mut t = tmp;
                t.last_mut().map(|v| *v = i);
                t
            });
            let value = Byte32::from_bytes(&{
                let mut t = tmp;
                t[0] = i;
                t
            });
            trie.add_word(key, value).unwrap();
            hashes.push(trie.0.hash().bytes())
        }
        for i in (0..6).rev() {
            let key = Byte32::from_bytes(&[i]);
            trie.delete_word(&key).unwrap();
            assert_eq!(trie.0.hash().bytes(), hashes[i as usize]);
        }
    }

    {
        // Check depth
        let mut trie = TestTrie::new(10);
        let key1 = Byte32::from_bytes(&[67]);
        trie.add_word(key1, Byte32::from_bytes_padding(&[67]))
            .unwrap();
        let root_phase1 = trie.0.hash().bytes();
        let key2 = Byte32::from_bytes(&[131]);
        let val2 = Byte32::from_bytes_padding(&[131]);
        trie.add_word(key2, val2).unwrap();
        let root_phase2 = trie.0.hash().bytes();
        // need walk/prove
    }
}

#[test]
fn test_new_zktrie() {
    glog::init_test();
    let root = Hash::default();
    let trie = <ZkTrie<TestHash>>::new(248, root);
    assert_eq!(trie.hash(), ZERO_HASH.as_ref());
}

#[test]
fn test_zktrie_random() {
    glog::init_test();
    let root = Hash::default();
    let mut db = MemDB::new();
    let db = &mut db;
    let mut trie = <ZkTrie<TestHash>>::new(248, root);

    let data = vec![
        (
            "0x2edac2e5866fdd10ccdc27a7cab08453f0f59b92c18403693082143d66ee3474",
            "0x00000000000000000000000000000000000000000000000000ee121424c78f15",
        ),
        (
            "0x3e6e49c9e1aaf563ab0c8372f2494528fb3040a9c290cf0dfb7f45230d8b43fe",
            "0x0000000000000000000000000000000000000000000000632826117cfb39eefd",
        ),
        (
            "0xed812ec25670a9f1e970acd0f591e82de9f941301d24780ae8f12666b08ab360",
            "0x00000000000000000000000000000000000000000000000000ee121424c78f15",
        ),
    ];
    let delete_idx = vec![0];

    for (k, v) in &data {
        let k: SH256 = (*k).into();
        let v: SH256 = (*v).into();
        let v = Byte32::from_bytes_padding(&v.0);
        trie.update(db, k.as_bytes(), 1, vec![v]).unwrap();
    }
    for idx in delete_idx {
        let key: SH256 = data[idx].0.into();
        trie.delete(db, key.as_bytes()).unwrap();
    }
    assert_eq!(
        trie.hash(),
        &Hash::from_hex("15e0373f921e4f9d3c5f29f89a5714f50ed9b7b461c04e8ecc4262ae65588079").unwrap(),
    );
    
}

#[test]
fn test_zktrie_get_update_delete() {
    glog::init_test();
    let mut db = MemDB::new();
    let db = &mut db;
    let root = Hash::default();
    let mut trie = <ZkTrie<TestHash>>::new(248, root);

    let val = trie.get_data(db, b"key").unwrap();
    assert_eq!(val, TrieData::NotFound);
    assert_eq!(trie.hash(), ZERO_HASH.as_ref());

    trie.update(db, b"key", 1, vec![Byte32::from_bytes_padding(&[1])])
        .unwrap();
    let expect = Hash::from_bytes(&[
        0x23_u8, 0x36, 0x5e, 0xbd, 0x71, 0xa7, 0xad, 0x35, 0x65, 0xdd, 0x24, 0x88, 0x47, 0xca,
        0xe8, 0xe8, 0x8, 0x21, 0x15, 0x62, 0xc6, 0x83, 0xdb, 0x8, 0x4f, 0x5a, 0xfb, 0xd1, 0xb0,
        0x3d, 0x4c, 0xb5,
    ]);
    assert_eq!(trie.hash(), &expect);

    let val = trie.get_data(db, b"key").unwrap();
    assert_eq!(val.get(), &Byte32::from_bytes_padding(&[1]).bytes()[..]);

    trie.delete(db, b"key").unwrap();
    assert_eq!(trie.hash(), ZERO_HASH.as_ref());

    let val = trie.get_data(db, b"key").unwrap();
    assert_eq!(TrieData::NotFound, val);
}
