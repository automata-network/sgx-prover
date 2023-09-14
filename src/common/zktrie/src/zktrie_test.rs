use std::prelude::v1::*;

use eth_types::{SU256, SH256};
use num_bigint::BigInt;

use crate::{
    from_bigint, to_bigint, Byte32, Hash, HashScheme, MemDB, TrieData, ZkTrie, Q_BIG, ZERO,
};
use std::ops::Deref;

pub struct TestHash;
impl HashScheme for TestHash {
    fn hash_scheme(arr: &[SU256], domain: &SU256) -> SU256 {
        let lc_eff: BigInt = 65536.into();
        let mut sum = to_bigint(domain);
        for bi in arr {
            let bi = to_bigint(bi);
            let nbi = &bi * &bi;
            sum = (&sum * &sum * &lc_eff) + nbi;
        }
        from_bigint(&(sum % Q_BIG.deref()))
    }
}

#[test]
fn test_new_zktrie() {
    glog::init_test();
    let root = Hash::default();
    let db = MemDB::new();
    let trie = <ZkTrie<TestHash>>::new(248, root);
    assert_eq!(trie.hash(), ZERO.as_ref());
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
    glog::info!("root: {:?}", trie.hash());

}

#[test]
fn test_zktrie_get_update_delete() {
    glog::init_test();
    let mut db = MemDB::new();
    let db = &mut db;
    let root = Hash::default();
    let mut trie = <ZkTrie<TestHash>>::new(10, root);

    let val = trie.get_data(db, b"key").unwrap();
    assert_eq!(val, TrieData::NotFound);
    assert_eq!(trie.hash(), ZERO.as_ref());

    trie.update(db, b"key", 1, vec![Byte32::from_bytes_padding(&[1])])
        .unwrap();
    let expect: Hash = [
        0x23_u8, 0x36, 0x5e, 0xbd, 0x71, 0xa7, 0xad, 0x35, 0x65, 0xdd, 0x24, 0x88, 0x47, 0xca,
        0xe8, 0xe8, 0x8, 0x21, 0x15, 0x62, 0xc6, 0x83, 0xdb, 0x8, 0x4f, 0x5a, 0xfb, 0xd1, 0xb0,
        0x3d, 0x4c, 0xb5,
    ]
    .into();
    assert_eq!(trie.hash(), &expect);

    let val = trie.get_data(db, b"key").unwrap();
    assert_eq!(val.get(), &Byte32::from_bytes_padding(&[1]).bytes()[..]);

    trie.delete(db, b"key").unwrap();
    assert_eq!(trie.hash(), ZERO.as_ref());

    let val = trie.get_data(db, b"key").unwrap();
    assert_eq!(TrieData::NotFound, val);
}
