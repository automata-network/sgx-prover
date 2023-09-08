#[derive(Debug, Clone)]
pub struct TrieAccountReader {
    block: BlockSelector,
    client: Arc<ExecutionClient>,
}

impl TrieAccountReader {
    pub fn new(block: BlockSelector, client: Arc<ExecutionClient>) -> Self {
        Self { client, block }
    }

    pub fn storage_trie<'b>(&self, owner: &'b SH160) -> TrieStorageReader<'_, 'b> {
        TrieStorageReader {
            reader: self,
            owner,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrieStorageReader<'a, 'b> {
    owner: &'b SH160,
    reader: &'a TrieAccountReader,
}

impl<'a, 'b> ProofFetcher for TrieStorageReader<'a, 'b> {
    fn get_nodes(&self, node: &[SH256]) -> Result<Vec<HexBytes>, String> {
        self.reader.get_nodes(node)
    }

    fn get_node(&self, key: &HexBytes) -> Result<HexBytes, String> {
        self.reader.get_node(key)
    }

    fn fetch_proofs(&self, key: &[u8]) -> Result<Vec<HexBytes>, String> {
        glog::info!(
            exclude:"dry_run",
            "fetch storage proof: {:?}.{}",
            self.owner.raw(),
            HexBytes::from(key)
        );
        assert_eq!(key.len(), 32);
        let key = SH256::from_slice(key).into();
        let result = self
            .reader
            .client
            .get_proof(self.owner, &[key], self.reader.block)
            .unwrap();
        let storage = result.storage_proof.into_iter().next().unwrap();
        Ok(storage.proof)
    }
}

impl ProofFetcher for TrieAccountReader {
    fn fetch_proofs(&self, key: &[u8]) -> Result<Vec<HexBytes>, String> {
        glog::info!(exclude:"dry_run", "fetch account proof: {}", HexBytes::from(key));
        assert_eq!(key.len(), 20);
        let account = H160::from_slice(key).into();
        let result = self.client.get_proof(&account, &[], self.block).unwrap();
        Ok(result.account_proof)
    }

    fn get_nodes(&self, node: &[SH256]) -> Result<Vec<HexBytes>, String> {
        self.client
            .get_dbnodes(node)
            .map_err(|err| format!("{:?}", err))
    }

    fn get_node(&self, key: &HexBytes) -> Result<HexBytes, String> {
        self.client
            .debug_db_get(key)
            .map_err(|err| format!("{:?}", err))
    }
}
