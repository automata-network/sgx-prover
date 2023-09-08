# SGX Prover


## Getting Started

### 1. System Dependencies

Install node using nvm. It's recommended to use v18.16.1. Then, install hardhat.

```
> nvm install v18.16.1
> nvm use v18.16.1
> cd verifier && npm install
```

Initialize the SGX environment. You can refer [here](https://github.com/automata-network/attestable-build-tool/blob/main/image/rust/Dockerfile).

Install the latest [Geth](https://github.com/ethereum/go-ethereum). We'll be using it to launch a local node as the L1 node and deploy the verifier contract.   
Ensure it's added to the PATH environment variable.

### 2. Environment Initialization

#### 2.1. Start Geth

Open a terminal window and execute:
```bash
> ./scripts/verifier.sh geth
```
The script will assist in launching geth in dev mode (data will be lost after a restart) and produces a block every 2 seconds.
**NOTICE**: For testing convenience, in this demo, we use the same Geth instance for both L1 and L2.

#### 2.2. Deploy Contract

```
> ./scripts/verifier.sh deploy
verifier address: 0xBf2A60958a0dF024Ffa1dF8C652240C42425762c
```

#### 2.3. Configure the attestor and prover


`config/attestor-localhost.json`:   
```json
{
    "private_key": "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a", <- Do not modify in the test environment
    "verifier": {
        "endpoint": "ws://localhost:8546",
        "addr": "0xBf2A60958a0dF024Ffa1dF8C652240C42425762c" <- Replace with the deployed verifier contract address
    }
}
```

`config/prover-localhost.json`:  
```json
{
    "verifier": {
        "endpoint": "ws://localhost:8546",
        "addr": "0xBf2A60958a0dF024Ffa1dF8C652240C42425762c" <- Replace with the deployed verifier contract address
    },
    "l2": "ws://localhost:8546", <- used in mock
    "spid": "***",
    "ias_apikey": "***",
    "relay_account": "0xc4c4ce41c075356be1f31bdec70accea47fd9c140d411f97aad82c19895eb2d1", <- Do not modify in the test environment

    "server": {
        "tls": "",
        "body_limit": 2097152,
        "workers": 10
    }
}
```

### 3. Local test

#### 3.1. Run the attestor

Open a terminal window and execute:
```bash
> RELEASE=1 ./script/attestor.sh
   Compiling sgx-attestor v1.0.0 (bin/sgx/sgx-attestor)
    Finished release [optimized] target(s) in 19.10s
     Running `bin/sgx/target/debug/sgx-attestor -c config/attestor-localhost.json`
[2023-09-04 08:31:10.002] [ef0612d2984c026c] [sgx_attestor_enclave:25] [INFO] - Initialize Enclave!
[2023-09-04 08:31:10.002] [ef0612d2984c026c] [apps:170] [INFO] - args: "[\"bin/sgx/target/debug/sgx-attestor\",\"-c\",\"config/attestor-localhost.json\"]"
[2023-09-04 08:31:10.004] [ef0612d2984c026c] [jsonrpc::ws_client:400] [INFO] - [ws://localhost:8546] poll interval = 150.088µs
[2023-09-04 08:31:10.006] [ef0612d2984c026c] [app_attestor::app:31] [INFO] - attestor info: addr=0x15d34aaf54267db7d7c367839aaf71a00a2c6a65, balance=1
[2023-09-04 08:31:10.007] [ef0612d2984c026c] [eth_client::log_trace:34] [WARN] - incorrect start offset=0, head=9640, reset to head
[2023-09-04 08:31:14.008] [ef0612d2984c026c] [eth_client::log_trace:89] [INFO] - finish scan to 9640 -> 9642
[2023-09-04 08:31:18.010] [ef0612d2984c026c] [eth_client::log_trace:89] [INFO] - finish scan to 9643 -> 9644s
```

#### 3.2. Run the prover

Open a terminal window and execute:
```bash
> RELEASE=1 ./script/prover.sh
   Compiling sgx-prover v1.0.0 (bin/sgx/sgx-prover)
    Finished release [optimized] target(s) in 20.30s
     Running `bin/sgx/target/debug/sgx-prover -c config/prover-localhost.json`
[2023-09-04 08:32:46.487] [daf6cc897bf92c0c] [sgx_prover_enclave:25] [INFO] - Initialize Enclave!
[2023-09-04 08:32:46.487] [daf6cc897bf92c0c] [apps:170] [INFO] - args: "[\"bin/sgx/target/debug/sgx-prover\",\"-c\",\"config/prover-localhost.json\"]"
[2023-09-04 08:32:46.488] [daf6cc897bf92c0c] [net::dns:50] [DEBUG] - query dns for ("localhost", 8546): 93.402µs
[2023-09-04 08:32:46.489] [daf6cc897bf92c0c] [jsonrpc::ws_client:400] [INFO] - [ws://localhost:8546] poll interval = 145.326µs
...
[2023-09-04 08:32:46.496] [prover-status-monitor] [verifier::client:101] [INFO] - getting prover attested...
... 
[2023-09-04 08:32:48.505] [prover-status-monitor] [verifier::client:320] [INFO] - waiting receipt(0x9938ec66bfb35065be3f85bb10ed8f0008569982c99ddba29156776e804a2acc): unconfirmed, retry in 1 secs
...
[2023-09-04 08:32:53.510] [prover-status-monitor] [verifier::client:98] [INFO] - waiting attestor to approve...
....
[2023-09-04 08:32:53.511] [prover-status-monitor] [verifier::client:119] [INFO] - prover is attested...
```
Wait for "prover is attested" to appear.

#### 3.3. Test block execution

Prover offers a method to quickly simulate the execution of certain blocks. It will assist in generating Proof of Blocks and invoke the prove method.

**Note, this method can only be used in a dev environment.**
```bash
# We execute blocks with block numbers 1 to 20
> curl http://localhost:18232 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"mock","params":["1","20"]}'

{
    "jsonrpc":"2.0",
    "result":{
        "report":{
            "block_hash":"0xb1d033b35f5e9cedee24efb9fc52eed36b6fabb2d84bf7f14e1a0012ca35caaa",
            "state_hash":"0xbfdfb6ab02770fedf554762ee2e6f1a92bdf9e8b9beb0ed46cf99b438926fdec",
            "prev_state_root":"0x612881e2e663cec84fbccf01df88fb6312db020b51f445da627c8bff049fa8ff",
            "new_state_root":"0xbbe62440b2cbb1e8d07cea505a1e0f6ae0fb29da5205f3e8079706d2594bf30a",
            "withdrawal_root":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "signature":"0x93a634b42038823b77ae08a647533861d25ac4dd6d87a4c081793fee98be3a7557666ea70e3b42d68ebd240d20e13a371d18d1b8aaefde2c457475baaf1e0fe400"
        },
        "tx_hash":"0xe552720643c9a4a42a9473f56e26c76dd530dc0d42c10a3bedde7d533244543a"
    },
    "id":1
}
```

* `block_hash`: A hash calculated based on the provided blocks.
* `state_hash`: A hash derived from the entire provided state.
* `prev_state_root`, `new_state_root`, `withdrawal_root`: Values passed in by the request.
* `signature`: The signature of the report.