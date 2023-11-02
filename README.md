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
It's recommended to use Azure with the `Standard DC4s v3` size.

Install the latest [Geth](https://github.com/ethereum/go-ethereum). We'll be using it to launch a local node as the L1 node and deploy the verifier contract.   
Ensure it's added to the PATH environment variable.

### 2. Environment Initialization

#### 2.1. Start Geth

Open a terminal window and execute:
```bash
> ./scripts/verifier.sh geth
```
The script will assist in launching geth in dev mode (data will be lost after a restart) and produces a block every 2 seconds.

#### 2.2. Deploy Contract

```
> ./scripts/verifier.sh deploy
verifier address: 0xBf2A60958a0dF024Ffa1dF8C652240C42425762c
```

#### 2.3. Configure the attestor and prover


`config/attestor-localhost.json`:   
```json
{
    "private_key": "0x6767f2678b02e0612a0bf6f07a1cb83da787d9369d965caf65184e82767c02a2", <- Do not modify in the test environment
    "verifier": {
        "endpoint": "http://localhost:8546",
        "addr": "0xBf2A60958a0dF024Ffa1dF8C652240C42425762c" <- Replace with the deployed verifier contract address
    },
}
```

`config/prover-localhost.json`:  
```json
{
    "verifier": {
        "endpoint": "http://localhost:8546",
        "addr": "0xBf2A60958a0dF024Ffa1dF8C652240C42425762c" <- Replace with the deployed verifier contract address
    },
    "l2": "http://localhost:18546",
    "relay_account": "0x135e5f68224c169b016d92aedb6af6163e6d985dd6d25b3bbd1124e964490843", <- Do not modify in the test environment

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
**Tips**:
  * In the testing environment, you can add --insecure to accept any attestation report.
  * Without an SGX environment, you can add NOSGX=1 to run in standard mode. In this mode, you need to forcibly enable --insecure.

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

**Tips**:
  * In the testing environment, you can add --dummy_attestation_report to generate a dummy attestation report.
  * In the testing environment, you can add --insecure to skip the attestation process.
  * Without an SGX environment, you can add NOSGX=1 to run in standard mode. In this mode, you need to forcibly enable --dummy_attestation_report.

#### 3.3. Test block execution

Prover offers a method to quickly simulate the execution of certain blocks. It will assist in generating Proof of Blocks and invoke the prove method.

**Note, this method can only be used in a dev environment.**
```bash
# generate a execution report for the block 100,000
> curl http://localhost:18232 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"report","params":["100000"]}'

{
	"id": 1,
	"jsonrpc": "2.0",
	"result": {
		"block_hash": "0xb743a9800b35a76b06ba854f3f36720f7d12871ea78b2cd17430502e158039c9",
		"new_state_root": "0x2e6c6fd65960c84447166b45d8a2112c229cba88fd1e4db34fbcbeb6dd0d67b8",
		"prev_state_root": "0x20dd588f8ce73141baba126193a112ee2eee739b10241e5fadfbbc95eb1917e5",
		"signature": "0xb2de217b8b6407323d7da51f78882586af2c66c5425a1389f16847b8e5648b167db16d78e0ccaa3dc2befa9e2dfb559fec7ff3965a1ec8f5889810d66ffd6a0901",
		"state_hash": "0x50f33560917312545fa0d8cdc01a380e3f53962d2457817bddbf46455c59d2ec",
		"withdrawal_root": "0xe323c9fea8a2e6a5a0ae2c857d5dc29fdadc16a669a60df6e16fb3a0bfe9eef9"
	}
}

# validate the block from 100 to 200
> curl http://localhost:18232 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"validate","params":["100", 100]}'

{
	"id": 1,
	"jsonrpc": "2.0",
	"result": null
}
```

* `block_hash`: A hash calculated based on the provided blocks.
* `state_hash`: A hash derived from the entire provided state.
* `prev_state_root`, `new_state_root`, `withdrawal_root`: Values passed in by the request.
* `signature`: The signature of the report.