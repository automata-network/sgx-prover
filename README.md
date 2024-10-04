# SGX Prover
[![Automata SGX SDK](https://img.shields.io/badge/Power%20By-Automata%20SGX%20SDK-orange.svg)](https://github.com/automata-network/automata-sgx-sdk)

SGX Prover is a prover running SGX enclave, as a component of [multi-prover-avs](https://github.com/automata-network/multi-prover-avs).

SGX Prover utilizing the [automata-sgx-sdk](https://github.com/automata-network/automata-sgx-sdk) to build the SGX app.

Currently SGX prover supports to execute scroll/linea blocks in SGX enclave and generate the PoE (proof of execution).

# Packages

Check in [here](https://github.com/automata-network/sgx-prover/pkgs/container/sgx-prover) if you are looking for a docker image. It's built from [Dockerfile](docker/Dockerfile).

# Build from source

### System Dependencies

Check the [Dockerfile](docker/Dockerfile) for installing the dependencies.

### Build

```
$ # make sure you have cargo-sgx installed, or you can skip this step.
$ cargo install cargo-sgx

$ # generate you own key
$ cargo sgx gen-key bin/sgx-prover/sgx/private.pem

$ cargo sgx build --release
$ ls -l target/release/sgx-prover target/release/*.signed.so
```

# Development

SGX Prover supports running on non-SGX VM, even on macos. In this case, the Intel SGX SDK is not required.

```
$ cargo sgx run --std 
```

# Run

Prepare the Config
```
$ cat ./config/prover.json
{
    "scroll_endpoint": "${scroll_node_endpoint}"
}
```

Run the server
```
# run by cargo sgx
$ cargo sgx run --release

# run by executable file
$ target/release/sgx-prover
```

Test the functionality with scroll
```
$ testdata/test_scroll.sh
{"jsonrpc":"2.0","result":{"not_ready":false,"batch_id":326800,"start_block":9850414,"end_block":9850527,"poe":{"batch_hash":"0x9fc92b2699dcd97f0f22d81e13d316d76751de67bfbc3c6afd023b05ca930f37","state_hash":"0xc0eff2fa84b7e0591d49994fed63d0ca9e69f77f9658caec93c7f452a18c0808","prev_state_root":"0x02b0659557cbef26689ca30067bd17658b55db5555aeffeb60025ede53e7fefb","new_state_root":"0x15277dcb70eabc3703a816f470f9b9f05aa4272d232ca6c7ced84d4874f5bb0e","withdrawal_root":"0x0aaa5af01432a5037adc40237e9f88c1059de1c207fe1b5287a595cd94c729d3","signature":"0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}},"id":1}
```