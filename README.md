# SGX Prover

SGX Prover is a prover running SGX enclave, as a component of [multi-prover-avs](https://github.com/automata-network/multi-prover-avs).

SGX Prover utilizing the [automata-sgx-builder](https://github.com/automata-network/automata-sgx-builder) to build the SGX app.

Currently SGX prover supports to execute scroll/linea blocks in SGX enclave and generate the PoE (proof of execution).

# Packages

Check in [here](https://github.com/automata-network/sgx-prover/pkgs/container/sgx-prover) if you are looking for a docker image. It's built from [Dockerfile](avs/docker/Dockerfile).

# Build from source

### System Dependencies

Check the [Dockerfile](avs/docker/Dockerfile) for installing the dependencies.

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