FROM ghcr.io/automata-network/automata-sgx-sdk:v0.2_ubuntu-20.04

WORKDIR /workspace

ARG CACHE_DATE=1
ARG BUILD_TAG
ENV BUILD_TAG=${BUILD_TAG}

COPY . /workspace/source

RUN --mount=type=cache,target=/root/.cargo/registry/index \
    --mount=type=cache,target=/root/.cargo/registry/cache \
    --mount=type=cache,target=/root/.cargo/git \
    cargo install cargo-sgx

RUN --mount=type=cache,target=/root/.cargo/registry/index \
    --mount=type=cache,target=/root/.cargo/registry/cache \
    --mount=type=cache,target=/root/.cargo/git \
    cd /workspace/source && cargo sgx build --release

RUN cp source/target/release/sgx-prover /workspace
RUN cp source/target/release/*.signed.so /workspace
RUN cp source/docker/entrypoint.sh /workspace
RUN rm -r source

ENTRYPOINT ["/workspace/entrypoint.sh"]
