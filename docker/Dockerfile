FROM ubuntu:20.04 as builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update

RUN apt install -y unzip lsb-release debhelper cmake reprepro autoconf automake bison build-essential curl dpkg-dev expect flex gcc-8 gdb git git-core gnupg kmod libboost-system-dev libboost-thread-dev libcurl4-openssl-dev libiptcdata0-dev libjsoncpp-dev liblog4cpp5-dev libprotobuf-dev libssl-dev libtool libxml2-dev ocaml ocamlbuild protobuf-compiler python-is-python3 texinfo uuid-dev vim wget software-properties-common clang perl pkgconf libboost-dev libsystemd0

RUN rm -rf /var/lib/apt/lists/*

ENV rust_toolchain nightly-2021-11-01
ENV CODENAME                focal
ENV VERSION                 2.19.100.3-focal1
ENV DCAP_VERSION            1.16.100.2-focal1
ENV AZ_DCAP_CLIENT_VERSION  1.12.0

RUN cd /root && \
    wget https://download.01.org/intel-sgx/sgx-linux/2.19/as.ld.objdump.r4.tar.gz && \
    tar xzf as.ld.objdump.r4.tar.gz && \
    cp -r external/toolset/ubuntu20.04/* /usr/bin/ && \
    rm -rf ./external ./as.ld.objdump.r4.tar.gz

RUN cd /root && \
    curl 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init' --output /root/rustup-init && \
    chmod +x /root/rustup-init && \
    echo '1' | /root/rustup-init --default-toolchain ${rust_toolchain} --profile minimal && \
    echo 'source /root/.cargo/env' >> /root/.bashrc && \
    rm /root/rustup-init && rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git

ENV SDK_URL="https://download.01.org/intel-sgx/sgx-linux/2.19/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.19.100.3.bin"
RUN cd /root && \
    curl -o sdk.sh $SDK_URL && \
    chmod a+x /root/sdk.sh && \
    echo -e 'no\n/opt' | ./sdk.sh && \
    echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    cd /root && \
    rm ./sdk.sh

RUN curl -fsSL  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - && \
    add-apt-repository "deb https://download.01.org/intel-sgx/sgx_repo/ubuntu $CODENAME main" && \
    echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | tee /etc/apt/sources.list.d/msprod.list && \
    wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y \
        libsgx-headers=$VERSION \
        libsgx-ae-epid=$VERSION \
        libsgx-ae-le=$VERSION \
        libsgx-ae-pce=$VERSION \
        libsgx-aesm-ecdsa-plugin=$VERSION \
        libsgx-aesm-epid-plugin=$VERSION \
        libsgx-aesm-launch-plugin=$VERSION \
        libsgx-aesm-pce-plugin=$VERSION \
        libsgx-aesm-quote-ex-plugin=$VERSION \
        libsgx-enclave-common=$VERSION \
        libsgx-enclave-common-dev=$VERSION \
        libsgx-epid=$VERSION \
        libsgx-epid-dev=$VERSION \
        libsgx-launch=$VERSION \
        libsgx-launch-dev=$VERSION \
        libsgx-quote-ex=$VERSION \
        libsgx-quote-ex-dev=$VERSION \
        libsgx-uae-service=$VERSION \
        libsgx-urts=$VERSION \
        sgx-aesm-service=$VERSION \
        libsgx-dcap-ql=$DCAP_VERSION \
        libsgx-dcap-ql-dev=$DCAP_VERSION \
        libsgx-dcap-quote-verify=$DCAP_VERSION \
        libsgx-dcap-quote-verify-dev=$DCAP_VERSION \
        libsgx-dcap-default-qpl=$DCAP_VERSION \
        libsgx-dcap-default-qpl-dev=$DCAP_VERSION \
        libsgx-ae-qve=$DCAP_VERSION \
        libsgx-ae-qe3=$DCAP_VERSION \
        libsgx-pce-logic=$DCAP_VERSION \
        libsgx-qe3-logic=$DCAP_VERSION \
        libsgx-ra-network=$DCAP_VERSION \
        libsgx-ra-uefi=$DCAP_VERSION && \
    apt install -y az-dcap-client=$AZ_DCAP_CLIENT_VERSION && \
    mkdir /var/run/aesmd && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

ENV LD_LIBRARY_PATH=/usr/lib:/usr/local/lib
ENV LD_RUN_PATH=/usr/lib:/usr/local/lib
ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/opt/sgxsdk/sdk_libs"
ENV RUSTFLAGS='-L /opt/intel/sgxsdk/lib64/'
ENV PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.cargo/bin'
ENV SGX_SDK='/opt/sgxsdk'
ENV PKG_CONFIG_PATH='/opt/sgxsdk/pkgconfig'
ENV SGX=1
ENV RELEASE=1

WORKDIR /workspace

ARG CACHE_DATE=1
COPY . /workspace/source
RUN --mount=type=cache,target=/root/.cargo/registry/index \
    --mount=type=cache,target=/root/.cargo/registry/cache \
    --mount=type=cache,target=/root/.cargo/git \
    BUILD=1 RELEASE=1 source/scripts/prover.sh

RUN cp /usr/lib/libdcap_quoteprov.so /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1.13.103.2
RUN cp source/bin/sgx/target/release/sgx-prover /workspace
RUN cp source/bin/sgx/target/release/sgx_prover_enclave.signed.so /workspace
RUN cp source/docker/entrypoint.sh /workspace
RUN rm -r source

ENV RUST_LOG=debug
ENTRYPOINT ["/workspace/entrypoint.sh"]
