#!/bin/bash

function execute() {
    cd $(dirname $0)/..
    TARGET_ENV="sgx"
    if [[ "$NOSGX" != "" ]]; then
        TARGET_ENV="std"
    fi

    PKG=$APP
    if [[ "$TARGET_ENV" == "sgx" ]]; then
        PKG="sgx-$PKG"
        if [[ "$INC" == "" ]]; then
            rm -rf bin/sgx/target/*/build/$PKG-*
        fi 
    fi
    dir="bin/$TARGET_ENV/$PKG"

    build_arg=""
    if [[ "$RELEASE" != "" ]]; then
        build_arg=" --release "
    fi

    if [[ "$NETWORK" != "" ]]; then
        CONFIG="-c config/$APP-$NETWORK.json"
    fi

    if [[ "$RUST_LOG" == "" ]]; then
        RUST_LOG="info"
    fi 

    build_arg=" --manifest-path=$dir/Cargo.toml $build_arg"

    if [[ "$BUILD" != "" ]]; then
        cargo build $build_arg 
    else
        RUST_BACKTRACE=1 cargo run $build_arg -- $CONFIG $@
    fi
}