#!/bin/bash -e

pkg=$1
if [[ "$pkg" == "" ]]; then
pkg="*"
fi

ls src/apps/$pkg/Cargo.toml | while read path; do
    cd $(dirname $path);
    echo ===============================================================
    echo $(dirname $path);
    echo ===============================================================
    echo "std build:"
    cargo build
    echo ===============================================================
    echo "enclave build:"
    cargo build --features tstd --no-default-features
    cd -
done
