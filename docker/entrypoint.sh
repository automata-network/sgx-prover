#!/bin/bash
unset SGX_AESM_ADDR
cd /workspace
./sgx-prover "$@"
