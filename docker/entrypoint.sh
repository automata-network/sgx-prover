#!/bin/bash
unset SGX_AESM_ADDR
export AZDCAP_DEBUG_LOG_LEVEL=INFO
cd /workspace
./sgx-prover "$@"
