#!/bin/bash
unset SGX_AESM_ADDR
export AZDCAP_DEBUG_LOG_LEVEL=ERROR
cd /workspace
./sgx-prover "$@"
