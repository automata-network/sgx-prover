#!/bin/bash
source $(dirname $0)/executor.sh
if [[ "$NETWORK" == "" ]]; then
    NETWORK=localhost
fi

APP=prover execute $@
