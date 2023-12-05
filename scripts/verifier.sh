#!/bin/bash

cd $(dirname $0)/../verifier

function node() {
	npx hardhat node
}

function geth() {
	env geth --dev --dev.period 2 --http --http.api eth,web3,net,debug --http.corsdomain "*" --ws --ws.api eth,web3,net,debug --ws.origins '*' -gcmode=archive --http.port 18545 --ws.port 18546
}

function deploy() {
	_run ./scripts/deploy.ts
}

function add_mrenclave() {
	_run ./scripts/add_mrenclave.ts
}

function _run() {
	if [[ "$URL" != "" ]]; then
		npx hardhat --network custom run $@	
	else
		npx hardhat --network l1 run $@	
	fi
}

$@
