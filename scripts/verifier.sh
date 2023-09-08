#!/bin/bash

cd $(dirname $0)/../verifier

function node() {
	npx hardhat node
}

function geth() {
	env geth --dev --dev.period 2 --http --http.api eth,web3,net,debug --http.corsdomain "*" --ws --ws.api eth,web3,net,debug --ws.origins '*' -gcmode=archive
}

function deploy() {
	npx hardhat --network localhost run ./scripts/deploy.ts
}

$@
