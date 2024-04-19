#!/bin/bash
if [[ "$BUILD_TAG" == "" ]]; then
	echo "usage: BUILD_TAG is empty"
	exit 1
fi
cd $(dirname $0)/..
docker buildx build -f docker/Dockerfile -t ghcr.io/automata-network/sgx-prover:avs-${BUILD_TAG} --load .
