#!/bin/bash -e
set -euo pipefail

# FABRIC_VERSION is set overridden by CI pipeline
VERSION=${FABRIC_VERSION:-2.2}
STABLE_TAG=amd64-${VERSION}-stable

for image in peer orderer tools ccenv baseos javaenv nodeenv; do
	docker pull -q hyperledger-fabric.jfrog.io/fabric-${image}:${STABLE_TAG}
	docker tag hyperledger-fabric.jfrog.io/fabric-${image}:${STABLE_TAG} hyperledger/fabric-${image}
	docker rmi -f hyperledger-fabric.jfrog.io/fabric-${image}:${STABLE_TAG} >/dev/null
done

docker pull -q hyperledger/fabric-ca:1.4
docker tag hyperledger/fabric-ca:1.4 hyperledger/fabric-ca
docker rmi -f hyperledger/fabric-ca:1.4 >/dev/null
