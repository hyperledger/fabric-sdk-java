#!/bin/bash -e
set -euo pipefail

# FABRIC_VERSION is overridden by CI pipeline
FABRIC_VERSION=${FABRIC_VERSION:-2.2}
CA_VERSION=${CA_VERSION:-1.5}

for image in peer orderer tools ccenv baseos javaenv nodeenv; do
	docker pull -q "hyperledger/fabric-${image}:${FABRIC_VERSION}"
	docker tag "hyperledger/fabric-${image}:${FABRIC_VERSION}" "hyperledger/fabric-${image}"
done

docker pull -q "hyperledger/fabric-ca:${CA_VERSION}"
docker tag "hyperledger/fabric-ca:${CA_VERSION}" hyperledger/fabric-ca
