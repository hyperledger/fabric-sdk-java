#!/bin/bash -e
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Script for continuous integration run.  Cleanup, start docker containers for fabric and fabric ca
# Start integration tests.

set -euo pipefail

export ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE
export ORG_HYPERLEDGER_FABRIC_CA_SDK_LOGLEVEL=TRACE
export ORG_HYPERLEDGER_FABRIC_SDK_LOG_EXTRALOGLEVEL=10

# IdeMixTest disabled in Azure Pipelines - it takes too long to run (>2 hours!)
export ORG_HYPERLEDGER_FABRIC_SDKTEST_RUNIDEMIXMTTEST=false

rm -rf "/tmp/HFCSampletest.properties"

cd "$(dirname "$0")"
source pull-fabric-images.sh

pushd ../src/test/fixture/sdkintegration/ >/dev/null
docker-compose up --force-recreate -d
popd >/dev/null && cd ..

docker ps -a

export ORG_HYPERLEDGER_FABRIC_SDK_DIAGNOSTICFILEDIR=target/diagDump
export MAVEN_OPTS="-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn"
mvn -B clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc

pushd src/test/fixture/sdkintegration/ >/dev/null
docker-compose down --volumes
