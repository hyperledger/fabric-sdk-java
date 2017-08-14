#!/usr/bin/env bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
#Script for continuous integration run.  Cleanup, start docker containers for fabric and fabric ca
#Start integration tests.
# expect WD env set HLJSDK directory.

# unset ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS
# unset ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CA_TLS
export ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS=true
export ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CA_TLS=--tls.enabled

export ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE
export ORG_HYPERLEDGER_FABRIC_CA_SDK_LOGLEVEL=TRACE
export ORG_HYPERLEDGER_FABRIC_SDK_LOG_EXTRALOGLEVEL=10

ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION=${ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION:-}

if [ "$ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION" == "1.0.0" ]; then
export ORG_HYPERLEDGER_FABRIC_SDKTEST_ITSUITE="-Dorg.hyperledger.fabric.sdktest.ITSuite=IntegrationSuiteV1.java"
else
export ORG_HYPERLEDGER_FABRIC_SDKTEST_ITSUITE=""
fi

cd $WD/src/test/fixture/sdkintegration
./fabric.sh restart >dockerlogfile.log 2>&1 &
sleep 5; #give it this much to start.

cd $WD

i=0

#wait till we get at least one peer started other should not be far behind.
until [ "`docker inspect -f {{.State.Running}} peer1.org2.example.com`" == "true" ]  || [ $i -gt 60 ]; do
   i=$((i + 1))
   echo "Waiting.. $i"
   sleep 10;
done;

sleep 15 # some more time just for the other services .. this should be overkill.

docker images
docker ps -a
export ORG_HYPERLEDGER_FABRIC_SDK_DIAGNOSTICFILEDIR=target/diagDump
mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc ${ORG_HYPERLEDGER_FABRIC_SDKTEST_ITSUITE}
docker images
docker ps -a
