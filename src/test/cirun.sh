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

export ORG_HYPERLEDGER_FABRIC_SDK_PROPOSAL_WAIT_TIME=25000
export ORG_HYPERLEDGER_FABRIC_SDK_CHANNELCONFIG_WAIT_TIME=20000
export ORG_HYPERLEDGER_FABRIC_SDK_CLIENT_TRANSACTION_CLEANUP_UP_TIMEOUT_WAIT_TIME=65000
export ORG_HYPERLEDGER_FABRIC_SDK_ORDERER_ORDERERWAITTIMEMILLISECS=180000
export ORG_HYPERLEDGER_FABRIC_SDK_PEER_EVENTREGISTRATION_WAIT_TIME=180000
export ORG_HYPERLEDGER_FABRIC_SDK_EVENTHUB_CONNECTION_WAIT_TIME=180000
export ORG_HYPERLEDGER_FABRIC_SDK_CHANNEL_GENESISBLOCK_WAIT_TIME=180000

# TEST TIMES
export ORG_HYPERLEDGER_FABRIC_SDKTEST_INVOKEWAITTIME=300000
export ORG_HYPERLEDGER_FABRIC_SDKTEST_DEPLOYWAITTIME=300000
export ORG_HYPERLEDGER_FABRIC_SDKTEST_PROPOSALWAITTIME=300000

ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION=${ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION:-}

if [ "$ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION" == "1.0.0" ]; then
# Limit the test run for V1.0
export ORG_HYPERLEDGER_FABRIC_SDKTEST_ITSUITE="-Dorg.hyperledger.fabric.sdktest.ITSuite=IntegrationSuiteV1.java"
#Options starting fabric-ca in docker-compose.yaml which are not supported on v1.0
export V11_IDENTITIES_ALLOWREMOVE=""
export V11_AFFILIATIONS_ALLOWREMOVE=""
#set which images we pull for docker-compose.yaml when starting Fabric.
export IMAGE_TAG_FABRIC=:x86_64-1.0.0
export IMAGE_TAG_FABRIC_CA=:x86_64-1.0.0
# set which Fabric  generated configuations is used.
export FAB_CONFIG_GEN_VERS="v1.0"
else
#everything just defaults for latest (v1.1)
export ORG_HYPERLEDGER_FABRIC_SDKTEST_ITSUITE=""
#unset to use what's in docker's .env file.
unset IMAGE_TAG_FABRIC
unset IMAGE_TAG_FABRIC_CA
fi

echo "environment:--------------------"
env
echo "environment:--------------------"

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
export MAVEN_OPTS="-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn"
mvn -B clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc ${ORG_HYPERLEDGER_FABRIC_SDKTEST_ITSUITE}
docker images
docker ps -a
