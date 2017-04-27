#!/usr/bin/env bash
#Script for continuous integration run.  Cleanup, start docker containers for fabric and fabric ca
#Start integration tests.
# expect WD env set HLJSDK directory.

unset ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS
unset ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CA_TLS
# export ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS=true
# export ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CA_TLS=--tls.enabled

export ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE
export ORG_HYPERLEDGER_FABRIC_CA_SDK_LOGLEVEL=TRACE

cd $WD/src/test/fixture/sdkintegration
rm -rf /tmp/keyValStore*; rm -rf  /tmp/kvs-hfc-e2e ~/test.properties; rm -rf /var/hyperledger/*
docker-compose up >dockerlogfile.log 2>&1 &
cd $WD
sleep 30
docker ps -a
mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false
