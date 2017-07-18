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

cd $WD/src/test/fixture/sdkintegration
./fabric.sh restart >dockerlogfile.log 2>&1 &
cd $WD
sleep 30
docker images
docker ps -a
export ORG_HYPERLEDGER_FABRIC_SDK_DIAGNOSTICFILEDIR=target/diagDump
mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc
docker images
docker ps -a
