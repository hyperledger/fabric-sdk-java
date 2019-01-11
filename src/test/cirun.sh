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
export ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CLIENT_AUTH_REQUIRED=true

export ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE
export ORG_HYPERLEDGER_FABRIC_CA_SDK_LOGLEVEL=TRACE
export ORG_HYPERLEDGER_FABRIC_SDK_LOG_EXTRALOGLEVEL=10

export ORG_HYPERLEDGER_FABRIC_SDK_PROPOSAL_WAIT_TIME=55000
export ORG_HYPERLEDGER_FABRIC_SDK_CHANNELCONFIG_WAIT_TIME=20000
export ORG_HYPERLEDGER_FABRIC_SDK_CLIENT_TRANSACTION_CLEANUP_UP_TIMEOUT_WAIT_TIME=65000
export ORG_HYPERLEDGER_FABRIC_SDK_ORDERER_ORDERERWAITTIMEMILLISECS=180000
export ORG_HYPERLEDGER_FABRIC_SDK_PEER_EVENTREGISTRATION_WAIT_TIME=180000
export ORG_HYPERLEDGER_FABRIC_SDK_EVENTHUB_CONNECTION_WAIT_TIME=180000
export ORG_HYPERLEDGER_FABRIC_SDK_CHANNEL_GENESISBLOCK_WAIT_TIME=180000

# TEST TIMES
export ORG_HYPERLEDGER_FABRIC_SDKTEST_INVOKEWAITTIME=300000
export ORG_HYPERLEDGER_FABRIC_SDKTEST_DEPLOYWAITTIME=1300000
export ORG_HYPERLEDGER_FABRIC_SDKTEST_PROPOSALWAITTIME=300000

export ORG_HYPERLEDGER_FABRIC_SDKTEST_RUNIDEMIXMTTEST=true

ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION=${ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION:-}
ORG_HYPERLEDGER_FABRIC_SDKTEST_FIXVERSION=${ORG_HYPERLEDGER_FABRIC_SDKTEST_FIXVERSION:-}

if [ -z $ORG_HYPERLEDGER_FABRIC_SDKTEST_FIXVERSION ];then
dotcount="${ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION//\.}"
if [ "3" == "${#dotcount}" ];then
export ORG_HYPERLEDGER_FABRIC_SDKTEST_FIXVERSION=${ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION%.*}
else
export ORG_HYPERLEDGER_FABRIC_SDKTEST_FIXVERSION=$ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION
fi
fi

case "$ORG_HYPERLEDGER_FABRIC_SDKTEST_FIXVERSION" in
"1.0")
    export ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CLIENT_AUTH_REQUIRED=false
    #Options starting fabric-ca in docker-compose.yaml which are not supported on v1.0
    export V11_IDENTITIES_ALLOWREMOVE=""
    export V11_AFFILIATIONS_ALLOWREMOVE=""
    #set which images we pull for docker-compose.yaml when starting Fabric.
    export IMAGE_TAG_FABRIC=:x86_64-1.0.6
    export IMAGE_TAG_FABRIC_CA=:x86_64-1.0.6
    # set which Fabric  generated configuations is used.
    export FAB_CONFIG_GEN_VERS="v1.0"
    ;;
"1.1" )
   export IMAGE_TAG_FABRIC=:x86_64-1.1.1
   export IMAGE_TAG_FABRIC_CA=:x86_64-1.1.1
   export FAB_CONFIG_GEN_VERS="v1.1"
   ;;
"1.2" )
   export IMAGE_TAG_FABRIC=:1.2.1
   export IMAGE_TAG_FABRIC_CA=:1.2.1
   export FAB_CONFIG_GEN_VERS="v1.2"
   ;;
 "1.3" )
   export IMAGE_TAG_FABRIC=:1.3.0
   export IMAGE_TAG_FABRIC_CA=:1.3.0
   export FAB_CONFIG_GEN_VERS="v1.3"
   ;;
"1.4" )
   export IMAGE_TAG_FABRIC=:1.4
   export IMAGE_TAG_FABRIC_CA=:1.4
   export FAB_CONFIG_GEN_VERS="v1.3"  # not a copy/paste error :)
   ;;
*)
#export FAB_CONFIG_GEN_VERS="v1.3"
    # cleans out an existing imgages...
#(docker images -qa | sort | uniq | xargs docker rmi -f) || true
#(docker images -qa | sort | uniq | xargs docker rmi -f) || true
#(docker images -qa | sort | uniq | xargs docker rmi -f) || true

#everything just defaults for latest (v1.1)
#unset to use what's in docker's .env file.
unset IMAGE_TAG_FABRIC
unset IMAGE_TAG_FABRIC_CA
    ;;
esac


echo "environment:--------------------"
env | sort
echo "---------------------------------"
echo "java version:--------------------"
java -XshowSettings:properties -version
echo "---------------------------------"
echo "mvn version:--------------------"
mvn --version
echo "---------------------------------"

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
#export MAVEN_OPTS="-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn -DforkCount=0"
export MAVEN_OPTS="-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn"
mvn -B clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc
docker images
docker ps -a
