#!/usr/bin/env bash
#Script for continuous integration run.  Cleanup, start docker containers for fabric and fabric ca
#Start integration tests.
# expect WD env set HLJSDK directory.
cd $WD/src/test/fixture/src
rm -rf /tmp/keyValStore*; rm -rf  /tmp/kvs-hfc-e2e ~/test.properties; rm -rf /var/hyperledger/*
docker-compose up > dockerlogfile.log 2>&1 &
cd $WD
sleep 30
docker ps -a
mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false