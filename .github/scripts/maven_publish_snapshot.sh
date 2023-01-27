#!/usr/bin/env bash

set -eu -o pipefail

POM_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:evaluate -Dexpression=project.version -q -DforceStdout)
RELEASE_VERSION="${POM_VERSION%%-*}"
PUBLISH_VERSION="${RELEASE_VERSION}-SNAPSHOT"

mvn --batch-mode --no-transfer-progress versions:set -DnewVersion="${PUBLISH_VERSION}"
mvn --batch-mode --no-transfer-progress --activate-profiles release -DskipTests deploy
