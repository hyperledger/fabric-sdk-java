#!/usr/bin/env bash

set -eu -o pipefail

PUBLISH_PROFILE="${1:?}"

POM_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:evaluate -Dexpression=project.version -q -DforceStdout)
PUBLISH_VERSION="${POM_VERSION%%-*}"

mvn --batch-mode --no-transfer-progress versions:set -DnewVersion="${PUBLISH_VERSION}"
mvn --batch-mode --no-transfer-progress --activate-profiles "release,${PUBLISH_PROFILE}" -DskipTests deploy
