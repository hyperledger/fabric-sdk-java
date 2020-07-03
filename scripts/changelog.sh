#!/bin/sh
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

if [ $# -ne 2 ]; then
    echo 'Missing required arguments: lastReleaseCommitHash releaseVersion' >&2
    exit 1
fi

echo "## $2\n$(date)" >> CHANGELOG.new
echo "" >> CHANGELOG.new
git log $1..HEAD  --oneline | grep -v Merge | sed -e "s/\[\(FAB-[0-9]*\)\]/\[\1\](https:\/\/jira.hyperledger.org\/browse\/\1\)/" -e "s/\([0-9|a-z]*\)/* \[\1\](https:\/\/github.com\/hyperledger\/fabric-sdk-java\/commit\/\1)/" >> CHANGELOG.new
echo "" >> CHANGELOG.new
cat CHANGELOG.md >> CHANGELOG.new
mv -f CHANGELOG.new CHANGELOG.md
