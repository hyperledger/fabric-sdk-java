# Releasing

The following artifacts are created as a result of releasing the Hyperledger Fabric SDK for Java:

- [fabric-sdk-java](https://central.sonatype.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java/2.2.0/versions)

## Before releasing

The following tasks are required before releasing:

- Check that the last merge or scheduled build for the release branch passed successfully. 

## Create release

Creating a GitHub release on the [releases page](https://github.com/hyperledger/fabric-sdk-java/releases) will trigger the build to publish the new release.

When drafting the release, create a new tag for the new version (with a `v` prefix), e.g. `vX.Y.Z`

See previous releases for examples of the title and description.

## After releasing

The following tasks are required after releasing:

- Update the `version` element in [pom.xml](pom.xml) to the next point release.
