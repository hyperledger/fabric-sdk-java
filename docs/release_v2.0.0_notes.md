# Java SDK for Hyperledger Fabric 2.0 release notes.

## Fabric changes.
### [FABJ-288 Lifecycle chaincode management](https://jira.hyperledger.org/browse/FABJ-288)
The SDK continues to support managing chaincode using the pre v2.0 lifecycle APIs, but they are now deprecated. The new v2.0 Fabric Lifecycle
chaincode APIs are fully supported. Note however, that channels need to enable v2.0 capabilities to use the new lifecycle APIs. Once
v2.0 capabilities are enabled the deprecated pre v2.0 APIs ( [InstallProposalRequest](https://github.com/hyperledger/fabric-sdk-java/blob/df422e10fa38bf8a627dd81e7ad038404d625576/src/main/java/org/hyperledger/fabric/sdk/InstallProposalRequest.java), [InstantiateProposalRequest](https://github.com/hyperledger/fabric-sdk-java/blob/df422e10fa38bf8a627dd81e7ad038404d625576/src/main/java/org/hyperledger/fabric/sdk/InstantiateProposalRequest.java),
[UpgradeProposalRequest](https://github.com/hyperledger/fabric-sdk-java/blob/df422e10fa38bf8a627dd81e7ad038404d625576/src/main/java/org/hyperledger/fabric/sdk/UpgradeProposalRequest.java) ) can no longer be used to manage any chaincode using that channel.

The v2.0 Lifecycle can require organizations to endorse (consent) to new chaincode being run on the channel. The default is to require a majority of organizations on the channel
 to endorse chaincode before it can be run.  For more details on Lifecycle chaincode management see [Fabric read the docs: Chaincode for Operators](https://hyperledger-fabric.readthedocs.io/en/latest/chaincode4noah.html)

The [End2endLifecycleIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/df422e10fa38bf8a627dd81e7ad038404d625576/src/test/java/org/hyperledger/fabric/sdkintegration/End2endLifecycleIT.java) integration test
tests and demonstrates these APIs between two organizations.

## Java SDK enhancements
### [FABJ-430 Networkconfig handlers](https://jira.hyperledger.org/browse/FABJ-430)
Applications can now register _handlers_ for both Peers and Orderers that the connection document defines to allow the applications a means to control adding any additional
properties on Peers and Orderers before they are added to the channel.
An example of defining a Peer handler is shown [NetworkConfigTest testPeerOrdererOverrideHandlers ](https://github.com/hyperledger/fabric-sdk-java/blob/df422e10fa38bf8a627dd81e7ad038404d625576/src/test/java/org/hyperledger/fabric/sdk/NetworkConfigTest.java#L425-L439)
and a [handler for Orderers](https://github.com/hyperledger/fabric-sdk-java/blob/df422e10fa38bf8a627dd81e7ad038404d625576/src/test/java/org/hyperledger/fabric/sdk/NetworkConfigTest.java#L441450:)

### [FABJ-428 Provide queued block event listener](https://jira.hyperledger.org/browse/FABJ-428)
Previously applications could register an event handler to get notified when any blocks were commited to a peer's ledger by getting a callback on another thread. A new
handler is now available allowing applications to register a handler with a Java blocking queue that block events will be added as the SDK detects blocks are committed on a peer's ledger.
Examples of registering this handler is shown in [UpdateChannelIT](https://github.com/hyperledger/fabric-sdk-java/blob/df422e10fa38bf8a627dd81e7ad038404d625576/src/test/java/org/hyperledger/fabric/sdkintegration/UpdateChannelIT.java#L417:L423)
### [FABJ-404 Application set Executor Service](https://jira.hyperledger.org/browse/FABJ-404)
The SDK creates it's own threads through a Java Executor services. This change allows applications to supply their own. This is really needed except in cases of
some managed environments that want to control their own thread pools.
