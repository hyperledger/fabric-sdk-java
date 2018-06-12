# Java SDK for Hyperledger Fabric 1.1 release notes.

The JSDK 1.1 has features added since the 1.0 based release to match those added to the Fabric 1.1 release.

## Fabric v1.0 considerations
The SDK is mostly backward compatible with the v1.0 based Fabric with the following considerations
- The new Peer eventing service is the default for the SDK however, in v1.0 Fabric peer eventing service is not supported. To address in applications that are
  connecting to Fabric 1.0 you must when adding or joining a peer to a channel provide a PeerRole option.
  A role with `PeerRole.NO_EVENT_SOURCE` has been defined that has the equivalent functionality of a v1.0 peer.
  You can see an example of this
  in [End2endIT.java#L732](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L732)
  and in [End2endAndBackAgainIT.java#L597](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L597)


## v1.1 Fabric features

### [FAB-6066 JSDK Channel service for events](https://jira.hyperledger.org/browse/FAB-6066)
The Fabric peer now implements eventing services on the same endpoint as proposal endorsements and it is no longer necessary to have an EventHub service.  Using peer
eventing is the preferred means for receiving events.  Future releases of Fabric may not support Eventhubs. When joining or adding Peers to a channel the default is
to have the peer provide the eventing service. Whether a peer is an eventing or non-eventing is controlled by the peer options when adding or joining
a channel.You can see an example of this in [End2endIT.java#L732](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L732)
and in [End2endAndBackAgainIT.java#L597](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L597)

Peers may be added to a channel with specific roles to help with distributing the workload. PeerRoles are defined in [Peer.java#L328](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/main/java/org/hyperledger/fabric/sdk/Peer.java#L328)
The default is for Peers to have all roles.


The new peer eventing services will by default just return the last block on the blockchain. Note this is *not* the **next** block that gets
added to the chain.  The application can now specify both the starting and ending block number to be sent. Applications set these
options when adding or joining peers to the channel with the PeerOption methods *startEvents*, *stopEvents* and *startEventsNewest* which
is the default. [End2endAndBackAgainIT.java#L234-L257](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L234-L257)
calls the method [`testPeerServiceEventingReplay`](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L719-L881) which restarts the channel with different start and stop values.



### [FAB-7652 JSDK filterblock enablement](https://jira.hyperledger.org/browse/FAB-7652)

Fabric supports on the new peer eventing service limits to what the events return though ACLs.  The block event may contain the full Block or a FilteredBlock.
Applications requesting for a full Block without authority will get a permission failure.  Application by default will get the full block. To request
request a FiltedBlock when adding or joining peers applications can add via PeerOptions.registerEventsForFilteredBlocks. An example of this is seen in
[End2endAndBackAgainIT.java#L592-595](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L592-L595)

Application's that register block listeners need to be written to check for *isFiltered()" to know if the block is full or filtered.

Filtered blocks are limited to the following methods.

FilteredBlocks
 - isFiltered should return true
 - getChannelId the channel name
 - getFilteredBlock the raw filtered block
 - getBlockNumber blocknumber
 - getEnvelopeCount number of envelopes
 - getEnvelopeInfo index into envelopes.
 - getEnvelopeInfos interator on envelopes

 EnvelopeInfo
 - getChannelId channel name
 - getTransactionID the transaction id
 - isValid was the transaction valid.
 - getType the type of envelope

 TransactionEnvelopeInfo all the methods on EnvelopeInfo
 - getTransactionActionInfoCount number transactions
 - getTransactionActionInfos an iterator over all the TransactionAction

 TransactionActionInfo
 - getEvent chaincode events


### [FAB-6603 Java SDK CryptoPrimitives should perform Signature operations using standard JCA/JCE](https://jira.hyperledger.org/browse/FAB-6603)
Changes made to make the Java SDK crypto primitives to use more JCA/JCE compliant methods. These changes are internal and not
directly apparent to the application. This allows specifying other JCA/JCE provider.

### [FAB-5632 Implement "Connection Profile" for java-sdk](https://jira.hyperledger.org/browse/FAB-5632)
Allow creating channels from a yaml or json specified document. Examples of this can be found in [NetworkConfigIT.java#L65](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/NetworkConfigIT.java#L65)

### [FAB-5387 Provide listener for custom chaincode events.](https://jira.hyperledger.org/browse/FAB-5387)
Allow application to register for specific events triggered by chaincode. Example of this can be found in
[End2endIT.java#L303](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L303)

The registerChaincodeEventListener method on the channel registers a call back that matches via a Java pattern on both the event name and the
chaincodeId.  When ledger block with an event that matches that criteria specified is found by event hub or new peer event service the
callback is called to handle the event.

### [FAB-8392 Include META-INF in chaincode packaging.](https://jira.hyperledger.org/browse/FAB-8392)
When installing chaincode, need to package CouchDB indexes in chaincode tar. See [InstallProposalRequest.java#L35](https://github.com/hyperledger/fabric-sdk-java/blob/6ef1bc801dfdb8533952b69f11fe712dffc5aa91/src/main/java/org/hyperledger/fabric/sdk/InstallProposalRequest.java#L35-L45)
Details for this can be found in the Fabric documentation [Using CouchDB from Chaincode](http://hyperledger-fabric.readthedocs.io/en/master/couchdb_as_state_database.html#using-couchdb-from-chaincode)

### [FAB-6200 Java serialize channels.](https://jira.hyperledger.org/browse/FAB-6200)
Channels can be Java serialized and deserialized.  Examples of this can be found throughout the integration tests. Example of serialization
in [End2endIT.java#L257](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L257)
where the sample store stores channel bar. Later in [End2endAndBackAgainIT.java#L562](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L562-L565)
it's restored.
*Applications using this serialization means will be tasked with any migrating future changes. The SDK will not do this.*
It's advised to use a different persistence means for saving and restoring channels

### [FAB-7324 JSDK Node CC example](https://jira.hyperledger.org/browse/FAB-7324)
The JSDK added support for installing deploying Node chaincode.
Example of this integration tests show mostly overriding the GO chaincode EndendIT.java as they are mostly treated the same.
See [End2endNodeIT.java#L23](https://github.com/hyperledger/fabric-sdk-java/blob/6ef1bc801dfdb8533952b69f11fe712dffc5aa91/src/test/java/org/hyperledger/fabric/sdkintegration/End2endNodeIT.java#L23-L62)

### [FAB-7949 fabric-sdk-java Utilize TLS binding information and timestamp in eventhub registration messages](https://jira.hyperledger.org/browse/FAB-7949)
Not directly exposed in the API, however when utilizing TLS mutual auth the client will add hashing of the client certificate in
event registration for both peer eventing and Eventhub to prevent replay attacks.

### [FAB-8842 Channel initialize and retry recovery.](https://jira.hyperledger.org/browse/FAB-8842)
Channel will now initialize without needing to connect to peers.  There may still be warning and error messages.
Even with the channel initialized however the lack of functioning Peers will possible prevent other operations from completing.
If Peers come back online eventing services will reconnect.

On many APIs the addition of specifying a user context was added to allow thread safe invocation.

Many APIs where a peer was needed was enhanced to try all defined Peers till successful or all failed.

### [FAB-8897 Customize transaction event handling.](https://jira.hyperledger.org/browse/FAB-8897)
Enhanced application control over sending request to the orderer.  Prior to this change all Java futures returned by sendTransation would only
be completed when all channel defined Eventhubs and peer eventing services seen the block with the specific
transaction.  This is still the default, but now can be changed with [TransactionOptions](https://github.com/hyperledger/fabric-sdk-java/blob/6ef1bc801dfdb8533952b69f11fe712dffc5aa91/src/main/java/org/hyperledger/fabric/sdk/Channel.java#L3082-L3167)
Example of this which mostly shows the defaults is in [End2endIT.java#L517](https://github.com/hyperledger/fabric-sdk-java/blob/6ef1bc801dfdb8533952b69f11fe712dffc5aa91/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L517-L534)

## v1.1 Fabric/CA features

### [FAB-7383 Implement the Fabric-CA identities and affiliations API](https://jira.hyperledger.org/browse/FAB-7383)
Fabric CA API added APIs for managing identities and affiliations. Examples how this can be done with Java SDK on how to
create, modify, read and delete are in [HFCAClientIT.java#L514-L658](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric_ca/sdkintegration/HFCAClientIT.java#L514-L658)
for identities and [HFCAClientIT#L704](https://github.com/hyperledger/fabric-sdk-java/blob/09f386c340e157e2a4f3f5cdde85e340f4586923/src/test/java/org/hyperledger/fabric_ca/sdkintegration/HFCAClientIT.java#L704-L1015)
for affiliations.

### [FAB-6411 Add Java SDK support for gencrl endpoint](https://jira.hyperledger.org/browse/FAB-6411)
Support for getting certificate revocation list from Fabric-ca was added to the HFCAClient's **generateCRL** method.
Examples of this are in the integration tests that call [HFCAClientIT.java getRevokes method](https://github.com/hyperledger/fabric-sdk-java/blob/224f569d9d1f1f77e5d22e8e0c78f3d4e298b3fc/src/test/java/org/hyperledger/fabric_ca/sdkintegration/HFCAClientIT.java#L496-L500)