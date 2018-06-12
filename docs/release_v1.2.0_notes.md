# Java SDK for Hyperledger Fabric 1.2 release notes.

The JSDK 1.2 has features added since the 1.2 based release to match those added to the Fabric 1.2 release.

## Fabric v1.0 and v1.1 considerations
The SDK is mostly backward compatible with the v1.x based Fabric with the following considerations
- The new Peer eventing service is the default for the SDK however, in v1.0 Fabric peer eventing service is not supported. To address in applications that are
  connecting to Fabric 1.0 you must when adding or joining a peer to a channel provide a PeerRole option.
  A role with `PeerRole.NO_EVENT_SOURCE` has been defined that has the equivalent functionality of a v1.0 peer.
  You can see an example of this
  in [End2endIT.java#L732](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L732)
  and in [End2endAndBackAgainIT.java#L597](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L597)


## v1.2 Fabric features

### [FAB-9680 private data collection support](https://jira.hyperledger.org/browse/FAB-9680)

Private data collection example is in [src/test/java/org/hyperledger/fabric/sdkintegration/PrivateDataIT.java
](https://github.com/hyperledger/fabric-sdk-java/blob/edd54f832351452ef6aea3d9cb505b2f38b12711/src/test/java/org/hyperledger/fabric/sdkintegration/PrivateDataIT.java)
From the SDK perspective there is very little change from installing, instantiating and invoking chaincode.  The only notable change is in
instantiation. In instantiation there is a requirement to pass in the Instantiation proposal a chaincode collection configuration  with the method `setChaincodeCollectionConfiguration` as seen on
this [line](https://github.com/hyperledger/fabric-sdk-java/blob/edd54f832351452ef6aea3d9cb505b2f38b12711/src/test/java/org/hyperledger/fabric/sdkintegration/PrivateDataIT.java#L246).
The [ChaincodeCollectionConfiguration](https://github.com/hyperledger/fabric-sdk-java/blob/edd54f832351452ef6aea3d9cb505b2f38b12711/src/main/java/org/hyperledger/fabric/sdk/ChaincodeCollectionConfiguration.java)
class allows collection configuration to be loaded from YAML or a json file or object.  Sample collection configuration files
exist in [src/test/fixture/collectionProperties](https://github.com/hyperledger/fabric-sdk-java/tree/edd54f832351452ef6aea3d9cb505b2f38b12711/src/test/fixture/collectionProperties).
[PrivateDataIT.yaml](https://github.com/hyperledger/fabric-sdk-java/blob/edd54f832351452ef6aea3d9cb505b2f38b12711/src/test/fixture/collectionProperties/PrivateDataIT.yaml)
has comments that help explain some of the aspects of configuring private collections.

More details on the concepts of Private Data feature can be found in the Fabric documentation [Private Data](https://hyperledger-fabric.readthedocs.io/en/release-1.2/private-data/private-data.html)

### [FAB-8805 JSDK Service Discovery](https://jira.hyperledger.org/browse/FAB-8805)
Service discovery allows through a collection of peers with a role of `SERVICE_DISCOVERY` to discover :

- Other peers in the network.
- Orderers in the network.
- Discovered names of chaincode that has been discovered in the network.
- Peers needed to endorse invoking a specific chaincode.

An example of this is shown in [src/test/java/org/hyperledger/fabric/sdkintegration/ServiceDiscoveryIT.java](badurl).
Here only a single peer is added to the channel that has a role of `SERVICE_DISCOVERY`.  The chaincode names discovered is reported by the method `getDiscoveredChaincodeNames`
on the channel.  It's shows potentially getting to different endorsements set by setting the discoveryOptions on the method `sendTransactionProposalToEndorsers` The first
set is not used and is only there for illustrate different options. The [DiscoveryOptions](badurl)  allows some control on discovering the needed endorsements


DiscoveryOptions
- `ignoreEndpoints`: Specify endorser endpoints that should not be used.
- `inspectResults`: If service discovery does not find the the needed endorsers for a specific chaincode it will by default throw a ServiceDiscoveryException. Setting
  this to true will have the method return the all the endorsements it did obtained.
- `forceDiscovery`: By default endorsers are found by already cached results. Setting this to true will force ignoring this cache and doing a full discovery before
finding the endorsements needed.
- `endorsementSelector`  The Fabric provided discovery does not find just one possible set of endorsers needed for a specific chaincode, but potentially multiple.  The `endorsementSelector` is code that determines
which endorser should be selected. There are two implemented with the SDK `ENDORSEMENT_SELECTION_RANDOM` and the default `ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT`.
Applications can use their own by implementing the interface `EndorsementSelector` and using the two SDK provided as a reference.

The endorsements are then sent to orderer that was also discovered.

Discovered endpoints for Peers and Orderers does not have all the information to construct the Peer or Orderers. Applications can take control of specifically what
properties and roles by setting on the channel `setSDPeerAddition` for Peers and `setSDOrdererAddition` for orderers.  The `SDOPeerrDefaultAddition`
 that implements `SDPeerAddition` is an example of code that creates a Peer from the discovery information. Similarly for
 the orderer there is `SDOrdererDefaultAddition` that implements `SDOrdererAddition`

More details on service discovery can be found in the Hyperledger Fabric documentation: [Service Discovery](https://hyperledger-fabric.readthedocs.io/en/latest/discovery-overview.html#service-discovery)




## v1.1 Fabric/CA features

### [FAB-10322 HFCAClient needs timeout settings](https://jira.hyperledger.org/browse/FAB-10322)

Configuration timeout properties for HTTP requests to the Fabric CA have been added. The properties
 `org.hyperledger.fabric_ca.sdk.connection.connection_request_timeout`,  `org.hyperledger.fabric_ca.sdk.connection.connect_timeout` and `org.hyperledger.fabric_ca.sdk.connection.socket_timeout`
  can be set and correspond to the HTTP client's equivalent values.
 For more information see [Apache's HTTP RequestConfig.Builder](https://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/client/config/RequestConfig.Builder.html)

### [FAB-9373 Add support for Certificates API on Java SDK](https://jira.hyperledger.org/browse/FAB-9373)

Adds support for managing certificates including deletions. Provides an API to also query for expired certificates and those that are about to expire.
Examples of this API can be seen [HFCAClientIT testGetCerticates](https://github.com/hyperledger/fabric-sdk-java/blob/f80259c0c285a65ee1c5bdeeafaa47d8a9a9d72f/src/test/java/org/hyperledger/fabric_ca/sdkintegration/HFCAClientIT.java#L1102-L1227)