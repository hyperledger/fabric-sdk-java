# Java SDK for Hyperledger Fabric 1.3 release notes.

The JSDK 1.3 has features added since the 1.2 based release to match those added to the Fabric 1.3 release.

## Fabric v1.0 and v1.1 considerations
The SDK is mostly backward compatible with the v1.x based Fabric with the following considerations
- The new Peer eventing service is the default for the SDK however, in v1.0 Fabric peer eventing service is not supported. To address in applications that are
  connecting to Fabric 1.0 you must when adding or joining a peer to a channel provide a PeerRole option.
  A role with `PeerRole.NO_EVENT_SOURCE` has been defined that has the equivalent functionality of a v1.0 peer.
  You can see an example of this
  in [End2endIT.java#L732](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L732)
  and in [End2endAndBackAgainIT.java#L597](https://github.com/hyperledger/fabric-sdk-java/blob/9224fa3f45a70392d1b244c080bf41bd561470d3/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java#L597)


## v1.3 Fabric features


### [FABJ-355 Run Java chaincode](https://jira.hyperledger.org/browse/FABJ-355)
Fabric v1.3 now officially supporting Java chaincode an example of Java chaincode, deployment, and invocation was added to the Java SDK.
The only difference between Java and the other supported languages is when installing it is setChaincodeLanguage is `Type.JAVA` and
chaincode is of course is written in Java.  The similarity, is shown by the sample JSDK to do the deployment and invocation of the Java
chaincode is just subclassed from the GO example.  [End2endJavaIT SDK Java deployment ](https://github.com/hyperledger/fabric-sdk-java/blob/ef604d1fd3bc12eeed9910036f24e4a4953156c4/src/test/java/org/hyperledger/fabric/sdkintegration/End2endJavaIT.java)
The deployed Java chaincode is [Java chaincode example](https://github.com/hyperledger/fabric-sdk-java/tree/ef604d1fd3bc12eeed9910036f24e4a4953156c4/src/test/fixture/sdkintegration/javacc/sample1)

### [FABJ-375 Query for a chaincode's collection configuration](https://jira.hyperledger.org/browse/FABJ-357)
An API `queryCollectionsConfig` added to the channel to retrieve what chaincode collections a specific chaincode uses was added. An example of invoking this API was added
to [PrivateDataIT test.](https://github.com/hyperledger/fabric-sdk-java/blob/ef604d1fd3bc12eeed9910036f24e4a4953156c4/src/test/java/org/hyperledger/fabric/sdkintegration/PrivateDataIT.java#L187-L193)

### [FABJ-340 Adding IdemixUser for unlinkability](https://jira.hyperledger.org/browse/FABJ-340)
The ability to sign proposals and transactions in an unlinkable way has been added to the Java SDK.  From the application perspective
there is a minimal change in API usage to achieve unlinkability.  The application user as normal needs to first have a x509 certificate enrollment.
The Identity Mixer (Idemix, for short) enrollment will be derived from the x509 enrollment. Next is to have a user context that has both the MSPID that is defined for Idemix and an Idemix enrollment that's created with FabricCA `idemixEnroll` instead of
the FabricCA's `enroll` method that created the x509 enrollment. Example of this can be seen in the [End2endIdemixIt test](https://github.com/hyperledger/fabric-sdk-java/blob/ef604d1fd3bc12eeed9910036f24e4a4953156c4/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIdemixIT.java#L121-L138).

When unlinkability is desired, the user context should be changed from the x509 user to the Idemix user.
An Idemix user context, however, should be limited to creating proposals to invoke chaincode.
Every proposal signed with Idemix will look like it is coming from a different user.
Only the Role and Organization Unit attributes will be disclosed in a serialized Identity and the rest will be hidden.
For further information on unlinkability and Idemix see [Identity Mixer Documentation for v1.3](https://hyperledger-fabric.readthedocs.io/en/release-1.3/idemix.html).

## v1.3 Fabric/CA features

### [FAB-10351 Idemix CA support for Java SDK](https://jira.hyperledger.org/browse/FABJ-331)

Idemix enrollment API `idemixEnroll` is used to obtain credentials needed for unlinkability.
An example of its usage can be seen in
[End2endIdemixIt test.](https://github.com/hyperledger/fabric-sdk-java/blob/ef604d1fd3bc12eeed9910036f24e4a4953156c4/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIdemixIT.java#L137)
