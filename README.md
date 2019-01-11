# Java SDK for Hyperledger Fabric 2.0
Welcome to Java SDK for Hyperledger project. The SDK helps facilitate Java applications to manage the lifecycle of
 Hyperledger channels  and user chaincode. The SDK also provides a means to execute
  user chaincode, query blocks
 and transactions on the channel, and monitor events on the channel.

The SDK acts on behave of a particular User which is defined by the embedding application through the implementation
 of the SDK's `User` interface.

Note, the SDK does ***not*** provide a means of persistence
  for the application defined channels and user artifacts on the client. This is left for the embedding application to best manage.
  Channels may be serialized via Java serialization in the context of a client.
  Channels deserialized are not in an initialized state.
  Applications need to handle migration of serialized files between versions.

The SDK also provides a client for Hyperledger's certificate authority.  The SDK is however not dependent on this
particular implementation of a certificate authority. Other Certificate authority's maybe used by implementing the
SDK's `Enrollment` interface.

 This provides a summary of steps required to get you started with building and using the Java SDK.
 Please note that this is not the API documentation or a tutorial for the SDK, this will
  only help you familiarize to get started with the SDK if you are new in this domain.


## Release notes

|Release | Notes |Summary|
|--------|:------|:------|
|1.4     | None | Minor updates no Fabric changes|
|1.3     | [v1.3 release notes](./docs/release_v1.3.0_notes.md)|<ul><li>Java chaincode support</li><li>Query chaincode collection configuration</li><li>Identity Mixer transaction unlinkabilty support</li></ul> |
|1.2     | [v1.2 release notes](./docs/release_v1.2.0_notes.md)|<ul><li>Private data collection support</li><li>Service discovery</li><li>Fabric CA certificate API </ul>|
|1.1     | [v1.1 release notes](./docs/release_v1.1.0_notes.md)|<ul><li>Channel service events</li><li>FilterBlocks</li><li>JCA/JCE compliance</li><li>Chaincode events</li><li>Node chaincode</li></ul>|



## Checkout SDK from Github
```
git clone https://github.com/hyperledger/fabric-sdk-java.git
cd fabric-sdk-java/
git checkout -b release-1.4
```

## Java applications
For Java applications use the latest published v1.4.x releases:
```
     <!-- https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java -->
     <dependency>
         <groupId>org.hyperledger.fabric-sdk-java</groupId>
         <artifactId>fabric-sdk-java</artifactId>
         <version>1.4.0/version>
     </dependency>

```

## Known limitations and restrictions

* TCerts are not supported: JIRA FAB-1401
* HSM not supported. JIRA FAB-3137

<p &nbsp; />
<p &nbsp; />


`*************************************************`


## Latest Fabric Builds.
Latest Fabric builds are seldom needed except for those working on the very latest Fabric features.
Some information to help with that can been found in [Developer Instructions](./docs/DeveloperInstructions.md)

## Latest builds of Fabric and Fabric-ca v1.4.0

To get a functioning Fabric v1.4.0 network needed by the SDK Integration tests once it's built.
In the directory `src/test/fixture/sdkintegration` issue :

`./fabric.sh restart`

This command needs to be rerun each time the Integration tests are run.

### Setting Up Eclipse
To get started using the Fabric Java SDK with Eclipse, refer to the instructions at: ./docs/EclipseSetup.md

## SDK dependencies
SDK depends on few third party libraries that must be included in your classpath when using the JAR file. To get a list of dependencies, refer to pom.xml file or run
<code>mvn dependency:tree</code> or <code>mvn dependency:list</code>.
Alternatively, <code> mvn dependency:analyze-report </code> will produce a report in HTML format in target directory listing all the dependencies in a more readable format.

To build this project, the following dependencies must be met
 * JDK 1.8 or above
 * Apache Maven 3.5.0

To run the integration tests Fabric and Fabric CA is needed which require
 * Docker 18.03
 * Docker compose 1.21.2

## Using the SDK

### Compiling

Once your JAVA_HOME points to your installation of JDK 1.8 (or above) and JAVA_HOME/bin and Apache maven are in your PATH, issue the following command to build the jar file:
<code>
  mvn install
</code>
or
<code>
  mvn install -DskipTests
</code> if you don't want to run the unit tests

### Running the unit tests
To run the unit tests, please use <code>mvn install</code> which will run the unit tests and build the jar file.

**Many unit tests will test failure condition's resulting in exceptions and stack traces being displayed. This is not an indication of failure!**

**[INFO] BUILD SUCCESS**  **_At the end is usually a very reliable indication that all tests have passed successfully!_**

### Running the integration tests
You must be running local instances of Fabric-ca, Fabric peers, and Fabric orderers to be able to run the integration tests. See above for for how to get a Fabric network running.
Use this `maven` command to run the integration tests:
 * _mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc_

### End to end test scenario

 Following the below integration tests/example code shows almost all that the SDK can do.
 To learn the SDK you must have some understanding first of Fabric Hyperledger. Then it's best to study the integrations tests and better yet work with them in a debugger to follow the code ( *a live demo* ).
 Start first with End2endIT.java and then End2endAndBackAgainIT.java samples before exploring the other samples.
 Then once you understand them you can cut and paste from there to your own application. ( _the code is done for you!_ )

 **Note** These samples are for testing, validating your environment and showing how to use the APIs. Most show a **simple** balance transfer.
  **They are not meant to represent best practices in design or use of chaincode or the use of the SDK**.


 |Integration Test | Summary and notes|
 |--------|:------|
 |[End2endIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java)|<ul><li>Register and enroll users with Fabric certificate authority.</li><li>Constructing channel first time.</li><li>Installing chaincode.</li><li>Instantiating chaincode.</li><li>Executing chaincode.</li><li>Querying channel for block information.</li><li>Chaincode event listener</li><li>Traversing block for information.</li><li>Prerequisite for all other testcases.</li></ul> |
 |[End2endAndBackAgainIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java)| <ul><li>Recreate channel.</li><li>Update chaincode.</li><li>Checking installed and instantiated chaincode.</li></ul> |
 |[End2endNodeIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/End2endNodeIT.java)| <ul><li>Shows running End2endIT.java but with Node chaincode.</li><li>Note subclasses En2endIT class.</li></ul> |
 |[End2endJavaIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/End2endJavaIT.java)| <ul><li>Shows running End2endIT.java but with Java chaincode.</li><li>Note subclasses En2endIT class.</li></ul> |
 |[End2endIdemixIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIdemixIT.java)| <ul><li>Shows running End2endIT.java but with Idemix credentials.</li><li>Note subclasses En2endIT class.</li></ul> |
 |[NetworkConfigIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/NetworkConfigIT.java)| <ul><li>Shows recreating channel with [common connection profile](https://jira.hyperledger.org/browse/FABN-808).</li></ul> |
 |[PrivateDataIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/PrivateDataIT.java)| <ul><li>Shows instantiating and installing chaincode that defines private data.</li><li>Information on Fabric private data can be found [read the docs.](https://hyperledger-fabric.readthedocs.io/en/release-1.2/private-data/private-data.html)</li></ul> |
 |[UpdateChannelIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/UpdateChannelIT.java)| <ul><li>Shows updating channel configuration.</li><li>Details on channel configurations can be found on read the docs [Channel Configuration](https://hyperledger-fabric.readthedocs.io/en/release-1.2/configtx.html#)</li></ul> |
 |[ServiceDiscoveryIT.java](https://github.com/hyperledger/fabric-sdk-java/blob/8044bac1bfe9baf9d6360b067e0d6b5445cc953d/src/test/java/org/hyperledger/fabric/sdkintegration/ServiceDiscoveryIT.java)| <ul><li>Shows service discovery.</li><li>Details on service discovery can be found on read the docs [Service Discovery](https://hyperledger-fabric.readthedocs.io/en/release-1.3/discovery-overview.html)</li><li>Note: requires adding entries in host file to remap docker fabric Peer and Orderers address to localhost</li></ul> |

### End to end test environment
The test defines one Fabric orderer and two organizations (peerOrg1, peerOrg2), each of which has 2 peers, one fabric-ca service.

#### Certificates and other cryptography artifacts

Fabric requires that each organization has private keys and certificates for use in signing and verifying messages going to and from clients, peers and orderers.
Each organization groups these artifacts in an **MSP** (Membership Service Provider) with a corresponding unique _MSPID_ .

Furthermore, each organization is assumed to generate these artifacts independently. The *fabric-ca* project is an example of such a certificate generation service.
Fabric also provides the `cryptogen` tool to automatically generate all cryptographic artifacts needed for the end to end test.
In the directory src/test/fixture/sdkintegration/e2e-2Orgs/channel

  The command used to generate end2end `crypto-config` artifacts:</br>

  v1.0 ```build/bin/cryptogen generate --config crypto-config.yaml --output=crypto-config```

  v1.1 ```cryptogen generate --config crypto-config.yaml --output=v1.1/crypto-config```

For ease of assigning ports and mapping of artifacts to physical files, all peers, orderers, and fabric-ca are run as Docker containers controlled via a docker-compose configuration file.

The files used by the end to end are:
 * _src/test/fixture/sdkintegration/e2e-2Orgs/vX.0_  (everything needed to bootstrap the orderer and create the channels)
 * _src/test/fixture/sdkintegration/e2e-2Orgs/vX.0crypto-config_ (as-is. Used by `configtxgen` and `docker-compose` to map the MSP directories)
 * _src/test/fixture/sdkintegration/docker-compose.yaml_


The end to end test case artifacts are stored under the directory _src/test/fixture/sdkintegration/e2e-2Org/channel_ .

### TLS connection to Orderer and Peers

IBM Java needs the following properties defined to use TLS 1.2 to get an HTTPS connections to Fabric CA.
```
-Dcom.ibm.jsse2.overrideDefaultTLS=true   -Dhttps.protocols=TLSv1.2
```

Currently, the pom.xml is set to use netty-tcnative-boringssl for TLS connection to Orderer and Peers, however, you can change the pom.xml (uncomment a few lines) to use an alternative TLS connection via ALPN.

### TLS Environment for SDK Integration Tests
The SDK Integration tests can be enabled by adding before the ./fabric restart the follow as:

ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS=true ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CA_TLS=--tls.enabled ./fabric.sh restart

Then run the Integration tests with:

ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS=true mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc

### Chaincode endorsement policies
Policies are described in the [Fabric Endorsement Policies document](https://gerrit.hyperledger.org/r/gitweb?p=fabric.git;a=blob;f=docs/endorsement-policies.md;h=1eecf359c12c3f7c1ddc63759a0b5f3141b07f13;hb=HEAD).
You create a policy using a Fabric tool ( an example is shown in [JIRA issue FAB-2376](https://jira.hyperledger.org/browse/FAB-2376?focusedCommentId=21121&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-21121))
and give it to the SDK either as a file or a byte array. The SDK, in turn, will use the policy when it creates chaincode instantiation requests.


To input a policy to the SDK, use the **ChaincodeEndorsementPolicy** class.

For testing purposes, there are 2 policy files in the _src/test/resources_ directory
  * _policyBitsAdmin_ ( which has policy **AND(DEFAULT.admin)** meaning _1 signature from the DEFAULT MSP admin' is required_ )
  * _policyBitsMember_ ( which has policy **AND(DEFAULT.member)** meaning _1 signature from a member of the DEFAULT MSP is required_ )

and one file in the _src/test/fixture/sdkintegration/e2e-2Orgs/channel_ directory specifically for use in the end to end test scenario
  * _members_from_org1_or_2.policy_ ( which has policy **OR(peerOrg1.member, peerOrg2.member)** meaning  _1 signature from a member of either organizations peerOrg1, PeerOrg2 is required_)

 Alternatively, you can also use ChaincodeEndorsementPolicy class by giving it a YAML file that has the policy defined in it.
 See examples of this in the End2endIT testcases that use _src/test/fixture/sdkintegration/chaincodeendorsementpolicy.yaml_
 The file chaincodeendorsementpolicy.yaml has comments that help understand how to create these policies. The first section
 lists all the signature identities you can use in the policy. Currently, only ROLE types are supported.
 The policy section is comprised of `n-of` and `signed-by` elements.  Then n-of (`1-of` `2-of`) require that many (`n`) in that
 section to be true. The `signed-by` references an identity in the identities section.

### Channel creation artifacts
Channel configuration files and orderer bootstrap files ( see directory _src/test/fixture/sdkintegration/e2e-2Orgs_ ) are needed when creating a new channel.
This is created with the Hyperledger Fabric `configtxgen` tool.  This must be run after `cryptogen` and the directory you're
running in **must** have a generated `crypto-config` directory.

If `build/bin/configtxgen` tool is not present  run `make configtxgen`

For v1.0 integration test the commands are:

 * build/bin/configtxgen -outputCreateChannelTx foo.tx -profile TwoOrgsChannel -channelID foo
 * build/bin/configtxgen -outputCreateChannelTx bar.tx -profile TwoOrgsChannel -channelID bar

For v1.1 integration the commands use the v11 profiles in configtx.yaml.
  You need to for now copy the configtx.yaml in `e2e-20orgs` to the v1.1 directory and run from there:
 * configtxgen -outputBlock orderer.block -profile TwoOrgsOrdererGenesis_v11
 * configtxgen -outputCreateChannelTx bar.tx -profile TwoOrgsChannel_v11 -channelID bar
 * configtxgen -outputCreateChannelTx foo.tx -profile TwoOrgsChannel_v11 -channelID foo

For v1.2 integration the commands use the v12 profiles in configtx.yaml.
 * configtxgen --configPath . -outputBlock orderer.block -profile TwoOrgsOrdererGenesis_v12
 * configtxgen --configPath .  -outputCreateChannelTx bar.tx -profile TwoOrgsChannel_v12 -channelID bar
 * configtxgen --configPath .  -outputCreateChannelTx foo.tx -profile TwoOrgsChannel_v12 -channelID foo
 This should produce in the `v1.2` directory: bar.tx,foo.tx, orderer.block

For v1.3 and 1.4 integration, cd to the `src/test/fixture/sdkintegration/e2e-2Orgs/v1.3` directory
and execute the following commands:
 * configtxgen --configPath . -outputBlock orderer.block -profile TwoOrgsOrdererGenesis_v13
 * configtxgen --configPath . -outputCreateChannelTx foo.tx -profile TwoOrgsChannel_v13 -channelID foo
 * configtxgen --configPath . -outputCreateChannelTx bar.tx -profile TwoOrgsChannel_v13 -channelID bar

 This should produce the following files in the same directory: orderer.block, foo.tx, and bar.tx

 **Note:** The above describes how this was done. If you redo this there are private key files
 which are produced with unique names which won't match what's expected in the integration tests.
 One example of this is the docker-compose.yaml (search for **_sk**)


### GO Lang chaincode
Go lang chaincode dependencies must be contained in vendor folder.
 For an explanation of this see [Vendor folder explanation](https://blog.gopheracademy.com/advent-2015/vendor-folder/)


## Basic Troubleshooting and frequently asked questions:

### Where can I find the Javadoc?

Look in the [Maven repository](http://central.maven.org/maven2/org/hyperledger/fabric-sdk-java/fabric-sdk-java/)
for the release in question there should be a file fabric-sdk-java-_&lt;release&gt;_-javadoc.jar

For SNAPSHOT builds look in [Sonatype repository](https://oss.sonatype.org/content/repositories/snapshots/org/hyperledger/fabric-sdk-java/fabric-sdk-java/)
Find the release _&lt;release&gt;_-SNAPSHOT directory then search for the latest fabric-sdk-java-&lt;_release_&gt;&#45;_&lt;latest timestamp&gt;_-javadoc.jar


### Is Android supported?
No.

### Is there an API to query for all channels that exist?
No.

### Firewalls, load balancers, network proxies

These can sometimes silently kill a network connections and prevent them from auto reconnecting. To fix this look at
adding to Peers, EventHub's and Orderer's connection properties:
`grpc.NettyChannelBuilderOption.keepAliveTime`, `grpc.NettyChannelBuilderOption.keepAliveTimeout`,
`grpc.NettyChannelBuilderOption.keepAliveWithoutCalls`. Examples of this are in End2endIT.java

### grpc message frame size exceeds maximum

The message being returned from the fabric server is too large for the default grpc frame size.
On the Peer, Orderer, orEventHub add the property `grpc.NettyChannelBuilderOption.maxInboundMessageSize`
See [End2endIT's constructChannel](https://github.com/hyperledger/fabric-sdk-java/blob/b649868113e969d851720c972f660114b64247bc/src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java#L846)


### java.security.InvalidKeyException: Illegal key size

If you get this error, this means your JDK does not capable of handling unlimited strength crypto algorithms. To fix this issue, You will need to download the JCE libraries for your version of JDK. Please follow the instructions <a href="http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters">here</a> to download and install the JCE for your version of the JDK.

## Communicating with developers and fellow users.
 Sign into <a href="https://chat.hyperledger.org/">Hyperledger project's Rocket chat</a>
 For this you will also need a <a href="https://identity.linuxfoundation.org/">Linux Foundation ID</a>

 Join the <b>fabric-sdk-java</b> channel.

## Reporting Issues
If your issue is with building Fabric development environment please discuss this on rocket.chat's #fabric-dev-env channel.

To report an issue please use: <a href="http://jira.hyperledger.org/">Hyperledger's JIRA</a>.
To login you will need a Linux Foundation ID (LFID) which you get at <a href="https://identity.linuxfoundation.org/">The Linux Foundation</a>
if you don't already have one.

JIRA Fields should be:
<dl>
  <dt>Type</dt>
  <dd>Bug <i>or</i> New Feature</dd>

  <dt>Component</dt>
  <dd>fabric-sdk-java</dd>
  <dt>Fix Versions</dt>
    <dd>v1.4</dd>
</dl>

Pleases provide as much information that you can with the issue you're experiencing: stack traces logs.

Please provide the output of **java -XshowSettings:properties -version**

### Logging for the SDK can be enabled with setting environment variables:

ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE

ORG_HYPERLEDGER_FABRIC_CA_SDK_LOGLEVEL=TRACE

ORG_HYPERLEDGER_FABRIC_SDK_DIAGNOSTICFILEDIR=&lt;*full path to directory*&gt; &#35; *dumps protobuf and diagnostic data. Can be produce large amounts of data!*

### Fabric debug
Fabric debug is by default enabled in the SDK docker-compose.yaml file with

On Orderer:

ORDERER_GENERAL_LOGLEVEL=debug

On peers:
CORE_LOGGING_LEVEL=DEBUG

Fabric CA
by starting command have the -d parameter.

Upload full logs to the JIRA not just where the issue occurred if possible


<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
