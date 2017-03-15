# Java SDK for Hyperledger Fabric 1.0
Welcome to Java SDK for Hyperledger project. The SDK helps facilitate Java applications to manage the lifecycle of
 Hyperledger channels  (*often referred to as chains*) and user chaincode. The SDK also provides a means to execute
  user chaincode, query blocks
 and transactions on the chain, and monitor events on the chain.
 
THe SDK acts on behave of a particular User which is defined by the embedding application through the implementation
 of the SDK's `User` interface.
 
Note, the SDK does ***not*** provide a means of persistence 
  for the application defined channels and user artifacts on the client. This is left for the embedding application to best manage.
  
The SDK also provides a client for Hyperledger's certificate authority.  The SDK is however not dependent on this
particular implementation of a certificate authority.  Other Certificate authority's maybe use by implementing the 
SDK's `Enrollment` interface.
 
 This provides a summary of steps required to get you started with building and using the Java SDK.
 Please note that this is not the API documentation or a tutorial for the SDK, this will
  only help you familiarize to get started with the SDK if you are new in this domain.

 The 1.0 sdk is currently under development and the ***API is still subject to change****. It is likely any code depending 
 on this 1.0 version `preview` may need updating
 with subsequent updates of the SDK.

## Valid builds of Fabric and Fabric-ca

Hyperledger Fabric v1.0 is currently under active development and the very latest Hyperledger Fabric builds may not work with this sdk.
You should use the following commit levels of the Hyperledger projects:

<!--
[comment]: <> (****************************************************************************************************)
[comment]: <> (*******   src/test/fabric_test_commitlevel.sh tells Jenkins to use the latest commit levels   ******)
-->

| Project        | Commit level                               | Date                       |
|:---------------|:------------------------------------------:|---------------------------:|
| fabric         | 0ef35105f4a7d64279551562f9a0dc9381a9249f   | Mar 18 11:07:39 2017 +0000 |
| fabric-ca      | 894b7e400ddfabee0e7d87c53ab0f454cf955204   | Mar 16 18:24:09 2017 +0000 |

 You can clone these projects by going to the [Hyperledger repository](https://gerrit.hyperledger.org/r/#/admin/projects/).

 As SDK developement continues, this file will be updated with compatible Hyperledger Fabric and Fabric-ca commit levels.

 Once you have cloned `fabric` and `fabric-ca`, use the `git reset --hard commitlevel` to set your repositories to the correct commit.
 
## Working with the Fabric Vagrant environment
 Do the following if you want to run the Fabric components ( peer, orderer, fabric-ca ) in Vagrant:

 * Follow the instructions <a href="https://github.com/hyperledger/fabric/blob/master/docs/dev-setup/devenv.md">here</a> to setup the development environment.
 
 * Open the file `Vagrantfile` and verify that the following `config.vm.network` statements are set. If not, then add them:
```
  config.vm.network :forwarded_port, guest: 7050, host: 7050 # fabric orderer service
  config.vm.network :forwarded_port, guest: 7051, host: 7051 # fabric peer vp0 service
  config.vm.network :forwarded_port, guest: 7053, host: 7053 # fabric peer event service
  config.vm.network :forwarded_port, guest: 7054, host: 7054 # fabric-ca service
  config.vm.network :forwarded_port, guest: 5984, host: 15984 # CouchDB service
  ### Below are probably missing.....
  config.vm.network :forwarded_port, guest: 7056, host: 7056
  config.vm.network :forwarded_port, guest: 7058, host: 7058
  config.vm.network :forwarded_port, guest: 8051, host: 8051
  config.vm.network :forwarded_port, guest: 8053, host: 8053
  config.vm.network :forwarded_port, guest: 8054, host: 8054
  config.vm.network :forwarded_port, guest: 8056, host: 8056
  config.vm.network :forwarded_port, guest: 8058, host: 8058
 
```
**Most likely the peer1,2,3 ports 7056-8058 are missing ***

Add to your Vagrant file a folder for referencing the sdkintegration folder 

  
  config.vm.synced_folder "..", "/opt/gopath/src/github.com/hyperledger/fabric"</br>
  
  ***config.vm.synced_folder "/home/user/fabric-sdk-java/src/test/fixture/sdkintegration", "/opt/gopath/src/github.com/hyperledger/fabric/sdkintegration"***</br>
  
  config.vm.synced_folder ENV.fetch('LOCALDEVDIR', ".."), "#{LOCALDEV}"</br>
  
 * Start the vagrant virtual machine
```
vagrant up
```
 * ssh into vagrant,
   * go to $GOPATH/src/github.com/hyperledger/fabric
   * run `make docker` to create the docker images for peer and orderer
   * go to $GOPATH/src/github/hyperledger/fabric-ca
   * run `make docker` to create the docker image for Fabric_ca
 * The fabric service creation may have created some files for testing that need to be removed.
   * _rm -rf /var/hyperledger/*_
   
 * Start the needed fabric services in vagrant.  In the vagrant system:
   1. _cd $GOPATH/src/github.com/hyperledger/fabric/sdkintegration
   1. _docker-compose up -d --force-recreate_

## SDK dependencies
SDK depends on few third party libraries that must be included in your classpath when using the JAR file. To get a list of dependencies, refer to pom.xml file or run
<code>mvn dependency:tree</code> or <code>mvn dependency:list</code>.

Alternatively, <code> mvn dependency:analyze-report </code> will produce a report in HTML format in target directory listing all the dependencies in a more readable format.

## Using the SDK
The SDK's test cases uses chaincode in the SDK's source tree: `/src/test/fixture`

The sdk jar is in `target/fabric-sdk-java-1.0-SNAPSHOT.jar` and you will need the additional dependencies listed above.
When the SDK is published to `Maven` you will be able to simply include it in a your application's `pom.xml`.

### Compiling
To build this project, the following dependencies must be met
 * JDK 1.8 or above
 * Apache Maven

Once your JAVA_HOME points to your installation of JDK 1.8 (or above) and JAVA_HOME/bin and Apache maven are in your PATH, issue the following command to build the jar file:
<code>
  mvn install
</code>
or
<code>
  mvn install -DskipTests
</code> if you don't want to run the unit tests

### Running the unit tests
To run the unit tests, please use <code>mvn test</code> or <code>mvn install</code> which will run the unit tests and build the jar file.
You must be running a local peer and orderer to be able to run the unit tests.

### Running the integration tests
You must be running local instances of Fabric-ca, Fabric peers and Fabric orderers to be able to run the integration tests. See above for running these services in Vagrant.
Use this `maven` command to run the integration tests: 
 * _mvn failsafe:integration-test -DskipITs=false_ 

### End to end test scenario
The _src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java_ integration test is an example of installing, instantiating, invoking and querying a chaincode.
It constructs the Hyperledger channel, deploys the `GO` chain code, invokes the chaincode to do a transfer amount operation and queries the resulting blockchain world state.

This test is a reworked version of the Fabric [e2e_cli example](https://github.com/hyperledger/fabric/tree/master/examples/e2e_cli) to demonstrate the features of the SDK.
To better understand blockchain and Fabric concepts, we recommend you install and run the _e2e_cli_ example.

#### End to end test environment
The test defines one Fabric orderer and two organizations (peerOrg1, peerOrg2), each of which has 2 peers, one fabric-ca service.

For ease of assigning ports and mapping of artifacts to physical files, all peers, orderers and fabric-ca are run as Docker containers controlled via a docker-compose configuration file.

The files used by the end to end are:
 * _src/test/fixture/sdkintegration/e2e-2Orgs/channel_  (everything needed to bootstrap the orderer and create the channels)
 * _src/test/fixture/sdkintegration/e2e-2Orgs/crypto-config_ (as-is. Used by `configtxgen` and `docker-compose` to map the MSP directories)
 * _src/test/fixture/sdkintegration/docker-compose.yaml_

### Certificates and other cryptography artifacts

Fabric requires that each organization have private keys and certificates for use in signing and verifying messages going to and from clients, peers and orderers.
Each organization groups these artifacts in an **MSP** (Membership Service Provider) with a unique _MSPID_ .

Furthermore, each organization is assumed to generate these artifacts independently. The *fabric-ca* project is an example of such a certificate generation service.
Fabric also provides the `cryptogen` tool to automatically generate all cryptographic artifacts needed for the end to end test.

The end to end test case artifacts are stored under in directory _src/test/fixture/sdkintegration/e2e-2Org/crypto-config_ .

### Chaincode endorsement policies
Policies are described in the [Fabric Endorsement Policies document](https://gerrit.hyperledger.org/r/gitweb?p=fabric.git;a=blob;f=docs/endorsement-policies.md;h=1eecf359c12c3f7c1ddc63759a0b5f3141b07f13;hb=HEAD).
You create a policy using a Fabric tool ( an example is shown in [JIRA issue FAB-2376](https://jira.hyperledger.org/browse/FAB-2376?focusedCommentId=21121&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-21121))
and give it to the SDK either as a file or a byte array. The SDK, in turn, will use the policy when it creates chaincode instantiation requests.

To input a policy to the SDK, use the [ChaincodeEndorsementPolicy class](https://gerrit.hyperledger.org/r/gitweb?p=fabric-sdk-java.git;a=blob;f=src/main/java/org/hyperledger/fabric/sdk/ChaincodeEndorsementPolicy.java;h=b67b5514b1e26ffac71210a33d788b83ee7cf288;hb=HEAD).

For testing purposes, there are 2 policy files in the _src/test/resources_ directory
  * _policyBitsAdmin_ ( which has policy **AND(DEFAULT.admin)** meaning _1 signature from the DEFAULT MSP admin' is required_ )
  * _policyBitsMember_ ( which has policy **AND(DEFAULT.member)** meaning _1 signature from a member of the DEFAULT MSP is required_ )

and one file in th _src/test/fixture/sdkintegration/e2e-2Orgs/channel_ directory specifically for use in the end to end test scenario
  * _members_from_org1_or_2.policy_ ( which has policy **OR(peerOrg1.member, peerOrg2.member)** meaning  _1 signature from a member of either organizations peerOrg1, PeerOrg2 is required_)
  
### Chain creation artifacts
Channel configuration files and orderer bootstrap files ( see directory _src/test/fixture/sdkintegration/e2e-2Orgs/channel_ ) are needed when creating a new channel.
This is created with the Hyperledger Fabric `configtxgen` tool.

For End2endIT.java the commands are

 * build/bin/configtxgen -outputCreateChannelTx foo.tx -profile TwoOrgs -channelID foo
 * build/bin/configtxgen -outputCreateChannelTx bar.tx -profile TwoOrgs -channelID bar
 * build/bin/configtxgen -outputBlock twoorgs.orderer.block -profile TwoOrgs
 
with the configtxgen config file _src/test/fixture/sdkintegration/e2e-2Orgs/channel/configtx.yaml_
 
 
If `build/bin/configtxgen` tool is not present  run `make configtxgen`
 
Before running the end to end test case:
 *  you may need to modify `configtx.yaml` to change all hostname and port definitions to match
your server(s) hostname(s) and port(s).
 *  you **WILL** have to modify `configtx.yaml` to have the _MSPDir_ point to the correct path to the _crypto-config_ directories. 
   * `configtx.yaml` currently assumes that you are running in a Vagrant environment where the fabric, fabric-ca and fabric-sdk-java projects exist under the _/opt/gopath/src/github.com/hyperledger_ directory.

### GO Lang chaincode
Go lang chaincode dependencies must be contained in vendor folder. 
 For an explanation of this see [Vender folder explanation](https://blog.gopheracademy.com/advent-2015/vendor-folder/)
 
 
#Basic Troubleshooting
**identity or token do not match**

Keep in mind that you can perform the enrollment process with the membership services server only once, as the enrollmentSecret is a one-time-use password. If you have performed a FSUser registration/enrollment with the membership services and subsequently deleted the crypto tokens stored on the client side, the next time you try to enroll, errors similar to the ones below will be seen.

``Error: identity or token do not match``

``Error: FSUser is already registered``

To address this, remove any stored crypto material from the CA server by following the instructions <a href="https://github.com/hyperledger/fabric/blob/master/docs/Setup/Chaincode-setup.md#removing-temporary-files-when-security-is-enabled">here</a> which typically involves deleting the /var/hyperledger/production directory and restarting the membership services. You will also need to remove any of the crypto tokens stored on the client side by deleting the KeyValStore . That KeyValStore is configurable and is set to ${FSUser.home}/test.properties within the unit tests.

When running the unit tests, you will always need to clean the membership services database, and delete the KeyValStore file, otherwise the unit tests will fail.

**java.security.InvalidKeyException: Illegal key size**

If you get this error, this means your JDK does not capable of handling unlimited strength crypto algorithms. To fix this issue, You will need to download the JCE libraries for your version of JDK. Please follow the instructions <a href="http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters">here</a> to download and install the JCE for your version of the JDK. 

#Communicating with developers and fellow users.
 Sign into <a href="https://chat.hyperledger.org/">Hyperledger project's Rocket chat</a>
 For this you will also need a <a href="https://identity.linuxfoundation.org/">Linux Foundation ID</a>

 Join the <b>fabric-sdk-java</b> channel.

#Reporting Issues
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
    <dd>v1.0.0</dd>
</dl>

Pleases provide as much information that you can with the issue you're experiencing: stack traces  logs.


