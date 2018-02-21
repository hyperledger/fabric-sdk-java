# Java SDK for Hyperledger Fabric 1.1
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
  Applications need to handle migration of serialzed files between versions.

The SDK also provides a client for Hyperledger's certificate authority.  The SDK is however not dependent on this
particular implementation of a certificate authority. Other Certificate authority's maybe used by implementing the
SDK's `Enrollment` interface.

 This provides a summary of steps required to get you started with building and using the Java SDK.
 Please note that this is not the API documentation or a tutorial for the SDK, this will
  only help you familiarize to get started with the SDK if you are new in this domain.


## Known limitations and restrictions

* TCerts are not supported: JIRA FAB-1401
* HSM not supported. JIRA FAB-3137

<p &nbsp; />
<p &nbsp; />

`*************************************************`
## *v1.1.0-alpha*

## v1.1 release notes
Please review the [v1.1 release notes](./docs/release_v1.1.0_notes.md) to familarize yourself with changes since v1.0 sdk release

### Git v1.1.0-alpha

There is a git tagged v1.1.0-alpha  release of the SDK where there is no
need to build the Hyperledger Fabric and Hyperledger Fabric CA described below.
The provided docker-compose.yaml for the integration tests should pull v1.1.0-alpha  tagged images from Docker hub.

The v1.1.0-alpha version of the Hyperledger Fabric Java SDK is published to Maven so you can directly use in your application's pom.xml.

[Maven Repository Hyperledger Fabric Java SDK](https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java)

_Make sure you're using docker images at the level of the Fabric that matches the level of the SDK you're using in your application._

### Using the SDK in your application

Add below code in your `pom.xml` to download fabric-sdk-java-1.1.0-alpha

```xml

     <dependencies>
        <dependency>
            <groupId>org.hyperledger.fabric-sdk-java</groupId>
            <artifactId>fabric-sdk-java</artifactId>
            <version>1.1.0-alpha</version>
         </dependency>
     </dependencies>
```

<p &nbsp; />
<p &nbsp; />

`*************************************************`

## 1.1.0-SNAPSHOT builds
Work in progress 1.1.0 SNAPSHOT builds can be used by adding the following to your application's
pom.xml
```
<dependencies>

        <!-- https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java -->
        <dependency>
            <groupId>org.hyperledger.fabric-sdk-java</groupId>
            <artifactId>fabric-sdk-java</artifactId>
            <version>1.1.0-SNAPSHOT</version>
        </dependency>

</dependencies>
```

Add to your maven's setting.xml typically in the .m2 directory under your home directory:
```
<profiles>
      <profile>
         <id>allow-snapshots</id>
         <activation>
            <activeByDefault>true</activeByDefault>
         </activation>
         <repositories>
            <repository>
               <id>snapshots-repo</id>
               <url>https://oss.sonatype.org/content/repositories/snapshots</url>
               <releases>
                  <enabled>false</enabled>
               </releases>
               <snapshots>
                  <enabled>true</enabled>
               </snapshots>
            </repository>
         </repositories>
      </profile>
</profiles>
```





## Latest builds of Fabric and Fabric-ca v1.1.0

Hyperledger Fabric v1.1.0 is currently under active development.

You can clone these projects by going to the [Hyperledger repository](https://gerrit.hyperledger.org/r/#/admin/projects/).

## Working with the Fabric Vagrant environment
Vagrant is NOT required if your OS has Docker support and all the requirements needed to build directly in your
environment.  For non Vagrant environment, the steps would be the same as below minus those parts involving Vagrant.
 Do the following if you want to run the Fabric components ( peer, orderer, fabric-ca ) in Vagrant:

  ```
  git clone  https://github.com/hyperledger/fabric.git
  git clone  https://github.com/hyperledger/fabric-ca.git
  cd  fabric-ca
  git reset --hard fabric-ca_commitlevel from above
  cd ../fabric
  git reset --hard fabric_commitlevel from above
  cd devenv
  change the Vagrant file as suggested below:
  vagrant up
  vagrant ssh
  make docker
  cd ../fabric-ca
  make docker
  cd ../fabric/sdkintegration
  docker-compose down;  rm -rf /var/hyperledger/*; docker-compose up --force-recreate
  ```



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
  config.vm.network :forwarded_port, guest: 7059, host: 7059

```

Add to your Vagrant file a folder for referencing the sdkintegration folder between the lines below:

  config.vm.synced_folder "..", "/opt/gopath/src/github.com/hyperledger/fabric"</br>

  `config.vm.synced_folder "/home/<<user>>/fabric-sdk-java/src/test/fixture/sdkintegration", "/opt/gopath/src/github.com/hyperledger/fabric/sdkintegration"`</br>

  config.vm.synced_folder ENV.fetch('LOCALDEVDIR', ".."), "#{LOCALDEV}"</br>




## SDK dependencies
SDK depends on few third party libraries that must be included in your classpath when using the JAR file. To get a list of dependencies, refer to pom.xml file or run
<code>mvn dependency:tree</code> or <code>mvn dependency:list</code>.

Alternatively, <code> mvn dependency:analyze-report </code> will produce a report in HTML format in target directory listing all the dependencies in a more readable format.

## Using the SDK
The SDK's test cases uses chaincode in the SDK's source tree: `/src/test/fixture`

The SDK's JAR is in `target/fabric-sdk-java-1.1.0-SNAPSHOT.jar` and you will need the additional dependencies listed above.


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

**Many unit tests will test failure condition's resulting in exceptions and stack traces being displayed. This is not an indication of failure!**

**[INFO] BUILD SUCCESS**  **_At the end is usually a very reliable indication that all tests have passed successfully!_**

### Running the integration tests
You must be running local instances of Fabric-ca, Fabric peers, and Fabric orderers to be able to run the integration tests. See above for running these services in Vagrant.
Use this `maven` command to run the integration tests:
 * _mvn failsafe:integration-test -DskipITs=false_

### End to end test scenario
The _src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java_ integration test is an example of installing, instantiating, invoking and querying a chaincode.
It constructs the Hyperledger channel, deploys the `GO` chaincode, invokes the chaincode to do a transfer amount operation and queries the resulting blockchain world state.

The _src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java_  Shows recreating the channel objects created in End2endIT.java and
upgrading chaincode and invoking the up graded chaincode.

Between End2endIT.java and End2endAndBackAgainIT.java this code shows almost all that the SDK can do.
 To learn the SDK you must have some understanding first of the Fabric. Then  it's best to study these two integrations tests  and better yet work with them in a debugger to follow the code. ( *a live demo* )
 Then once you understand them you can cut and paste from there to your own application. ( _the code is done for you!_ )


This test is a reworked version of the Fabric [e2e_cli example](https://github.com/hyperledger/fabric/tree/master/examples/e2e_cli) to demonstrate the features of the SDK.
To better understand blockchain and Fabric concepts, we recommend you install and run the _e2e_cli_ example.

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

We need certificate and key for each of the Orderer and Peers for TLS connection. You can generate your certificate and key files with openssl command as follows:

 * Set up your own Certificate Authority (CA) for issuing certificates
 * For each of orderers and peers:
   * generate a private key: <code>openssl genrsa 512 > key.pem</code>.
   * generate a certificate request (csr): <code>openssl req -new -days 365 -key key.pem -out csr.pem</code>, which will request your input for some information, where CN has to be the container's alias name (e.g. peer0, peer1, etc), all others can be left blank.
   * sign the csr with the CA private key to generate a certificate: <code>openssl ca -days 365 -in csr.pem -keyfile {CA's privatekey} -notext -out cert.pem</code>
   * put the resulting cert.pem and key.pem together with the CA's certificate (as the name cacert.pem) in the directory where the docker container can access.

The option -notext in the last openssl command in the above is important. Without the option, the resulting cert.pemmay does not work for some Java implementation (e.g. IBM JDK).
The certificates and keys for the end-to-end test case are stored in the directory _src/test/fixture/sdkintegration/e2e-2Org/tls/_.

Currently, the pom.xml is set to use netty-tcnative-boringssl for TLS connection to Orderer and Peers, however, you can change the pom.xml (uncomment a few lines) to use an alternative TLS connection via ALPN.

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

 This should produce in the `v1.1` directory: bar.tx,foo.tx, orderer.block

 **Note:** The above describes how this was done. If you redo this there are private key files
 which are produced with uniqe names which won't match what's expected in the integration tests.
 One examle of this is the docker-compose.yaml (search for **_sk**)




### GO Lang chaincode
Go lang chaincode dependencies must be contained in vendor folder.
 For an explanation of this see [Vendor folder explanation](https://blog.gopheracademy.com/advent-2015/vendor-folder/)

### Setting Up Eclipse

To get started using the Fabric Java SDK with Eclipse, refer to the instructions at: ./docs/EclipseSetup.md

## Basic Troubleshooting

**Firewalls, load balancers, network proxies**

These can sometimes silently kill a network connections and prevent them from auto reconnecting. To fix this look at
adding to Peers, EventHub's and Orderer's connection properties:
`grpc.NettyChannelBuilderOption.keepAliveTime`, `grpc.NettyChannelBuilderOption.keepAliveTimeout`,
`grpc.NettyChannelBuilderOption.keepAliveWithoutCalls`. Examples of this are in End2endIT.java


**identity or token do not match**

Keep in mind that you can perform the enrollment process with the membership services server only once, as the enrollmentSecret is a one-time-use password. If you have performed a FSUser registration/enrollment with the membership services and subsequently deleted the crypto tokens stored on the client side, the next time you try to enroll, errors similar to the ones below will be seen.

``Error: identity or token do not match``

``Error: FSUser is already registered``

To address this, remove any stored crypto material from the CA server by following the instructions <a href="https://github.com/hyperledger/fabric/blob/master/docs/Setup/Chaincode-setup.md#removing-temporary-files-when-security-is-enabled">here</a> which typically involves deleting the /var/hyperledger/production directory and restarting the membership services. You will also need to remove any of the crypto tokens stored on the client side by deleting the KeyValStore . That KeyValStore is configurable and is set to ${FSUser.home}/test.properties within the unit tests.

When running the unit tests, you will always need to clean the membership services database and delete the KeyValStore file, otherwise, the unit tests will fail.

**java.security.InvalidKeyException: Illegal key size**

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
    <dd>v1.1</dd>
</dl>

Pleases provide as much information that you can with the issue you're experiencing: stack traces logs.

Please provide the output of **java -XshowSettings:properties -version**

Logging for the SDK can be enabled with setting environment variables:

ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE

ORG_HYPERLEDGER_FABRIC_CA_SDK_LOGLEVEL=TRACE

Fabric debug is by default enabled in the SDK docker-compose.yaml file with

On Orderer:

ORDERER_GENERAL_LOGLEVEL=debug

On peers:
CORE_LOGGING_LEVEL=DEBUG

Fabric CA
by starting command have the -d parameter.

Upload full logs to the JIRA not just where the issue occurred if possible


<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
