# Java SDK for Hyperledger Fabric 1.0
Welcome to Java SDK for Hyperledger project. This is a summary of steps required to get you started with building and using the Java SDK.
 Please note that this is not the API documentation or a tutorial for the SDK, this will only help you familiarize to get started with the SDK if you are new in this domain.
 
 The 1.0 sdk is currently under development and the api is still subject to change. It is likely any code depending on this 1.0 version `preview` many need updating 
 with subsequent updates of this sdk.

## Compiling
To build this project, following dependencies must be met
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

## Running the unit tests
To run the unit tests, please use <code>mvn test</code> or <code>mvn install</code> which will run the unit tests and build the jar file.
You must be running a local a peer and orderer to be able to run the unit tests.

## Running the End to End tests
To run the End-to-End tests, please use <code>mvn failsafe:integration-test -DskipITs=false</code> which will run the End2end tests. You must be running a local instance of membersrvcs and a peer to be able to run the End-to-End tests. 

Hyperledger Fabric v1.0 is currently under active development and the very latest Hyperledger Fabric builds may not work with this sdk.
You should use the following commit levels of the Hyperledger projects:

| Project        | Commit level                               | Date        |
|:---------------|:------------------------------------------:|------------:|
| fabric         | 5d9e4ede298ab646ac918dc5b034c7d319dd1d9a   | Jan 30 2017 |
| fabric-ca      | bf8fb4d5e497217cd6125025830aa6870de442aa   | Jan 27 2017 |
 
 
 
 You can clone these projects by going to the [Hyperledger repository](https://gerrit.hyperledger.org/r/#/admin/projects/).
 
 As sdk developement continues, this file will be updated with compatible Hyperledger Fabric commit levels.
 
 Once you have cloned `fabric` and `fabric-ca`, use the `git reset --hard commitlevel` to set your repositories to the correct commit.
 
 To make the ports available to the sdk from vagrant, edit the `devenv/Vagrantfile` file
 * Open the file `Vagrantfile` and verify that the following `config.vm.network` statements are set:
```
  config.vm.network :forwarded_port, guest: 7050, host: 7050 # orderer service
  config.vm.network :forwarded_port, guest: 7051, host: 7051 # Openchain gRPC services
  config.vm.network :forwarded_port, guest: 7054, host: 7054 # Membership service/Fabric CA
  config.vm.network :forwarded_port, guest: 7053, host: 7053 # GRPCCient gRPC services
  config.vm.network :forwarded_port, guest: 5984, host: 15984 # CouchDB service
```

Follow the instructions <a href="https://github.com/hyperledger/fabric/blob/master/docs/dev-setup/devenv.md">here</a> to setup the development environment.

ssh into vagrant, 
* go to $GOPATH/src/github.com/hyperledger/fabric
  * run `make docker` to create the docker images for peer and orderer
* go to 4GOPATH/src/github/hyperledger/fabric-cop
  * currently, you want to run fabric-ca with TLS disabled which is the default for commit aa5fb82 mentioned above.
  * if you do need to turn off TLS, edit the COP server configuration file at _/hyperledger/fabric-ca/images/fabric-ca/config/server-config.json_
  * run `make docker` to create the docker image for COP

On your native system where you have the sdk installed you need to copy the docker compose file that starts the services to the directory mapped 
 to vagrant On your native system from the sdk directory:
cp ./test/fixture/src/docker-compose.yml &lt;directory where fabric was installed &gt;

The fabric service creation may have created some files for testing that need to be removed. In the vagrant system:
```
rm -rf /var/hyperledger/*
```
Now start the needed fabric services in vagrant.  In the vagrant system:
```
cd /hyperledger
docker-compose up
```

Once done setting up the fabric The end2end unit test will deploy GO code to the fabric that init's, modifies and queries the fabric's ledger.
The sdk finds this code by setting the `GOPATH` environment variable. For this test set this to: 
GOPATH=&lt;fullpath to your sdk directory&gt;/src/test/fixture

With the Fabric services up and running you can run the End2end integration test. To do this with maven run this command:

`mvn failsafe:integration-test -DskipITs=false`

This runs the src/test/java/org/hyperledger/fabric/sdk/End2endIT.java code.
It constructs the Hyperledger Chain, deploys the `GO` chain code and initializes the ledger with to variables A= "100", B= "200"
It then invokes the chain code function `move` that transfers 100 from A to B on the ledger.
Then queries the ledger to see if B is now 300.

 



## Using the SDK
To use the SDK in your code, simply add the generated JAR file in your classpath. 
Once the JAR file is in your classpath, create a chain instance to interact with the network.<br>
<code>
Chain testChain = new Chain("chain1");
</code><br>

Add the membership service:<br>
<code>
testChain.setMemberServicesUrl("grpc://localhost:7054", null);			
</code><br>

Set a keyValueStore:<br>
<code>
testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home")+"/test.properties"));			
</code><br>

Add a peer to the chain:<br>
<code>
testChain.addPeer("grpc://localhost:7051", null);			
</code><br>

Get a member:<br>
<code>
Member registrar = testChain.getMember("admin");
</code><br>

Enroll a member:<br>
<code>
  Member member = testChain.enroll("user", "secret");
</code><br>

## SDK dependencies
SDK depends on few third party libraries that must be included in your classpath when using the JAR file. To get a list of dependencies, refer to pom.xml file or run
<code>mvn dependency:tree</code> or <code>mvn dependency:list</code>.

Alternatively, <code> mvn dependency:analyze-report </code> will produce a report in HTML format in target directory listing all the dependencies in a more readable format.

#Basic Troubleshooting
**identity or token do not match**

Keep in mind that you can perform the enrollment process with the membership services server only once, as the enrollmentSecret is a one-time-use password. If you have performed a user registration/enrollment with the membership services and subsequently deleted the crypto tokens stored on the client side, the next time you try to enroll, errors similar to the ones below will be seen.

``Error: identity or token do not match``

``Error: user is already registered``

To address this, remove any stored crypto material from the CA server by following the instructions <a href="https://github.com/hyperledger/fabric/blob/master/docs/Setup/Chaincode-setup.md#removing-temporary-files-when-security-is-enabled">here</a> which typically involves deleting the /var/hyperledger/production directory and restarting the membership services. You will also need to remove any of the crypto tokens stored on the client side by deleting the KeyValStore . That KeyValStore is configurable and is set to ${user.home}/test.properties within the unit tests.

When running the unit tests, you will always need to clean the membership services database, and delete the KeyValStore file, otherwise the unit tests will fail.

**java.security.InvalidKeyException: Illegal key size**

If you get this error, this means your JDK does not capable of handling unlimited strength crypto algorithms. To fix this issue, You will need to download the JCE libraries for your version of JDK. Please follow the instructions <a href="http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters">here</a> to download and install the JCE for your version of the JDK. 
