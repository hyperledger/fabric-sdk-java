# Java SDK for Hyperledger Fabric
Welcome to Java SDK for Hyperledger project. This is a summary of steps required to get you started with building and using the Java SDK. Please note that this is not the API documentation or a tutorial for the SDK, this will only help you familiarize to get started with the SDK if you are new in this domain.

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
To run the unit tests, please use <code>mvn test</code> or <code>mvn install</code> which will run the unit tests and build the jar file. You must be running a local instance of membersrvcs and a peer to be able to run the unit tests. Please follow the instructions <a href="https://github.com/hyperledger/fabric/blob/master/docs/dev-setup/devenv.md">here</a> to setup the development environment.

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
