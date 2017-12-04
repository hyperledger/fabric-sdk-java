# Eclipse Setup Instructions

## Pre-req

The following dependencies must be met:

 * JDK 1.8 or above
 * Apache Maven

Set your JAVA\_HOME points to your installation of JDK 1.8 (or above) and make sure that JAVA_HOME/bin and Apache maven are in your PATH.

## Eclipse Setup

1. Download and install the latest Eclipse client

2. If you want to contribute to the project, you will need to make sure you are logged in to Gerrit and have setup your SSH keys. For more information on this, refer to: http://hyperledger-fabric.readthedocs.io/en/latest/Gerrit/lf-account.html

3. Clone the Java SDK from Gerrit. Make sure SSH and "Clone with commit-msg hook" are selected before you click on the copy to clipboard icon. Make sure the line you have copied has a: && scp .. errit.hyperledger.org:hooks/commit-msg fabric-sdk-java/.git/hooks/
    * https://gerrit.hyperledger.org/r/#/admin/projects/fabric-sdk-java

4. Download and Install Maven, if you haven't already.
    * https://maven.apache.org/download.cgi

5. Open up Eclipse to import the project. Go to File > Import > Maven > Existing Maven Project. Point to the location where you cloned the SDK in step 3.
    * If you see the error: **Failed to read the project description file (.project) for 'fabric-sdk-java'.  The file has been changed on disk, and it now contains invalid information.  The project will not function properly until the description file is restored to a valid state.** Remove the comments on top of .project file and .classpath and try importing the project again.

6. Hit Finish.
    * If you see error: **No marketplace entries found to handle maven-antrun-plugin:1.4:run in Eclipse.  Please see Help for more information.** Continue to hit Finish. We will resolve this later.

7. Download dependencies. Navigate to you fabric-sdk-java folder, and execute the following command: **mvn install -DskipTests**

8. After running the command in step 6, you might see the following error in Eclipse: **Plugin execution not covered by lifecycle configuration: org.apache.maven.plugins:maven-antrun-plugin:1.4:run (execution: default, phase: generate-test-resources).** Right click on the error and choose: **Mark goal run as ignored in eclipse.**

9. Enable Checkstyle. Go to Project > Properties > Checkstyle. Make sure the “Checkstyle active for this project”, “files outside source directories”, and “derived (generated) files” are all checked.

10. Hit “Local Check Configurations”, then select “New”. Choose “External Configuration File”, hit “Browse” and select “checkstyle-config.xml” from the fabric-sdk-java root directory.

11. Hit "Apply and Close", and the checkstyle will be applied.

Your eclipse environment should be set up now.