# Java SDK Release Process Document:

Below are the steps explains how to publish Hyperledger Fabric sdk-java jar file to OSSRH
(Open Source Software Repository Hosting) and then to Maven central.
Sonatype OSSRH uses Sonatype Nexus Repository Manager to provide repository hosting service for
Open source projects like Hyperledger Fabric.

OSSRH uses the Maven repository format and allow you to

1) deploy development version (snapshots)
2) stage release binaries
3) promote release and sync them to Maven central repository

Before you deploy developement version or stable release, you have to follow below steps
to continue further

1) Create JIRA account (https://issues.sonatype.org/secure/Signup!default.jspa)
2) Create a new Project
See this example for reference
https://issues.sonatype.org/browse/OSSRH-30331

Make sure your requested project is created and JIRA ticket is marked a Resolved.

Add below lines in **pom.xml**

```
<distributionManagement>
        <snapshotRepository>
            <id>ossrh</id>
            <url>https://oss.sonatype.org/content/repositories/snapshots</url>
        </snapshotRepository>
</distributionManagement>
```

```
<configuration>
            <serverId>ossrh</serverId>
            <nexusUrl>https://oss.sonatype.org/</nexusUrl>
            <autoReleaseAfterClose>false</autoReleaseAfterClose>
</configuration>
```

Add below lines in **settings.xml**

```
<settings>
    <servers>
        <server>
            <id>ossrh</id>
            <username>${env.OSSRH_USER_TOKEN}</username>
            <password>${env.OSSRH_PWD_TOKEN}</password>
        </server>
     </servers>
   <profiles>
        <profile>
            <id>ossrh</id>
            <activation>
                <activeByDefault>true</activeByDefault>
            </activation>
            <properties>
                <gpg.keyname>${env.GPG_KEY}</gpg.keyname>
                <gpg.passphrase>${env.GPG_PWD}</gpg.passphrase>
            </properties>
        </profile>
    </profiles>
</settings>
```
Please make sure **settings.xml** is copied in maven home path.
Verify **settings.xml** in `cd ~/.m2/`. Follow below steps to publish java jar artifacts to
nexus/maven repository using Maven approach.

### Step 1: Export Environment Variables

Make sure values are passed to the environment variables placed in settings.xml file

```
export OSSRH_USER_TOKEN=ossrh ID
export OSSRH_PWD_TOKEN=ossrh pwd
```
### Step 2: Generate gpg keys.

Follow below link to generate gpg keys http://central.sonatype.org/pages/working-with-pgp-signatures.html

Follow below steps to generate gpg keys:

- Execute below command to generate gpg key to sign artifacts

      `gpg --gen-key` Stick to the defaulut values like
     - Key type should be RSA & RSA (default)
     - Key Size should be 2048 (default)
     - Key valid for 0 (defaulut)
     - Confirm above section - (y)
     - Provide Real Name (ossrh userid)
     - Provide email address (associated to the ossrh userid)
     - Provide comment ( Any of your choice)
     - Confirm the selection (Type O for Okay)
     - Enter Passphrase (remember this) and re-enter Passphrase

After provide the correct information above, it generates gpg keys.
If the process taking time to generate gpg key, perform some other actions like accessing keyboard,
mouse and accessing disk usage to fasten the process.

- List out generated gpg keys
      `gpg2 --list-keys`
ex:
```
/home/juven/.gnupg/pubring.gpg
------------------------------
pub   1024D/E8EBD57A 2017-06-17
uid                  Juven Xu (Juven Xu works at Sonatype) <juven@sonatype.com>
sub   2048g/D704745C 2017-06-17
```

- Distribute public key

Run below command to distribute public key

`gpg2 --keyserver hkp://pool.sks-keyservers.net --send-keys E8EBD57A`

```
export GPG_KEY=<gpg public key> (E8EBD57A)
export GPG_PWD=<passphrase>
```
### Step 3: Deploy Artifact

Execute below command from fabric-sdk-java directory to build and publish java jar artifact to
maven repository

```
mvn clean install deploy -P release -s settings.xml -DskipITs=false -Dmaven.test.failure.ignore=false
```

Once the command is successfully execute, you will see fabric-sdk-java artifacts in maven central
repository https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java
and snapshot java artifacts in nexus repository
https://oss.sonatype.org/content/repositories/snapshots/org/hyperledger/fabric-sdk-java/fabric-sdk-java/

### Step 4: Perform Release to Maven

Promote release build from sonatype nexus the artifact is successfully pushed to
https://oss.sonatype.org/#stagingProfiles. Wait for sometime to syncup this release in maven central
repository. If everything goes fine, published artifact should be available in maven central repository.

https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java

# Test Java SDK jar file using sample APP

[TODO]

## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
