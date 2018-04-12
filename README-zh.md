# Java SDK for Hyperledger Fabric 1.1

*阅读其他语言: [English](README.md), [简体中文](README-zh.md).*

欢迎使用Java SDK for Hyperledger项目。 SDK有助于促进Java应用程序管理Hyperledger生命周期和用户链码。 SDK还提供了一种方式来执行用户链码，查询块和通道上的交易，并能够监控通道上的事件。

该SDK能够对通过实现SDK的`用户`接口来定义应用程序的用户特定行为进行操作。

注意，SDK没有提供持久性的方法。

为应用程序在客户端上定义的通道和用户组件,这就更好地管理应用程序。在客户机的上下文中，可以通过Java序列化来序列化通道。反序列化的通道不处于初始化状态。
应用程序需要处理不同版本之间的序列化文件的迁移。

该SDK还为Hyperledger的证书颁发机构提供了一个客户端。但是SDK并不依赖于此。
权威的证书颁发机构进行特定实现。其他证书颁发机构应该通过实现SDK中的`Enrollment`接口来使用。

这里提供了一个步骤的总结，以帮助您从构建和使用Java SDK开始。
请注意，这不是API文档或SDK的教程，如果您是这个领域的新手，这只会帮助您熟悉SDK。

## 已知的限制和局限性
* TCerts不受支持：JIRA FAB-1401
* HSM 不受支持: JIRA FAB-3137

<p &nbsp; />
<p &nbsp; />

`*************************************************`
## *v1.1.0*

## v1.1 发行说明
请查看[v1.1 发行说明](./docs/release_v1.1.0_notes.md)熟悉v1.0发布以来的变化。


`*************************************************`

## 1.1.0-SNAPSHOT 构建
可以通过在应用程序中的pom.xml添加以下内容来使用1.1.0 SNAPSHOT 构建。
```xml
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

<dependencies>

        <!-- https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java -->
        <dependency>
            <groupId>org.hyperledger.fabric-sdk-java</groupId>
            <artifactId>fabric-sdk-java</artifactId>
            <version>1.1.0-SNAPSHOT</version>
        </dependency>

</dependencies>
```
## 最新的Fabric和Fabric-ca v1.1.0版本。
要获得一个功能良好的Fabric v1.1.0网络，需要通过SDK集成测试。
在`src/test/fixture/sdkintegration`目录中:
`IMAGE_TAG_FABRIC=:x86_64-1.1.0 IMAGE_TAG_FABRIC_CA=:x86_64-1.1.0 ./fabric.sh restart`

这个命令需要在每次运行集成测试时重新运行。

你可以通过[Hyperledger repository](https://gerrit.hyperledger.org/r/#/admin/projects/)来克隆这些项目。

## 最新的Fabric构建
除了那些使用最新Fabric功能的人外，很少需要最新的Fabric构建。这些信息可以在[Developer Instructions](./docs/DeveloperInstructions.md)中找到。

### 设置Eclipse
通过Eclipse使用Fabric Java SDK请参阅[EclipseSetup.md](./docs/EclipseSetup.md)。

## SDK 依赖关系
SDK依赖于少量的第三方库,在使用JAR文件时，他们必须包含在类路径中。 要获取依赖关系列表，请参阅pom.xml文件,你也可以运行
<code>mvn dependency：tree</code>或<code>mvn dependency：list</code>。
除此之外，你可以使用命令<code>mvn dependency：analyze-report</code>,
这将在目标目录中生成HTML格式报告，以更具可读性的格式列出所有依赖关系。

要构建此项目，必须满足以下依赖关系
  * JDK 1.8或以上
  * Apache Maven 3.5.0

## 使用 SDK

### 编译

一旦您的JAVA_HOME指向您的JDK 1.8安装路径（或更高版本）并且JAVA_HOME/bin和Apache maven配置了环境变量，请执行以下命令来构建jar文件：
<code>
  mvn install
</code>
如果你不想运行单元测试,可以执行如下命令:
<code>
  mvn install -DskipTests
</code>

### 运行单元测试
要运行单元测试，请使用<code> mvn install </code>来运行单元测试并构建jar文件.

**许多单元测试使用测试失败条件,这会显示的异常和堆栈跟踪,但这并不表示失败！**
**[INFO] BUILD SUCCESS**  **_最后通常是一个非常可靠的指示，表明所有测试都已成功通过！_**

### 运行集成测试

您必须运行Fabric-ca，Fabric peers和Fabric orderers的本地实例才能运行集成测试。 请参阅上文以了解如何使Fabric网络运行。
使用这个`maven`命令来运行集成测试：
 * _mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc_

### 端到端测试场景

 _src/test/java/org/hyperledger/fabric/sdkintegration/End2endIT.java_ 这个集成测试中包含安装，实例化，调用和查询链码的示例。
它构造Hyperledger通道，部署‘go’链码，调用链码来执行传输量操作，并查询由此产生的区块链世界状态。

 _src/test/java/org/hyperledger/fabric/sdkintegration/End2endAndBackAgainIT.java_ 这个测试用来显示在End2endIT.java中重新创建的通道对象,以及升级chaincode并调用升级后的chaincode。

在End2endIT.java和End2endAndBackAgainIT.java 中几乎显示了SDK可以执行的所有操作。
要学习SDK，您必须首先了解Fabric。学习这两个集成测试的最好方法是使用在调试器来跟踪代码。(*一个很好的例子*)
一旦你了解它们，你就可以从那里剪切并粘贴到你自己的应用程序中。 （_代码是为你完成的！_）

### 端到端测试环境
该测试定义了一个Fabric orderer和两个organizations(peerOrg1, peerOrg2)，每个组织有两个peers，一个fabric-ca服务。

#### 证书和其他密码学组件
Fabric要求每个组织都有用于签名和验证消息的私钥和证书。
每个组织都将这些组件分配在一个**MSP**（成员资格服务提供商）中，并使用对应唯一的 _MSPID_。

此外，每个组织都被假定为能够独立生成这些组件。 *fabric-ca*项目就是这种证书生成服务的一个例子。
Fabric还提供`cryptogen`工具来自动生成端到端测试所需的所有加密文件。
在目录 src/test/fixture/sdk integration/e2e-2Orgs/channel 中.
  
  用于生成`crypto-config`配置的命令:</br>
  
  v1.0 ```build/bin/cryptogen generate --config crypto-config.yaml --output=crypto-config```
  
  v1.1 ```cryptogen generate --config crypto-config.yaml --output=v1.1/crypto-config```

为了便于分配端口并将组件映射到物理文件，所有peers, orderers, 和 fabric-ca均作为通过docker-compose配置文件控制的Docker容器运行。

端到端使用的文件如下:
 * _src/test/fixture/sdkintegration/e2e-2Orgs/vX.0_  (everything needed to bootstrap the orderer and create the channels)
 * _src/test/fixture/sdkintegration/e2e-2Orgs/vX.0crypto-config_ (as-is. Used by `configtxgen` and `docker-compose` to map the MSP directories)
 * _src/test/fixture/sdkintegration/docker-compose.yaml_

The end to end test case artifacts are stored under the directory _src/test/fixture/sdkintegration/e2e-2Org/channel_ .
端到端测试用例组件存储在 _src/test/fixture/sdkintegration/e2e-2Org/channel_ 目录下。

### TLS连接到Order和Peers

IBM Java需要定义以下属性才能使用TLS 1.2来获得到Fabric CA的HTTPS连接。
```
-Dcom.ibm.jsse2.overrideDefaultTLS=true   -Dhttps.protocols=TLSv1.2
```
目前，pom.xml中设置使用netty-tcnative-boringssl用于TLS连接到Orderer和Peers，您可以更改pom.xml（取消注释几行）来通过ALPN使用替代TLS连接。

### SDK集成测试需要的TLS环境
SDK集成测试可以通过在./fabric重新启动之前添加以下内容来启用：

```shell
ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS = true ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_CA_TLS = - tls.enabled 
./fabric.sh restart
```
然后运行集成测试：
```shell
ORG_HYPERLEDGER_FABRIC_SDKTEST_INTEGRATIONTESTS_TLS=true 
mvn clean install -DskipITs=false -Dmaven.test.failure.ignore=false javadoc:javadoc
```

### Chaincode背书政策?(Chaincode endorsement policies)
Policies are described in the Fabric Endorsement Policies document.
策略在[Fabric背书策略文档](https://gerrit.hyperledger.org/r/gitweb?p=fabric.git;a=blob;f=docs/endorsement-policies.md;h=1eecf359c12c3f7c1ddc63759a0b5f3141b07f13;hb=HEAD)中进行了描述。
当您在使用Fabric工具创建策略（示例显示在[JIRA issue FAB-2376](https://jira.hyperledger.org/browse/FAB-2376?focusedCommentId=21121&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-21121)中）.
并将其作为文件或字节数组提供给SDK时,SDK会在创建链代码实例化请求时使用该策略。

要将策略输入到SDK，请使用 **ChaincodeEndorsementPolicy**类。
出于测试目的，_src/test/resources_ 目录中有2个策略文件.
  * _policyBitsAdmin_ (政策 **AND(DEFAULT.admin)** 意味着来自 DEFAULT MSP 管理员的签名是必需的)
  * _policyBitsMember_ (政策 **AND(DEFAULT.member)** 意味着来自 DEFAULT MSP 一个成员的签名是必需的)

_src/test/fixture/sdk integration/e2e-2Orgs/channel_ 目录下一个文件专门用于端到端测试场景. 
  * _members_from_org1_or_2.policy_ (策略 **OR(peerOrg1.member, peerOrg2.member)** 意味着来自组织peerOrg1或者PeerOrg2中一个成员的签名是必须的)
  
或者,你也可以通过定义一个 YAML 策略文件使用ChaincodeEndorsementPolicy类.
端到端的测试用例在 _src/test/fixture/sdkintegration/chaincodeendorsementpolicy.yaml_
文件 _chaincodeendorsementpolicy.yaml_ 中有注释,能帮助你了解如何创建这些策略。
第一部分列出您可以在政策中使用的所有签名身份,目前只支持ROLE类型。
策略部分由 `n-of` 和 `signed-by` 的节点组成。然后,n-of(`1-of` `2-of`) 需要该部分很多 `n` 为true.`signed-by` 引用标识部分中的身份标示.
 **此部分翻译欠妥,请[参阅原文](README.md/###Chaincode endorsement policies)以便更好的理解**
 
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
  which are produced with unique names which won't match what's expected in the integration tests.
  One examle of this is the docker-compose.yaml (search for **_sk**)
 
 
 ### GO Lang 区块链
 Go lang 区块链的依赖关系必须包含在vendor文件夹中。
有关此的解释请参阅[Vendor folder explanation](https://blog.gopheracademy.com/advent-2015/vendor-folder/)
 
 
 ## 基本故障排除
 
 **防火墙，负载均衡器，网络代理**
 
 有时这些可能会静默地关闭网络连接，并阻止它们自动重新连接。
 要解决这些问题,请查看添加在 Peers, EventHubs 和 Orderer's 中的连接配置:
 `grpc.NettyChannelBuilderOption.keepAliveTime`, `grpc.NettyChannelBuilderOption.keepAliveTimeout`,
 `grpc.NettyChannelBuilderOption.keepAliveWithoutCalls`. 这些例子在 End2endIT.java 中.
 
 
 **身份或令牌不匹配**
 
请记住，您只能使用成员服务服务器执行一次注册过程，因为enrollmentSecret使用一次性密码。如果您已使用成员服务执行了FSUser注册/登记，但是随后删除了存储在客户端的加密令牌，则下次尝试注册时，将会看到类似于以下信息的错误。
 ``Error: identity or token do not match``
 
 ``Error: FSUser is already registered``
 要解决这个问题，请按照[这里](https://github.com/hyperledger/fabric/blob/master/docs/Setup/Chaincode-setup.md#removing-temporary-files-when-security-is-enabled)的说明删除CA服务器中存储的所有加密资料，这些操作通常涉及删除/var/hyperledger/production目录并重新启动membership服务。您还需要通过删除KeyValStore来移除存储在客户端的所有加密令牌。在单元测试中,KeyValStore在文件${FSUser.home}/test.properties中进行配置.

运行单元测试时，您将始终需要清除membership服务数据库并删除KeyStore文件，否则单元测试将失败。

 **java.security.InvalidKeyException: Illegal key size**
 
 如果你得到这个错误，这意味着你的JDK不能处理无限强度的加密算法。 要解决此问题，您需要为您的JDK下载JCE库。 请按照[说明](http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters)为您的JDK下载和安装相应版本的JCE。


 ## 与开发人员和其他用户沟通
  登录到[Hyperledger project's Rocket chat](https://chat.hyperledger.org/)
  为此，您还需要一个[Linux Foundation ID](https://identity.linuxfoundation.org/)
  加入**fabric-sdk-java**频道。
 
 ## 报告问题
 如果您的问题与构建Fabric开发环境有关，请在ocket.chat's #fabric-dev-env 频道上讨论此问题。
 
 要报告问题，请到[Hyperledger's JIRA](http://jira.hyperledger.org/).
您需要一个 Linux Foundation ID (LFID)进行登录,如果还没有,你可以在[The Linux Foundation](https://identity.linuxfoundation.org/")获得.
 
JIRA字段应该如下：
 <dl>
   <dt>Type</dt>
   <dd>Bug <i>or</i> New Feature</dd>
 
   <dt>Component</dt>
   <dd>fabric-sdk-java</dd>
   <dt>Fix Versions</dt>
     <dd>v1.1</dd>
 </dl>
 
 请提供尽可能多的信息，以解决您遇到的问题：堆栈跟踪日志。
 
 请提供 **java -XshowSettings:properties -version**的输出信息.
 
 通过设置环境变量可以启用对SDK的记录：
 ```shell
 ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE
 
 ORG_HYPERLEDGER_FABRIC_CA_SDK_LOGLEVEL=TRACE
```

Fabric 调试在文件 SDK docker-compose.yml 中默认启用. 
 
 在Orderer上:
 
 ORDERER_GENERAL_LOGLEVEL=debug
 
 在 peers上:
 CORE_LOGGING_LEVEL=DEBUG
 
 Fabric CA
 通过添加参数-d开始执行命令
 
 如果可能的话，将完整日志上传到JIRA，而不仅仅是发生问题的地方
 
 
 <a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
