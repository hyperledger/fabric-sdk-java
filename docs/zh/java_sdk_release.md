# Java SDK 发布流程文档：

以下步骤说明如何将Hyperledger Fabric sdk-java jar文件发布到OSSRH
(开放源代码软件存储库托管)以及Maven中心。
Sonatype OSSRH使用 Sonatype Nexus Repository Manager为Hyperledger Fabric这样的开源项目提供存储库托管服务

OSSRH使用Maven仓库格式并提供以下功能:

1) 部署开发版本(snapshots)
2) 发布二进制文件
3) 推送发布并将它们同步到Maven中央存储库

在部署开发版本或稳定版本之前，您必须遵循以下步骤

1) [创建JIRA帐户](https://issues.sonatype.org/secure/Signup!default.jspa)
2) 创建一个新的工程
看[这个例子](https://issues.sonatype.org/browse/OSSRH-30331)以供参考

确保您的申请的项目已创建并且JIRA ticket已标记为Resolved。

在**pom.xml**中添加如下几行

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

在 **settings.xml** 中中添加如下几行

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
请确保**settings.xml** 文件已经复制到maven的home目录下.
在`cd ~/.m2/`中验证**settings.xml**.
按照以下步骤使用Maven方法将java jar文件发布到nexus/maven存储库。

### 步骤1:导出环境变量

确保将settings.xml文件中的值传递给环境变量.

```
export OSSRH_USER_TOKEN=ossrh ID
export OSSRH_PWD_TOKEN=ossrh pwd
```
### 步骤2:生成gpg密钥。

按照这个[链接](http://central.sonatype.org/pages/working-with-pgp-signatures.html)生成gpg密钥.

按照以下步骤生成gpg密钥：

- 执行以下命令生成gpg密钥以签署组件:

      `gpg --gen-key` 使用默认值
     - Key type should be RSA & RSA (default)
     - Key Size should be 2048 (default)
     - Key valid for 0 (defaulut)
     - Confirm above section - (y)
     - Provide Real Name (ossrh userid)
     - Provide email address (associated to the ossrh userid)
     - Provide comment ( Any of your choice)
     - Confirm the selection (Type O for Okay)
     - Enter Passphrase (remember this) and re-enter Passphrase

提供上述正确信息后，会生成gpg密钥。如果生成gpg密钥时间较长，你可以执行一些其他操作，如按下键盘，鼠标以及访问磁盘使用来加速进程。

- 列出生成gpg密钥
      `gpg2 --list-keys`
像下面这样:
```
/home/juven/.gnupg/pubring.gpg
------------------------------
pub   1024D/E8EBD57A 2017-06-17
uid                  Juven Xu (Juven Xu works at Sonatype) <juven@sonatype.com>
sub   2048g/D704745C 2017-06-17
```

- 分发公钥

运行以下命令分发公钥

`gpg2 --keyserver hkp://pool.sks-keyservers.net --send-keys E8EBD57A`

```
export GPG_KEY=<gpg public key> (E8EBD57A)
export GPG_PWD=<passphrase>
```
### 步骤3:部署组件

在fabric-sdk-java目录执行以下命令来构建和发布java jar文件到maven存储库

```
mvn clean install deploy -P release -s settings.xml -DskipITs=false -Dmaven.test.failure.ignore=false
```

一旦命令成功执行，您将在[maven中央存储库](https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java)中看到fabric-sdk-java，并在[nexus存储库](https://oss.sonatype.org/content/repositories/snapshots/org/hyperledger/fabric-sdk-java/fabric-sdk-java/)中看到java snapshot.

### 步骤4:执行发布到Maven

sonatype nexus推广发布版本构件已成功推送到https://oss.sonatype.org/#stagingProfiles.等待maven中央存储库同步此版本。 如果一切顺利，发布的组件应该在[Maven中央存储库](https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java)中可用。

# 使用示例APP测试Java SDK jar文件

[TODO]

## License <a name="license"></a>

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
