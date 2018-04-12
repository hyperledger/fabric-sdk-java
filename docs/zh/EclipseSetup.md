# Eclipse设置说明

## 前提准备

以下依赖关系必须满足：

 * JDK 1.8 或更高
 * Apache Maven

配置环境变量,确保 JAVA_HOME/bin 和 Apache maven 在PATH中. 

## Eclipse设置

1. 下载和安装最新的 Eclipse 客户端

2. 如果您想为项目做出贡献，您需要确保您已登录到Gerrit并设置了您的SSH密钥。 欲了解更多信息，请参阅[Gerrit](http://hyperledger-fabric.readthedocs.io/en/latest/Gerrit/lf-account.html)

3. 从Gerrit克隆Java SDK。 在点击复制到剪贴板图标之前，请确保已选择SSH和"Clone with commit-msg hook"。 确保你复制的内容中有：&& scp .. errit.hyperledger.org:hooks/commit-msg fabric-sdk-java/.git/hooks/
    * https://gerrit.hyperledger.org/r/#/admin/projects/fabric-sdk-java

4. 如果没有安装maven,请下载安装.
    * https://maven.apache.org/download.cgi
5. 打开Eclipse来导入项目。File > Import > Maven > Existing Maven Project.选择您在步骤3中克隆SDK的位置。
    * 如果你看到错误, **Failed to read the project description file (.project) for 'fabric-sdk-java'** ,说明该文件已在磁盘上更改，并且现在包含无效信息。 描述文件恢复到有效状态时，项目才能正常运行。

6. 点击完成.
    * 如果您看到错误:  **No marketplace entries found to handle maven-antrun-plugin:1.4:run in Eclipse.**,请参阅帮助了解更多信息。继续点击完成。 我们稍后会解决这个问题。

7. 下载依赖关系.
    进入到您的fabric-sdk-java文件夹，然后执行以下命令： **mvn install -DskipTests**
    
8. 在步骤6中运行命令后，您可能会在Eclipse中看到以下错误：
    **Plugin execution not covered by lifecycle configuration: org.apache.maven.plugins:maven-antrun-plugin:1.4:run (execution: default, phase: generate-test-resources).**
    右键单击错误并选择:**Mark goal run as ignored in eclipse.**

9. 启用Checkstyle. 
    在 Project > Properties > Checkstyle 中,确保“Checkstyle active for this project”, “files outside source directories”, 和 “derived (generated) files” 全部是选中的.

10. 点击“Local Check Configurations”,然后选择 “New”->“External Configuration File”,点击“Browse”,然后选择fabric-sdk-java 根目录下的“checkstyle-config.xml”.

11. 点击"Apply and Close",checkstyle将被应用。

您的eclipse环境现在设置完成了。