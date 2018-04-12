## 使用Fabric Vagrant环境
如果您的操作系统支持Docker并且您直接在系统中构建所有需求，则不需要Vagrant.
对于不是Vagrant环境的，去除涉及Vagrant的部分即可.
如果要在Vagrant中运行Fabric组件（peer，orderer，fabric-ca），请执行以下操作：

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


 * 打开文件`Vagrantfile`并验证是否设置了以下`config.vm.network`语句。 如果没有，则添加它们：
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

添加到您的Vagrantfile文件夹以引用下面几行之间的sdk集成文件夹：
(原文:Add to your Vagrantfile a folder for referencing the sdk integration folder between the lines below:)

  config.vm.synced_folder "..", "/opt/gopath/src/github.com/hyperledger/fabric"</br>

  `config.vm.synced_folder "/home/<<user>>/fabric-sdk-java/src/test/fixture/sdkintegration", "/opt/gopath/src/github.com/hyperledger/fabric/sdkintegration"`</br>

  config.vm.synced_folder ENV.fetch('LOCALDEVDIR', ".."), "#{LOCALDEV}"</br>