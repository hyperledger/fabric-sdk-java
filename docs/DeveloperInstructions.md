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