#!/bin/bash

configtxgen -outputBlock orderer.block -profile TwoOrgsOrdererGenesis_v13
configtxgen -outputCreateChannelTx foo.tx -profile TwoOrgsChannel_v13 -channelID foo
configtxgen -outputCreateChannelTx bar.tx -profile TwoOrgsChannel_v13 -channelID bar
