/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdkintegration;

import org.apache.commons.io.IOUtils;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.HFCAClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.hyperledger.fabric.sdkintegration.SampleStore.getPrivateKeyFromBytes;

/**
 * @author Maxim Z
 * Basic implementation of functionality for hyperledger 1.0 API
 */
public class MainAPIService {

    public SampleUser getUser(String userName, SampleOrg sampleOrg, SampleStore sampleStore, File keystoreDir, File certificateFile) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

        SampleUser sampleUser = new SampleUser(userName, sampleOrg.getName(), sampleStore);
        sampleUser.setMspId(sampleOrg.getMSPID());

        PrivateKey privateKey = getPrivateKeyFromBytes(IOUtils.toByteArray(new FileInputStream(Util.findFileSk(keystoreDir))));
        String certificate = new String(IOUtils.toByteArray(new FileInputStream(certificateFile)), "UTF-8");

        sampleUser.setEnrollment(new SampleStore.SampleStoreEnrollement(privateKey, certificate));
        sampleUser.saveState();
        return sampleUser;
    }

    public Channel getChanel(String channelName, HFClient hfclient, Orderer orderer, SampleOrg sampleOrg) throws InvalidArgumentException {
        Channel newChannel = hfclient.newChannel(channelName);
        newChannel.addOrderer(orderer);
        sampleOrg.peers.forEach(p -> {
            try {
                newChannel.addPeer(p);
            } catch (InvalidArgumentException e) {
                e.printStackTrace();
            }
        });

        try {
            newChannel.initialize();
        } catch (TransactionException e) {
            e.printStackTrace();
        }

        return newChannel;
    }

    public Channel newChannel(String channelName, HFClient hfclient, SampleOrg sampleOrg, Orderer orderer) throws IOException, InvalidArgumentException, TransactionException {

        File txFile = new File(getClass().getResource("/" + channelName + ".tx").getFile());
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(txFile);
        byte[] channelConfig = hfclient.getChannelConfigurationSignature(channelConfiguration, sampleOrg.getAdmin());

        Set<Peer> peers = new HashSet<>();
        sampleOrg.peerLocations.forEach((name, location) -> {
            try {
                peers.add(hfclient.newPeer(name, location));
            } catch (InvalidArgumentException e) {
                e.printStackTrace();
            }
        });

        Channel newChannel = hfclient.newChannel(channelName, orderer, channelConfiguration, channelConfig);

        for (Peer per : peers) newChannel.addPeer(per);

        newChannel.addOrderer(orderer);
        newChannel.initialize();
        return newChannel;
    }

    public Channel getOrCreateChannel(String channelName, HFClient hfclient, Orderer orderer, SampleOrg sampleOrg) throws TransactionException, IOException, InvalidArgumentException {
        try {
            return getChanel(channelName, hfclient, orderer, sampleOrg);
        } catch (InvalidArgumentException e) {
            e.printStackTrace();
            return newChannel(channelName, hfclient, sampleOrg, orderer);
        }
    }

    public Collection<Orderer> getOrderers(SampleOrg sampleOrg, HFClient hfclient, Properties ordererProperties) throws org.hyperledger.fabric.sdk.exception.InvalidArgumentException {
        Collection<Orderer> orderers = new HashSet<>();
        for (String orderName : sampleOrg.getOrdererNames()) {
            ordererProperties.put("grpcs.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
            ordererProperties.put("grpcs.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
            orderers.add(hfclient.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName), ordererProperties));
        }
        return orderers;
    }


    /**
     * SampleOrg have to contains peer, orderer, eventHub, client locations.
     *
     * @param sampleOrg
     */
    public HFClient constructHFClient(SampleOrg sampleOrg) throws MalformedURLException, CryptoException, InvalidArgumentException {
        sampleOrg.setCAClient(HFCAClient.createNewInstance(sampleOrg.getCALocation(), null));
        HFCAClient ca = sampleOrg.getCAClient();
        ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        HFClient hfclient = HFClient.createNewInstance();
        hfclient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        hfclient.setUserContext(sampleOrg.getAdmin());
        return hfclient;
    }

}
