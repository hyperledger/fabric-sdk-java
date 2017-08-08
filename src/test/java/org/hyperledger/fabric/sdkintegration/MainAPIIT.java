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

import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.ChannelConfiguration;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

/**
 * Test cowers main API functionality
 */
public class MainAPIIT {


    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final TestConfig testConfig = TestConfig.getConfig();

    private Collection<Orderer> orderers = new LinkedList<>();
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TEST_ADMIN_PW = "adminpw";
    private static final String ORDER_INSTANCE_LOCATION_URL = "grpc://localhost:7050";


    private static CryptoPrimitives crypto;
    private SampleStore sampleStore;


    @BeforeClass
    public static void setupBeforeClass() {
        try {
            crypto = new CryptoPrimitives();
            crypto.init();
        } catch (Exception e) {
            throw new RuntimeException("HFCAClientTest.setupBeforeClass failed!", e);
        }
    }

    @Before
    public void setup() throws CryptoException, org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException, org.hyperledger.fabric.sdk.exception.InvalidArgumentException, MalformedURLException, EnrollmentException {
        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) {
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();
        //admin = sampleStore.getMember(TEST_ADMIN_NAME, TEST_ADMIN_ORG);
    }

    @Test
    public void testEnrollAdmin() throws Exception {
        assertEquals(enrollUser().getName(), "admin");
    }

    @Test
    public void testCreateChannel() throws Exception {
        createChannel();
    }


    private SampleUser enrollUser() throws CryptoException, org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException, org.hyperledger.fabric.sdk.exception.InvalidArgumentException, MalformedURLException, EnrollmentException {
        SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
        sampleOrg.setCAClient(HFCAClient.createNewInstance("http://localhost:7054", null));
        HFCAClient ca = sampleOrg.getCAClient();
        final String orgName = sampleOrg.getName();
        final String mspid = sampleOrg.getMSPID();
        ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
        if (!admin.isEnrolled()) {
            admin.setEnrollment(ca.enroll(admin.getName(), TEST_ADMIN_PW));
            admin.setMspId(mspid);
        }
        return admin;
    }

    private Channel createChannel() throws CryptoException, org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException, org.hyperledger.fabric.sdk.exception.InvalidArgumentException, IOException, EnrollmentException, TransactionException {
        SampleUser admin = enrollUser();
        SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
        sampleOrg.addOrdererLocation("orderer.example.com", ORDER_INSTANCE_LOCATION_URL);
        sampleOrg.setCAClient(HFCAClient.createNewInstance("http://localhost:7054", null));
        HFCAClient ca = sampleOrg.getCAClient();
        ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        HFClient hfclient = HFClient.createNewInstance();
        hfclient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        hfclient.setUserContext(admin);

        File txFile = new File(getClass().getResource("/foo.tx").getFile());
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(txFile);

        Orderer anOrderer = getOrders(sampleOrg, hfclient);
        byte[] channelConfig = hfclient.getChannelConfigurationSignature(channelConfiguration, admin/*sampleOrg.getPeerAdmin()*/);
        Channel newChannel = hfclient.newChannel("foo", anOrderer, channelConfiguration, channelConfig);
        newChannel.addOrderer(anOrderer);
        newChannel.initialize();
        return newChannel;
    }



    private Orderer getOrders(SampleOrg sampleOrg, HFClient hfclient) throws org.hyperledger.fabric.sdk.exception.InvalidArgumentException {
        for (String orderName : sampleOrg.getOrdererNames()) {
            Properties ordererProperties = testConfig.getOrdererProperties(orderName);
            //example of setting keepAlive to avoid timeouts on inactive http2 connections.
            // Under 5 minutes would require changes to server side to accept faster ping rates.
            ordererProperties.put("grpcs.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
            ordererProperties.put("grpcs.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
            orderers.add(hfclient.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName), ordererProperties));
        }
        //Just pick the first orderer in the list to create the channel.
        Orderer anOrderer = orderers.iterator().next();
        orderers.remove(anOrderer);
        return anOrderer;
    }


}
