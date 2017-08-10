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
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;

import static java.lang.String.format;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test cowers main API functionality
 * <p>
 * Run hyperledger nodes by the next script - fabric-sdk-java/src/test/fixture/sdkintegration/fabric.sh up
 */
public class MainAPIServiceIT {

    private static final String FABRIC_CA_HTTP_URL = "http://localhost:7054";
    private static final String ORDERER_NAME = "orderer.example.com";
    private static final String TEST_CHANNEL_NAME = "foo";
    private static final String TEST_USER_NAME = "Admin";

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private MainAPIService mainAPIService = new MainAPIService();

    private static final TestConfig testConfig = TestConfig.getConfig();
    private SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");

    private File keystoreDir = Paths.get(testConfig.getTestChannelPath(), TestConfig.getTestPeerOrgPath(), sampleOrg.getDomainName(), format("/users/Admin@%s/msp/keystore", sampleOrg.getDomainName())).toFile();
    private File certificateFile = Paths.get(testConfig.getTestChannelPath(), TestConfig.getTestPeerOrgPath(), sampleOrg.getDomainName(), format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", sampleOrg.getDomainName(), sampleOrg.getDomainName())).toFile();

    private SampleStore sampleStore;
    private Orderer orderer;

    @Before
    public void setup() throws Exception {
        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        sampleStore = new SampleStore(sampleStoreFile);
        sampleOrg.setAdmin(mainAPIService.getUser(TEST_USER_NAME, sampleOrg, sampleStore, keystoreDir, certificateFile));
        sampleOrg.setCALocation(FABRIC_CA_HTTP_URL);
        sampleOrg.setHfclient(mainAPIService.constructHFClient(sampleOrg));
        Collection<Orderer> orderers = mainAPIService.getOrderers(sampleOrg, sampleOrg.getHfclient(), testConfig.getOrdererProperties(ORDERER_NAME));
        assertTrue(orderers.size() > 0);
        orderer = orderers.iterator().next();
    }

    @Test
    public void getUserTest() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        SampleUser user = mainAPIService.getUser(TEST_USER_NAME, sampleOrg, sampleStore, keystoreDir, certificateFile);
        assertEquals(user.getName(), TEST_USER_NAME);
        assertEquals(user.getMspId(), sampleOrg.getMSPID());
        assertEquals(user.getEnrollment().getKey().getAlgorithm(), "ECDSA");
        assertEquals(user.getEnrollment().getKey().getFormat(), "PKCS#8");
    }

    @Test
    public void getOrderersTest() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidArgumentException {
        Collection<Orderer> orderers = mainAPIService.getOrderers(sampleOrg, sampleOrg.getHfclient(), testConfig.getOrdererProperties(ORDERER_NAME));
        assertTrue(orderers.size() == 1);
    }

    @Test
    public void getOrCreateChannelTest() throws Exception {
        Channel channel = mainAPIService.getOrCreateChannel(TEST_CHANNEL_NAME, sampleOrg.getHfclient(), orderer, sampleOrg);
        assertTrue(channel.isInitialized());
        assertEquals(channel.getName(), TEST_CHANNEL_NAME);

    }

    @Test
    public void getChanelTest() throws Exception {
        Channel channel = mainAPIService.getChanel(TEST_CHANNEL_NAME, sampleOrg.getHfclient(), orderer, sampleOrg);
        assertTrue(channel.isInitialized());
        assertEquals(channel.getName(), TEST_CHANNEL_NAME);
    }


    /**
     * Run this test only if you did not create the channel.
     *
     * @throws Exception
     */
    @Ignore
    @Test
    public void newChannelTest() throws Exception {
        Channel channel = mainAPIService.newChannel(TEST_CHANNEL_NAME, sampleOrg.getHfclient(), sampleOrg, orderer);
        assertTrue(channel.isInitialized());
        assertEquals(channel.getName(), TEST_CHANNEL_NAME);
    }

}
