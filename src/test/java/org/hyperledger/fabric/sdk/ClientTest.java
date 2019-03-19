/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric.sdk;

import java.util.concurrent.Executors;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.hyperledger.fabric.sdk.testutils.TestUtils.MockUser;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.junit.Assert.assertSame;

public class ClientTest {
    private static final String CHANNEL_NAME = "channel1";
    static HFClient hfclient = null;

    private static final String USER_NAME = "MockMe";
    private static final String USER_MSP_ID = "MockMSPID";

    @BeforeClass
    public static void setupClient() throws Exception {
        try {
            resetConfig();
            hfclient = TestHFClient.newInstance();

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }

    }

    @Test
    public void testNewChannel() {
        try {
            Channel testChannel = hfclient.newChannel(CHANNEL_NAME);
            Assert.assertTrue(testChannel != null && CHANNEL_NAME.equalsIgnoreCase(testChannel.getName()));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test (expected = InvalidArgumentException.class)
    public void testSetNullChannel() throws InvalidArgumentException {
        hfclient.newChannel(null);
        Assert.fail("Expected null channel to throw exception.");
    }

    @Test
    public void testNewPeer() {
        try {
            Peer peer = hfclient.newPeer("peer_", "grpc://localhost:7051");
            Assert.assertTrue(peer != null);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadURL() throws InvalidArgumentException {
        hfclient.newPeer("peer_", " ");
        Assert.fail("Expected peer with no channel throw exception");
    }

    @Test
    public void testNewOrderer() {
        try {
            Orderer orderer = hfclient.newOrderer("xx", "grpc://localhost:5005");
            Assert.assertTrue(orderer != null);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadAddress() throws InvalidArgumentException {
        hfclient.newOrderer("xx", "xxxxxx");
        Assert.fail("Orderer allowed setting bad URL.");
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadCryptoSuite() throws InvalidArgumentException {
        HFClient.createNewInstance()
                .newOrderer("xx", "xxxxxx");
        Assert.fail("Orderer allowed setting no cryptoSuite");
    }

    @Test
    public void testGoodMockUser() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        client.setUserContext(TestUtils.getMockUser(USER_NAME, USER_MSP_ID));
        Orderer orderer = hfclient.newOrderer("justMockme", "grpc://localhost:99"); // test mock should work.
        Assert.assertNotNull(orderer);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserContextNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        client.setUserContext(null);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserNameNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(null, USER_MSP_ID);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserNameEmpty() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser("", USER_MSP_ID);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserMSPIDNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, null);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserMSPIDEmpty() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, "");

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);
        mockUser.setEnrollment(null);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentBadCert() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);

        Enrollment mockEnrollment = TestUtils.getMockEnrollment(null);
        mockUser.setEnrollment(mockEnrollment);

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentBadKey() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);

        Enrollment mockEnrollment = TestUtils.getMockEnrollment(null, "mockCert");
        mockUser.setEnrollment(mockEnrollment);

        client.setUserContext(mockUser);

    }

    @Test
    public void testExecutorset() throws Exception {

        hfclient = TestHFClient.newInstance();
        //    ThreadPoolExecutor threadPoolExecutor = ThreadPoolExecutor()
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(10, 100,
                40, TimeUnit.valueOf("MILLISECONDS"),
                new SynchronousQueue<Runnable>(),
                r -> {
                    Thread t = Executors.defaultThreadFactory().newThread(r);
                    t.setDaemon(true);
                    return t;
                });

        hfclient.setExecutorService(threadPoolExecutor);
        assertSame(threadPoolExecutor, hfclient.getExecutorService());
        Channel mychannel = hfclient.newChannel("mychannel");
        assertSame(threadPoolExecutor, mychannel.getExecutorService());

    }

    @Test (expected = InvalidArgumentException.class)
    public void testExecutorsetAgain() throws Exception {

        hfclient = TestHFClient.newInstance();

        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(10, 100,
                40, TimeUnit.valueOf("MILLISECONDS"),
                new SynchronousQueue<Runnable>(),
                r -> {
                    Thread t = Executors.defaultThreadFactory().newThread(r);
                    t.setDaemon(true);
                    return t;
                });

        hfclient.setExecutorService(threadPoolExecutor);
        assertSame(threadPoolExecutor, hfclient.getExecutorService());
        ThreadPoolExecutor threadPoolExecutor2 = new ThreadPoolExecutor(10, 100,
                40, TimeUnit.valueOf("MILLISECONDS"),
                new SynchronousQueue<Runnable>(),
                r -> {
                    Thread t = Executors.defaultThreadFactory().newThread(r);
                    t.setDaemon(true);
                    return t;
                });
        hfclient.setExecutorService(threadPoolExecutor2);
    }

    @Test (expected = InvalidArgumentException.class)
    public void testExecutorDefaultSet() throws Exception {

        hfclient = TestHFClient.newInstance();

        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(10, 100,
                40, TimeUnit.valueOf("MILLISECONDS"),
                new SynchronousQueue<Runnable>(),
                r -> {
                    Thread t = Executors.defaultThreadFactory().newThread(r);
                    t.setDaemon(true);
                    return t;
                });

        Channel badisme = hfclient.newChannel("badisme");
        badisme.getExecutorService();
        hfclient.setExecutorService(threadPoolExecutor);
    }

    @Test (expected = InvalidArgumentException.class)
    public void testExecutorsetNULL() throws Exception {

        hfclient = TestHFClient.newInstance();

        hfclient.setExecutorService(null);
    }

    @Test //(expected = InvalidArgumentException.class)
    @Ignore
    public void testCryptoFactory() throws Exception {
        try {
            resetConfig();
            Assert.assertNotNull(Config.getConfig().getDefaultCryptoSuiteFactory());

            HFClient client = HFClient.createNewInstance();

            client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            MockUser mockUser = TestUtils.getMockUser(USER_NAME, USER_MSP_ID);

            Enrollment mockEnrollment = TestUtils.getMockEnrollment(null, "mockCert");
            mockUser.setEnrollment(mockEnrollment);

            client.setUserContext(mockUser);
        } finally {
            System.getProperties().remove("org.hyperledger.fabric.sdk.crypto.default_crypto_suite_factory");

        }

    }

}
