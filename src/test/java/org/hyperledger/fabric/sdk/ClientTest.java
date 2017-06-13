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

import java.security.PrivateKey;
import java.util.Set;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ClientTest {
    private static final String CHANNEL_NAME = "channel1";
    static HFClient hfclient = null;

    @BeforeClass
    public static void setupClient() throws Exception {
        try {
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
        client.setUserContext(new MockUser());
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

        MockUser mockUser = new MockUser();
        mockUser.name = null;

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserNameEmpty() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = new MockUser();
        mockUser.name = "";

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserMSPIDNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = new MockUser();
        mockUser.mspId = null;

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadUserMSPIDEmpty() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = new MockUser();
        mockUser.mspId = "";

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentNull() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = new MockUser();
        mockUser.enrollment = null;

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentBadCert() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = new MockUser();
        mockUser.enrollment.cert = null;

        client.setUserContext(mockUser);

    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadEnrollmentBadKey() throws Exception {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        MockUser mockUser = new MockUser();
        mockUser.enrollment.privateKey = null;

        client.setUserContext(mockUser);

    }

    static class MockEnrollment implements Enrollment {
        public String cert = "mockCert";
        public PrivateKey privateKey = new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return null;
            }

            @Override
            public String getFormat() {
                return null;
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        @Override
        public PrivateKey getKey() {
            return privateKey;
        }

        @Override
        public String getCert() {
            return cert;
        }
    }

    static class MockUser implements User {
        public String name = "MockMe";
        public String mspId = "MockMSPID";
        public MockEnrollment enrollment = new MockEnrollment();

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Set<String> getRoles() {
            return null;
        }

        @Override
        public String getAccount() {
            return null;
        }

        @Override
        public String getAffiliation() {
            return null;
        }

        @Override
        public Enrollment getEnrollment() {
            return enrollment;
        }

        @Override
        public String getMspId() {
            return mspId;
        }
    }

}
