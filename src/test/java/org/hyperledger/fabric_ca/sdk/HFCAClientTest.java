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

package org.hyperledger.fabric_ca.sdk;

import java.io.File;
import java.net.MalformedURLException;
import java.util.Properties;

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.exception.RegistrationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class HFCAClientTest {
    public static class MemberServicesFabricCAImplTest {
        private static final String TEST_ADMIN_NAME = "admin";
        private static final String TEST_ADMIN_PW = "adminpw";
        private static final String TEST_ADMIN_ORG = "org1";

        private SampleStore sampleStore;
        SampleUser admin;

        @Before
        public void setup() throws CryptoException, InvalidArgumentException, org.hyperledger.fabric.sdk.exception.InvalidArgumentException, MalformedURLException, EnrollmentException {

            File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
            if (sampleStoreFile.exists()) { //For testing start fresh
                sampleStoreFile.delete();
            }
            sampleStore = new SampleStore(sampleStoreFile);
            sampleStoreFile.deleteOnExit();

            //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface
            admin = sampleStore.getMember(TEST_ADMIN_NAME, TEST_ADMIN_ORG);

        }

        @Test
        public void testCOPCreation() {

            try {
                HFCAClient memberServices = HFCAClient.createNewInstance("http://localhost:99", null);
                Assert.assertNotNull(memberServices);
                Assert.assertSame(HFCAClient.class, memberServices.getClass());

            } catch (Exception e) {
                Assert.fail("Unexpected Exception " + e.getMessage());
            }
        }

        @Test
        public void testNullURL() {

            try {
                HFCAClient.createNewInstance(null, null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(MalformedURLException.class, e.getClass());

            }
        }

        @Test
        public void emptyURL() {

            try {
                HFCAClient.createNewInstance("", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(MalformedURLException.class, e.getClass());

            }
        }

        @Test
        public void testBadProto() {

            try {
                HFCAClient.createNewInstance("file://localhost", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(IllegalArgumentException.class, e.getClass());

            }
        }

        @Test
        public void testBadURLPath() {

            try {
                HFCAClient.createNewInstance("http://localhost/bad", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(IllegalArgumentException.class, e.getClass());

            }
        }

        @Test
        public void testBadURLQuery() {

            try {
                HFCAClient.createNewInstance("http://localhost?bad", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(IllegalArgumentException.class, e.getClass());

            }
        }

        @Test
        public void testNewInstanceNameUrlProperties() {

            try {
                HFCAClient memberServices = HFCAClient.createNewInstance("name", "http://localhost:99", null);
                Assert.assertNotNull(memberServices);
                Assert.assertSame(HFCAClient.class, memberServices.getClass());

            } catch (Exception e) {
                Assert.assertSame(IllegalArgumentException.class, e.getClass());

            }
        }

        @Test
        public void testNewInstanceNameUrlPropertiesSetNullName() {

            try {
                HFCAClient.createNewInstance(null, "http://localhost:99", null);
                Assert.fail("Expected exception when name is set to null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertEquals("name must not be null or an empty string.", e.getMessage());

            }
        }

        @Test
        public void testNewInstanceNameUrlPropertiesSetEmptyName() {

            try {
                HFCAClient.createNewInstance("", "http://localhost:99", null);
                Assert.fail("Expected exception when name is set to null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertEquals("name must not be null or an empty string.", e.getMessage());

            }
        }

        @Test
        public void testNewInstanceNoHost() {
            Properties testprops = new Properties();

            try {
                HFCAClient.createNewInstance("client", "http://:99", testprops);
                Assert.fail("Expected exception when hostname is not specified in the URL");

            } catch (Exception e) {
                Assert.assertSame(IllegalArgumentException.class, e.getClass());
                Assert.assertEquals("HFCAClient url needs host", e.getMessage());

            }
        }

        @Test
        public void testGetCryptoSuite() {
            CryptoPrimitives testcrypt = new CryptoPrimitives();

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.setCryptoSuite(testcrypt);
                Assert.assertEquals(testcrypt, client.getCryptoSuite());

            } catch (Exception e) {
                Assert.fail("Unexpected Exception " + e.getMessage());
            }
        }

        @Test
        public void testRegisterNullEnrollId() {

            try {
                RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
                regreq.setEnrollmentID(null);
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.register(regreq, null);
                Assert.fail("Expected exception when enrollment ID is null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertEquals("EntrollmentID cannot be null or empty", e.getMessage());

            }
        }

        @Test
        public void testRegisterEmptyEnrollId() {

            try {
                RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
                regreq.setEnrollmentID("");
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.register(regreq, null);
                Assert.fail("Expected exception when enrollment ID is empty");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertEquals("EntrollmentID cannot be null or empty", e.getMessage());

            }
        }

        @Test
        public void testRegisterNoServerResponse() {

            try {
                RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.register(regreq, admin);
                Assert.fail("Expected exception when server is not available during registration");

            } catch (Exception e) {
                Assert.assertSame(RegistrationException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("Error while registering the user"));

            }
        }

        @Test
        public void testEnrollmentEmptyUser() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.enroll("", TEST_ADMIN_PW);
                Assert.fail("Expected exception when user parameter is empty");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("enrollment user is not set"));

            }
        }

        @Test
        public void testEnrollmentNullUser() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.enroll(null, TEST_ADMIN_PW);
                Assert.fail("Expected exception when user parameter is null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("enrollment user is not set"));

            }
        }

        @Test
        public void testEnrollmentEmptySecret() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.enroll(TEST_ADMIN_NAME, "");
                Assert.fail("Expected exception when secret parameter is empty");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("enrollment secret is not set"));

            }
        }

        @Test
        public void testEnrollmentNullSecret() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.enroll(TEST_ADMIN_NAME, null);
                Assert.fail("Expected exception when secret parameter is null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("enrollment secret is not set"));

            }
        }

        @Test
        public void testEnrollmentNoServerResponse() {

            try {
                CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
                cryptoSuite.init();
                EnrollmentRequest req = new EnrollmentRequest("profile 1", "label 1", null);
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.setCryptoSuite(cryptoSuite);
                client.enroll(TEST_ADMIN_NAME, TEST_ADMIN_NAME, req);
                Assert.fail("Expected exception when server is not available during enrollment");

            } catch (Exception e) {
                Assert.assertSame(EnrollmentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("Url:http://localhost:99, Failed to enroll user admin "));

            }
        }

        @Test
        public void testReenrollmentNullUser() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.reenroll(null);
                Assert.fail("Expected exception when user parameter is null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("reenrollment user is missing"));

            }
        }

        @Test
        public void testReenrollmentNullEnrollmentObject() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                admin.setEnrollment(null);
                client.reenroll(admin);
                Assert.fail("Expected exception when user enrollment object is null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("reenrollment user is not a valid user object"));

            }
        }

        @Test
        public void testRevokeNullUserObject() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                client.revoke(null, admin.getName(), "keyCompromise");
                Assert.fail("Expected exception when revoker object is null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("revoker is not set"));

            }
        }

        @Test
        public void testRevokeNullEnrollmentObject() {

            try {
                HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
                admin.setEnrollment(null);
                client.revoke(admin, admin.getEnrollment(), "keyCompromise");
                Assert.fail("Expected exception when enrollment object is null");

            } catch (Exception e) {
                Assert.assertSame(InvalidArgumentException.class, e.getClass());
                Assert.assertTrue(e.getMessage().contains("revokee enrollment is not set"));

            }
        }
    }
}
