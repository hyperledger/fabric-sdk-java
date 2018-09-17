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
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollment;
import org.hyperledger.fabric.sdk.identity.IdemixRoles;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.exception.RegistrationException;
import org.hyperledger.fabric_ca.sdk.exception.RevocationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.invokeMethod;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class HFCAClientTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TEST_ADMIN_PW = "adminpw";
    private static final String TEST_ADMIN_ORG = "org1";

    private SampleStore sampleStore;
    SampleUser admin;

    private static CryptoPrimitives crypto;

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
    public void setup() throws CryptoException, InvalidArgumentException,
            org.hyperledger.fabric.sdk.exception.InvalidArgumentException, MalformedURLException, EnrollmentException {

        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { // For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();

        // SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface
        admin = sampleStore.getMember(TEST_ADMIN_NAME, TEST_ADMIN_ORG);

    }

    @Test
    public void testNewInstance() throws Exception {

        HFCAClient memberServices = HFCAClient.createNewInstance("http://localhost:99", null);

        assertNotNull(memberServices);
        Assert.assertSame(HFCAClient.class, memberServices.getClass());
    }

    @Test
    public void testNewInstanceWithName() throws Exception {

        HFCAClient memberServices = HFCAClient.createNewInstance("name", "http://localhost:99", null);

        assertNotNull(memberServices);
        Assert.assertSame(HFCAClient.class, memberServices.getClass());

    }

    @Test
    public void testNewInstanceWithNameAndProperties() throws Exception {

        Properties testProps = new Properties();
        HFCAClient memberServices = HFCAClient.createNewInstance("name", "http://localhost:99", testProps);

        assertNotNull(memberServices);
        Assert.assertSame(HFCAClient.class, memberServices.getClass());

    }

    @Test
    public void testNewInstanceNullUrl() throws Exception {
        thrown.expect(MalformedURLException.class);
        HFCAClient.createNewInstance(null, (Properties) null);
    }

    @Test
    public void testNewInstanceEmptyUrl() throws Exception {
        thrown.expect(MalformedURLException.class);
        HFCAClient.createNewInstance("", null);
    }

    @Test
    public void testNewInstanceBadUrlProto() throws Exception {

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("HFCAClient only supports");

        HFCAClient.createNewInstance("file://localhost", null);
    }

    @Test
    public void testNewInstanceBadUrlPath() throws Exception {

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("HFCAClient url does not support path");

        HFCAClient.createNewInstance("http://localhost/bad", null);
    }

    @Test
    public void testNewInstanceNoUrlHost() throws Exception {

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("HFCAClient url needs host");

        HFCAClient.createNewInstance("http://:99", null);
    }

    @Test
    public void testNewInstanceBadUrlQuery() throws Exception {

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("HFCAClient url does not support query");

        HFCAClient.createNewInstance("http://localhost?bad", null);
    }

    @Test
    public void testNewInstanceNullName() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("name must not be");

        HFCAClient.createNewInstance(null, "http://localhost:99", null);
    }

    @Test
    public void testNewInstanceEmptyName() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("name must not be");

        HFCAClient.createNewInstance("", "http://localhost:99", null);

    }

    @Test
    public void testSetCryptoSuite() throws Exception {

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);

        CryptoPrimitives testcrypt = new CryptoPrimitives();
        client.setCryptoSuite(testcrypt);
        Assert.assertEquals(testcrypt, client.getCryptoSuite());

    }

    @Test
    public void testRegisterEnrollmentIdNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("EntrollmentID cannot be null or empty");

        RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
        regreq.setEnrollmentID(null);

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.register(regreq, null);
    }

    @Test
    public void testRegisterEnrollmentIdEmpty() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("EntrollmentID cannot be null or empty");

        RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
        regreq.setEnrollmentID("");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.register(regreq, null);
    }

    @Test
    public void testRegisterNullRegistrar() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Registrar should be a valid member");

        RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
        regreq.setEnrollmentID("abc");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.register(regreq, null);
    }

    @Test
    public void testRegisterNoServerResponse() throws Exception {

        thrown.expect(RegistrationException.class);
        thrown.expectMessage("Error while registering the user");

        Properties testProps = new Properties();
        HFCAClient client = HFCAClient.createNewInstance("client", "https://localhost:99", testProps);

        CryptoPrimitives testcrypt = new CryptoPrimitives();
        client.setCryptoSuite(testcrypt);

        RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
        client.register(regreq, admin);

    }

    @Test
    public void testRegisterNoServerResponseAllHostNames() throws Exception {

        thrown.expect(RegistrationException.class);
        thrown.expectMessage("Error while registering the user");

        Properties testProps = new Properties();
        testProps.setProperty("allowAllHostNames", "true");
        HFCAClient client = HFCAClient.createNewInstance("client", "https://localhost:99", testProps);

        CryptoPrimitives testcrypt = new CryptoPrimitives();
        client.setCryptoSuite(testcrypt);

        RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
        client.register(regreq, admin);
    }

    @Test
    public void testRegisterNoServerResponseNoPemFile() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Unable to add CA certificate");

        Properties testProps = new Properties();
        testProps.setProperty("pemFile", "nofile.pem");
        HFCAClient client = HFCAClient.createNewInstance("client", "https://localhost:99", testProps);

        CryptoPrimitives testcrypt = new CryptoPrimitives();
        client.setCryptoSuite(testcrypt);

        RegistrationRequest regreq = new RegistrationRequest("name", "affiliation");
        client.register(regreq, admin);
    }

    @Test
    public void testEnrollmentEmptyUser() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("enrollment user is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.enroll("", TEST_ADMIN_PW);
    }

    @Test
    public void testEnrollmentNullUser() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("enrollment user is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.enroll(null, TEST_ADMIN_PW);
    }

    @Test
    public void testEnrollmentEmptySecret() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("enrollment secret is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.enroll(TEST_ADMIN_NAME, "");
    }

    @Test
    public void testEnrollmentNullSecret() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("enrollment secret is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.enroll(TEST_ADMIN_NAME, null);
    }

    // Tests enrollment when no server is available
    @Test
    public void testEnrollmentNoServerResponse() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to enroll user admin");

        CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();

        EnrollmentRequest req = new EnrollmentRequest("profile 1", "label 1", null);
        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(cryptoSuite);

        client.enroll(TEST_ADMIN_NAME, TEST_ADMIN_NAME, req);
    }

    @Test
    public void testEnrollmentNoKeyPair() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to enroll user admin");

        CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();

        EnrollmentRequest req = new EnrollmentRequest("profile 1", "label 1", null);
        req.setCSR("abc");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(cryptoSuite);

        client.enroll(TEST_ADMIN_NAME, TEST_ADMIN_NAME, req);
    }

    @Test
    public void testReenrollNullUser() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("reenrollment user is missing");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.reenroll(null);
    }

    @Test
    public void testReenrollNullEnrollment() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("reenrollment user is not a valid user object");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        admin.setEnrollment(null);
        client.reenroll(admin);
    }

    @Test
    public void testRevoke1Exception() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("Error while revoking cert");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        KeyPair keypair = crypto.keyGen();
        Enrollment enrollment = new X509Enrollment(keypair, "abc");

        client.revoke(admin, enrollment, "keyCompromise");
    }

    // revoke1: revoke(User revoker, Enrollment enrollment, String reason)
    @Test
    public void testRevoke1NullUser() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("revoker is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        KeyPair keypair = crypto.keyGen();
        Enrollment enrollment = new X509Enrollment(keypair, "abc");

        client.revoke(null, enrollment, "keyCompromise");
    }

    @Test
    public void testRevoke1NullEnrollment() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("revokee enrollment is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.revoke(admin, (Enrollment) null, "keyCompromise");
    }

    // revoke2: revoke(User revoker, String revokee, String reason)
    @Test
    public void testRevoke2NullUser() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("revoker is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.revoke(null, admin.getName(), "keyCompromise");
    }

    @Test
    public void testRevoke2NullEnrollment() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("revokee user is not set");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.revoke(admin, (String) null, "keyCompromise");
    }

    @Test
    public void testTLSTrustedCertProperites() throws Throwable {

        Properties testprops = new Properties();

        testprops.setProperty("pemFile", "src/test/fixture/testPems/caBundled.pems," + // has 3 certs
                " src/test/fixture/testPems/Org1MSP_CA.pem"); // has 1

        testprops.put("pemBytes", Files.readAllBytes(Paths.get("src/test/fixture/testPems/Org2MSP_CA.pem")));

        CryptoPrimitives crypto = new CryptoPrimitives();
        crypto.init();

        HFCAClient client = HFCAClient.createNewInstance("client", "https://localhost:99", testprops);
        client.setCryptoSuite(crypto);

        invokeMethod(client, "setUpSSL");

        final KeyStore trustStore = client.cryptoPrimitives.getTrustStore();
        final Enumeration<String> aliases = trustStore.aliases();

        Set<BigInteger> expected = new HashSet<>(Arrays.asList(
                new BigInteger("4804555946196630157804911090140692961"),
                new BigInteger("127556113420528788056877188419421545986539833585"),
                new BigInteger("704500179517916368023344392810322275871763581896"),
                new BigInteger("70307443136265237483967001545015671922421894552"),
                new BigInteger("276393268186007733552859577416965113792")));

        int count = 0;
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final X509Certificate certificate = (X509Certificate) trustStore.getCertificate(alias);
            final BigInteger serialNumber = certificate.getSerialNumber();
            assertTrue(format("Missing certifiate with serial no. %s", serialNumber + ""), expected.contains(serialNumber));
            ++count;

        }
        assertEquals("Number of CA certificates mismatch", expected.size(), count);
    }

    @Test
    public void testIdemixNullEnrollment() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("enrollment is missing");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        client.idemixEnroll(null, "idemixMSP");
    }

    @Test
    public void testIdemixMissingMSPID() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("mspID cannot be null or empty");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA");
        KeyPair pair = keyGen.generateKeyPair();
        Enrollment enrollment = new X509Enrollment(pair, "");
        client.idemixEnroll(enrollment, null);
    }

    @Test
    public void testIdemixWrongEnrollment() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("enrollment type must be x509");

        HFCAClient client = HFCAClient.createNewInstance("client", "http://localhost:99", null);
        client.setCryptoSuite(crypto);
        Enrollment enrollment = new IdemixEnrollment(null, null, "mspid", null, null, null, "ou", (Integer) TestUtils.getField(IdemixRoles.MEMBER, "value"));
        client.idemixEnroll(enrollment, "mspid");
    }

    @Test
    public void testAddCAToURL() throws MalformedURLException, URISyntaxException, InvalidArgumentException {
        final String url = "http://localhost:99";
        HFCAClient client = HFCAClient.createNewInstance("ca1", url, null);
        client.setCryptoSuite(crypto);
        String url2 = client.addCAToURL(url);
        assertEquals(url + "?ca=ca1", url2);
    }
}