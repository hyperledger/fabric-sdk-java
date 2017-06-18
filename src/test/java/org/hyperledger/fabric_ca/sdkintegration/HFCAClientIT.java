/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric_ca.sdkintegration;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.Attribute;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.MockHFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.RevocationException;
import org.hyperledger.fabric_ca.sdk.helper.Config;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static java.lang.String.format;
import static org.junit.Assert.fail;

public class HFCAClientIT {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TEST_ADMIN_PW = "adminpw";
    private static final String TEST_ADMIN_ORG = "org1";
    private static final String TEST_USER1_ORG = "Org2";
    private static final String TEST_USER1_AFFILIATION = "org1.department1";
    private static final String TEST_WITH_INTEGRATION_ORG = "peerOrg1";

    private SampleStore sampleStore;
    private HFCAClient client;
    private SampleUser admin;

    private static CryptoSuite crypto;

    // Keeps track of how many test users we've created
    private static int userCount = 0;

    // Common prefix for all test users (the suffix will be the current user count)
    // Note that we include the time value so that these tests can be executed repeatedly
    // without needing to restart the CA (because you cannot register a username more than once!)
    private static String userNamePrefix = "user" + (System.currentTimeMillis() / 1000) + "_";

    private static TestConfig testConfig = TestConfig.getConfig();

    @BeforeClass
    public static void init() throws Exception {
        out("\n\n\nRUNNING: HFCAClientEnrollIT.\n");

        crypto = CryptoSuite.Factory.getCryptoSuite();
        crypto.init();
    }

    @Before
    public void setup() throws Exception {

        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { // For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();

        client = HFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        client.setCryptoSuite(crypto);

        // SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface
        admin = sampleStore.getMember(TEST_ADMIN_NAME, TEST_ADMIN_ORG);
        if (!admin.isEnrolled()) { // Preregistered admin only needs to be enrolled with Fabric CA.
            admin.setEnrollment(client.enroll(admin.getName(), TEST_ADMIN_PW));
        }

    }

    // Tests re-enrolling a user that has had an enrollment revoked
    @Test
    public void testReenrollAndRevoke() throws Exception {

        SampleUser user = getTestUser(TEST_ADMIN_ORG);

        if (!user.isRegistered()) { // users need to be registered AND enrolled
            RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
            String password = "testReenrollAndRevoke";
            rr.setSecret(password);
            user.setEnrollmentSecret(client.register(rr, admin));
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }
        if (!user.isEnrolled()) {
            user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret()));
        }

        sleepALittle();

        // get another enrollment
        EnrollmentRequest req = new EnrollmentRequest("profile 1", "label 1", null);
        req.addHost("example1.ibm.com");
        req.addHost("example2.ibm.com");
        Enrollment tmpEnroll = client.reenroll(user, req);

        // verify
        String cert = tmpEnroll.getCert();
        verifyOptions(cert, req);

        sleepALittle();

        // revoke one enrollment of this user
        client.revoke(admin, tmpEnroll, "remove user 2");

        // trying to reenroll should be ok (revocation above is only for a particular enrollment of this user)
        client.reenroll(user);

    }

    // Tests attempting to re-enroll a revoked user
    @Test
    public void testUserRevoke() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to re-enroll user");

        SampleUser user = getTestUser(TEST_USER1_ORG);

        if (!user.isRegistered()) {
            RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
            String password = "testUserRevoke";
            rr.setSecret(password);
            rr.addAttribute(new Attribute("user.role", "department lead"));
            rr.addAttribute(new Attribute("hf.revoker", "true"));
            user.setEnrollmentSecret(client.register(rr, admin)); // Admin can register other users.
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }

        sleepALittle();

        if (!user.isEnrolled()) {
            EnrollmentRequest req = new EnrollmentRequest("profile 2", "label 2", null);
            req.addHost("example3.ibm.com");
            user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret(), req));

            // verify
            String cert = user.getEnrollment().getCert();
            verifyOptions(cert, req);
        }

        sleepALittle();

        // revoke all enrollment of this user
        client.revoke(admin, user.getName(), "revoke user 3");

        // trying to reenroll the revoked user should fail with an EnrollmentException
        client.reenroll(user);
    }

    @Test
    public void testEnrollNoKeyPair() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to enroll user");

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        EnrollmentRequest req = new EnrollmentRequest("profile 1", "label 1", null);
        req.setCsr("test");
        client.enroll(user.getName(), user.getEnrollmentSecret(), req);
    }

    @Test
    public void testRevokeNotAuthorized() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("does not have attribute 'hf.Revoker'");

        // See if a normal user can revoke the admin...
        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);
        client.revoke(user, admin.getName(), "revoke admin");
    }

    @Test
    public void testEnrollSameUser() throws Exception {

        // thrown.expect(RevocationException.class);
        // thrown.expectMessage("does not have attribute 'hf.Revoker'");

        // See if a normal user can revoke the admin...
        SampleUser user1 = getEnrolledUser(TEST_ADMIN_ORG);

        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { // For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();

        SampleUser user2 = getEnrolledUser(TEST_ADMIN_ORG);

        // client.revoke(user, admin.getName(), "revoke admin");
        client.enroll(user1.getName(), user2.getEnrollmentSecret());
    }

    // Tests enrolling a user to an unknown CA client
    @Test
    public void testEnrollUnknownClient() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to enroll user");

        CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
        cryptoSuite.init();

        // This client does not exist
        String clientName = "test CA client";

        HFCAClient clientWithName = HFCAClient.createNewInstance(clientName,
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        clientWithName.setCryptoSuite(cryptoSuite);

        clientWithName.enroll(admin.getName(), TEST_ADMIN_PW);
    }

    // revoke1: revoke(User revoker, Enrollment enrollment, String reason)
    @Test
    public void testRevoke1NullReason() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("cannot be null");

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);
        client.revoke(admin, user.getEnrollment(), null);
    }

    // revoke2: revoke(User revoker, String revokee, String reason)
    @Test
    public void testRevoke2UnknownUser() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("Error while revoking");

        client.revoke(admin, "unknownUser", "remove user2");
    }

    @Test
    public void testRevoke2NullReason() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("cannot be null");

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);
        client.revoke(admin, user.getName(), null);
    }

    @Test
    public void testMockEnrollSuccessFalse() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("failed enrollment for user");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":false}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Ignore
    @Test
    public void testMockEnrollNoCert() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("failed enrollment for user");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Test
    public void testMockEnrollNoResult() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("response did not contain a result");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Test
    public void testMockEnrollWithMessages() throws Exception {

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        mockClient.setHttpPostResponse(
                "{\"success\":true, \"result\":{\"Cert\":\"abc\"}, \"messages\":[{\"code\":123, \"message\":\"test message\"}]}");
        mockClient.enroll(user.getName(), user.getEnrollmentSecret());
    }

    @Test
    public void testMockReenrollNoResult() throws Exception {

        thrown.expect(EnrollmentException.class);
        // thrown.expectMessage("failed");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.reenroll(user);
    }

    @Ignore
    @Test
    public void testMockReenrollNoCert() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("failed re-enrollment for user");

        MockHFCAClient mockClient = MockHFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        mockClient.setCryptoSuite(crypto);

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        mockClient.setHttpPostResponse("{\"success\":true}");
        mockClient.reenroll(user);
    }

    // ==========================================================================================
    // Helper methods
    // ==========================================================================================

    private void verifyOptions(String cert, EnrollmentRequest req) throws CertificateException {
        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(cert.getBytes()));
            CertificateFactory certFactory = CertificateFactory.getInstance(Config.getConfig().getCertificateFormat());
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);

            // check Subject Alternative Names
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            if (altNames == null) {
                if (req.getHosts() != null && !req.getHosts().isEmpty()) {
                    fail("Host name is not included in certificate");
                }
                return;
            }
            ArrayList<String> subAltList = new ArrayList<>();
            for (List<?> item : altNames) {
                int type = ((Integer) item.get(0)).intValue();
                if (type == 2) {
                    subAltList.add((String) item.get(1));
                }
            }
            if (!subAltList.equals(req.getHosts())) {
                fail("Subject Alternative Names not matched the host names specified in enrollment request");
            }

        } catch (CertificateParsingException e) {
            fail("Cannot parse certificate. Error is: " + e.getMessage());
            throw e;
        } catch (CertificateException e) {
            fail("Cannot regenerate x509 certificate. Error is: " + e.getMessage());
            throw e;
        }
    }

    // Returns a new (unique) user for use in a single test
    private SampleUser getTestUser(String org) {
        String userName = userNamePrefix + (++userCount);
        return sampleStore.getMember(userName, org);
    }

    // Returns an enrolled user
    private SampleUser getEnrolledUser(String org) throws Exception {
        SampleUser user = getTestUser(org);
        RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
        String password = "password";
        rr.setSecret(password);
        user.setEnrollmentSecret(client.register(rr, admin));
        if (!user.getEnrollmentSecret().equals(password)) {
            fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
        }
        user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret()));
        return user;
    }

    private void sleepALittle() {
        // Seems to be an odd that calling back too quickly can once in a while generate an error on the fabric_ca
        // try {
        // Thread.sleep(5000);
        // } catch (InterruptedException e) {
        // e.printStackTrace();
        // }

    }

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();
    }

}
