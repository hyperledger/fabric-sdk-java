/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
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
import java.net.MalformedURLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.Attribute;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.helper.Config;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.fail;

public class HFCAClientEnrollIT {
    // public static class MemberServicesFabricCAImplTest {
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TEST_ADMIN_PW = "adminpw";
    private static final String TEST_ADMIN_ORG = "org1";
    private static final String TEST_USER2_NAME = "user2";
    private static final String TEST_USER2_PW = "user2pw";
    private static final String TEST_USER3_NAME = "user3";
    private static final String TEST_USER3_PW = "user3pw";
    private static final String TEST_USER1_ORG = "Org2";
    private static final String TEST_USER1_AFFILIATION = "org1.department1";
    private static final String TEST_WITH_INTEGRATION_ORG= "peerOrg1";
    private SampleStore sampleStore;
    private HFCAClient client;
    SampleUser admin;

    private static TestConfig testConfig = TestConfig.getConfig();

    @Before
    public void setup() throws CryptoException, InvalidArgumentException, org.hyperledger.fabric.sdk.exception.InvalidArgumentException, MalformedURLException, EnrollmentException {

        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();


        CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
        cryptoSuite.init();
        client = HFCAClient.createNewInstance(testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        client.setCryptoSuite(cryptoSuite);

        //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface
        admin = sampleStore.getMember(TEST_ADMIN_NAME, TEST_ADMIN_ORG);
        if (!admin.isEnrolled()) {  //Preregistered admin only needs to be enrolled with Fabric CA.
            admin.setEnrollment(client.enroll(admin.getName(), TEST_ADMIN_PW));
        }

    }

    @Test
    public void testReenrollAndRevoke() {
        try {

            SampleUser user2 = sampleStore.getMember(TEST_USER2_NAME, TEST_ADMIN_ORG);

            if (!user2.isRegistered()) {  // users need to be registered AND enrolled
                RegistrationRequest rr = new RegistrationRequest(user2.getName(), TEST_USER1_AFFILIATION);
                rr.setSecret(TEST_USER2_PW);
                user2.setEnrollmentSecret(client.register(rr, admin));
                if (!user2.getEnrollmentSecret().equals(TEST_USER2_PW)) {
                    fail("Secret returned from RegistrationRequest not match : " + user2.getEnrollmentSecret());
                }
            }
            if (!user2.isEnrolled()) {
                user2.setEnrollment(client.enroll(user2.getName(), user2.getEnrollmentSecret()));
            }

            sleepALittle();

            // get another enrollment
            EnrollmentRequest req = new EnrollmentRequest("profile 1", "label 1", null);
            req.addHost("example1.ibm.com");
            req.addHost("example2.ibm.com");
            Enrollment tmpEnroll = client.reenroll(user2, req);

            // verify
            String cert = tmpEnroll.getCert();
            verifyOptions(cert, req);

            sleepALittle();

            // revoke one enrollment of this user
            client.revoke(admin, tmpEnroll, "remove use2r");

            // trying to reenroll should be ok (revocation above is only for a particular enrollment of this user)
            client.reenroll(user2);
        } catch (Exception e) {
            e.printStackTrace();
            fail("user reenroll/revoke test failed with error : " + e.getMessage());
        }
    }

    @Test
    public void testUserRevoke() {
        try {

            SampleUser user3 = sampleStore.getMember(TEST_USER3_NAME, TEST_USER1_ORG);

            if (!user3.isRegistered()) {
                RegistrationRequest rr = new RegistrationRequest(user3.getName(), TEST_USER1_AFFILIATION);
                rr.setSecret(TEST_USER3_PW);
                rr.addAttribute(new Attribute("user.role", "department lead"));
                rr.addAttribute(new Attribute("hf.revoker", "true"));
                user3.setEnrollmentSecret(client.register(rr, admin)); //Admin can register other users.
                if (!user3.getEnrollmentSecret().equals(TEST_USER3_PW)) {
                    fail("Secret returned from RegistrationRequest not match : " + user3.getEnrollmentSecret());
                }
            }

            sleepALittle();

            if (!user3.isEnrolled()) {
                EnrollmentRequest req = new EnrollmentRequest("profile 2", "label 2", null);
                req.addHost("example3.ibm.com");
                user3.setEnrollment(client.enroll(user3.getName(), user3.getEnrollmentSecret(), req));

                // verify
                String cert = user3.getEnrollment().getCert();
                verifyOptions(cert, req);
            }

            sleepALittle();

            // revoke all enrollment of this user
            client.revoke(admin, user3.getName(), "revoke user 3");

            try {
                // trying to reenroll the revoked user should fail
                client.reenroll(user3);
                fail("test failed: revoked user should not be able to reenroll");
            } catch (EnrollmentException e) {
                // this should be ok
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail("user enroll/revoke-all test failed with error : " + e.getMessage());
        }
    }

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

    private static void sleepALittle() {
        // Seems to be an odd that calling back too quickly can once in a while generate an error on the fabric_ca
//        try {
//            Thread.sleep(5000);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }

    }

}
