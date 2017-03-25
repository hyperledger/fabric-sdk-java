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

import java.io.File;
import java.net.MalformedURLException;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.fail;

public class HFCAClientEnrollIT {
    // public static class MemberServicesFabricCAImplTest {
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TEST_ADMIN_PW = "adminpw";
    private static final String TEST_ADMIN_ORG = "org0";
    private static final String TEST_USER2_NAME = "user2";
    private static final String TEST_USER3_NAME = "user3";
    private static final String TEST_USER1_NAME = "user1";
    private static final String TEST_USER1_ORG = "Org1";
    private static final String TEST_USER1_AFFILIATION = "org1.department1";
    private static final String CA_LOCATION = "http://localhost:7054";
    private SampleStore sampleStore;
    private HFCAClient client;
    SampleUser admin;

    @Before
    public void setup() throws CryptoException, InvalidArgumentException, MalformedURLException, EnrollmentException {

        File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        sampleStoreFile.deleteOnExit();

        CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
        cryptoSuite.init();
        client = new HFCAClient(CA_LOCATION, null);
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
                user2.setEnrollmentSecret(client.register(rr, admin));
            }
            if (!user2.isEnrolled()) {
                user2.setEnrollment(client.enroll(user2.getName(), user2.getEnrollmentSecret()));
            }

            sleepALittle();

            // get another enrollment
            Enrollment tmpEnroll = client.reenroll(user2);

            sleepALittle();

            // revoke the tmp enrollment
            client.revoke(admin, tmpEnroll, 1);
        } catch (Exception e) {
            e.printStackTrace();
            fail("user reenroll/revoke test failed with error : " + e.getMessage());
        }
    }

    @Test
    public void testUserRevoke() {
        try {
            CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
            cryptoSuite.init();
            HFCAClient client = new HFCAClient(CA_LOCATION, null);
            client.setCryptoSuite(cryptoSuite);


            SampleUser user3 = sampleStore.getMember(TEST_USER3_NAME, TEST_USER1_ORG);

            if (!user3.isRegistered()) {
                RegistrationRequest rr = new RegistrationRequest(user3.getName(), TEST_USER1_AFFILIATION);
                user3.setEnrollmentSecret(client.register(rr, admin)); //Admin can register other users.
            }

            sleepALittle();

            if (!user3.isEnrolled()) {
                user3.setEnrollment(client.enroll(user3.getName(), user3.getEnrollmentSecret()));
            }

            sleepALittle();

            client.revoke(admin, user3.getName(), 1);
        } catch (Exception e) {
            e.printStackTrace();
            fail("user enroll/revoke-all test failed with error : " + e.getMessage());
        }
    }

    // https://jira.hyperledger.org/browse/FAB-2955
    private static void sleepALittle() {
        // Seems to be an odd that calling back too quickly can once in a while generate an error on the fabric_ca
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


    }

}