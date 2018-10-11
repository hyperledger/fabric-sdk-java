package org.hyperledger.fabric.sdkintegration;

import java.io.IOException;
import java.util.Collection;
import java.util.Properties;

import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/*
    This runs a version of end2end but with Node chaincode.
    It requires that End2endIT has been run already to do all enrollment and setting up of orgs,
    creation of the channels. None of that is specific to chaincode deployment language.
 */

public class End2endIdemixIT extends End2endIT {

    {
        CHAIN_CODE_FILEPATH = "sdkintegration/gocc/sampleIdemix";
        testName = "End2endIdemixIT";  //Just print out what test is really running.
        CHAIN_CODE_NAME = "idemix_example_go";
        CHAIN_CODE_LANG = TransactionRequest.Type.GO_LANG;
        testUser1 = "idemixUser";
    }

    private static final String FOO_CHANNEL_NAME = "foo";
    private static final TestConfig testConfig = TestConfig.getConfig();
    private Collection<SampleOrg> testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();

    @Override
    void blockWalker(HFClient client, Channel channel) throws InvalidArgumentException, ProposalException, IOException {
        // block walker depends on the state of the chain after go's end2end. Nothing here is language specific so
        // there is no loss in coverage for not doing this.
    }

    @Override
    @Test
    public void setup() throws Exception {
        sampleStore = new SampleStore(sampleStoreFile);
        setupUsers(sampleStore);
        runFabricTest(sampleStore); // just run fabric tests.
    }

    /**
     * Will register and enroll users persisting them to samplestore.
     *
     * @param sampleStore
     * @throws Exception
     */
    public void setupUsers(SampleStore sampleStore) throws Exception {
        //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface

        ////////////////////////////
        // get users for all orgs
        for (SampleOrg sampleOrg : testSampleOrgs) {
            final String orgName = sampleOrg.getName();

            SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
            sampleOrg.setAdmin(admin); // The admin of this org.

            sampleOrg.setPeerAdmin(sampleStore.getMember(orgName + "Admin", orgName));
        }

        enrollIdemixUser(sampleStore);
    }

    public void enrollIdemixUser(SampleStore sampleStore) throws Exception {
        for (SampleOrg sampleOrg : testSampleOrgs) {

            HFCAClient ca = sampleOrg.getCAClient();

            final String orgName = sampleOrg.getName();
            final String mspid = sampleOrg.getMSPID();
            ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            if (testConfig.isRunningFabricTLS()) {
                //This shows how to get a client TLS certificate from Fabric CA
                // we will use one client TLS certificate for orderer peers etc.
                final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
                enrollmentRequestTLS.addHost("localhost");
                enrollmentRequestTLS.setProfile("tls");
                final Enrollment enroll = ca.enroll("admin", "adminpw", enrollmentRequestTLS);
                final String tlsCertPEM = enroll.getCert();
                final String tlsKeyPEM = getPEMStringFromPrivateKey(enroll.getKey());

                final Properties tlsProperties = new Properties();

                tlsProperties.put("clientKeyBytes", tlsKeyPEM.getBytes(UTF_8));
                tlsProperties.put("clientCertBytes", tlsCertPEM.getBytes(UTF_8));
                clientTLSProperties.put(sampleOrg.getName(), tlsProperties);
                //Save in samplestore for follow on tests.
                sampleStore.storeClientPEMTLCertificate(sampleOrg, tlsCertPEM);
                sampleStore.storeClientPEMTLSKey(sampleOrg, tlsKeyPEM);
            }

            HFCAInfo info = ca.info(); //just check if we connect at all.
            assertNotNull(info);
            String infoName = info.getCAName();
            if (infoName != null && !infoName.isEmpty()) {
                assertEquals(ca.getCAName(), infoName);
            }

            SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
            SampleUser idemixUser = sampleStore.getMember(testUser1, sampleOrg.getName());
            if (!idemixUser.isRegistered()) {  // users need to be registered AND enrolled
                RegistrationRequest rr = new RegistrationRequest(idemixUser.getName(), "org1.department1");
                idemixUser.setEnrollmentSecret(ca.register(rr, admin));
            }
            if (!idemixUser.isEnrolled()) {
                idemixUser.setEnrollment(ca.enroll(idemixUser.getName(), idemixUser.getEnrollmentSecret()));
                idemixUser.setMspId(mspid);
            }

            // If running version 1.3, then get Idemix credential
            if (testConfig.isFabricVersionAtOrAfter("1.3")) {
                String mspID = "idemixMSPID1";
                if (sampleOrg.getName().contains("Org2")) {
                    mspID = "idemixMSPID2";
                }
                idemixUser.setIdemixEnrollment(ca.idemixEnroll(idemixUser.getEnrollment(), mspID));
            }

            sampleOrg.addUser(idemixUser);
        }
    }

    @Override
    Channel constructChannel(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        // override this method since we don't want to construct the channel that's been done.
        // Just get it out of the samplestore!

        client.setUserContext(sampleOrg.getPeerAdmin());

        return sampleStore.getChannel(client, name).initialize();

    }
}
