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
import java.io.StringReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.openssl.PEMParser;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.Attribute;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAAffiliation;
import org.hyperledger.fabric_ca.sdk.HFCAAffiliation.HFCAAffiliationResp;
import org.hyperledger.fabric_ca.sdk.HFCACertificateRequest;
import org.hyperledger.fabric_ca.sdk.HFCACertificateResponse;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCACredential;
import org.hyperledger.fabric_ca.sdk.HFCAIdentity;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.HFCAX509Certificate;
import org.hyperledger.fabric_ca.sdk.MockHFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.IdentityException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.exception.RevocationException;
import org.hyperledger.fabric_ca.sdk.helper.Config;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.setField;
import static org.hyperledger.fabric_ca.sdk.HFCAClient.DEFAULT_PROFILE_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
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
    private static final String TEST_WITH_INTEGRATION_ORG2 = "peerOrg2";

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

        resetConfig();

        crypto = CryptoSuite.Factory.getCryptoSuite();
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

    // Tests attributes
    @Test
    public void testRegisterAttributes() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        SampleUser user = new SampleUser("mrAttributes", TEST_ADMIN_ORG, sampleStore, crypto);

        RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
        String password = "mrAttributespassword";
        rr.setSecret(password);

        rr.addAttribute(new Attribute("testattr1", "mrAttributesValue1"));
        rr.addAttribute(new Attribute("testattr2", "mrAttributesValue2"));
        rr.addAttribute(new Attribute("testattrDEFAULTATTR", "mrAttributesValueDEFAULTATTR", true));
        user.setEnrollmentSecret(client.register(rr, admin));
        if (!user.getEnrollmentSecret().equals(password)) {
            fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
        }
        EnrollmentRequest req = new EnrollmentRequest();
        req.addAttrReq("testattr2").setOptional(false);

        user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret(), req));

        Enrollment enrollment = user.getEnrollment();
        String cert = enrollment.getCert();
        String certdec = getStringCert(cert);

        assertTrue(format("Missing testattr2 in certficate decoded: %s", certdec), certdec.contains("\"testattr2\":\"mrAttributesValue2\""));
        //Since request had specific attributes don't expect defaults.
        assertFalse(format("Contains testattrDEFAULTATTR in certificate decoded: %s", certdec), certdec.contains("\"testattrDEFAULTATTR\"")
                || certdec.contains("\"mrAttributesValueDEFAULTATTR\""));
        assertFalse(format("Contains testattr1 in certificate decoded: %s", certdec), certdec.contains("\"testattr1\"") || certdec.contains("\"mrAttributesValue1\""));

    }

    /**
     * Test that we get default attributes.
     *
     * @throws Exception
     */
    @Test
    public void testRegisterAttributesDefault() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        SampleUser user = new SampleUser("mrAttributesDefault", TEST_ADMIN_ORG, sampleStore, crypto);

        RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
        String password = "mrAttributespassword";
        rr.setSecret(password);

        rr.addAttribute(new Attribute("testattr1", "mrAttributesValue1"));
        rr.addAttribute(new Attribute("testattr2", "mrAttributesValue2"));
        rr.addAttribute(new Attribute("testattrDEFAULTATTR", "mrAttributesValueDEFAULTATTR", true));
        user.setEnrollmentSecret(client.register(rr, admin));
        if (!user.getEnrollmentSecret().equals(password)) {
            fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
        }

        user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret()));

        Enrollment enrollment = user.getEnrollment();
        String cert = enrollment.getCert();

        String certdec = getStringCert(cert);

        assertTrue(format("Missing testattrDEFAULTATTR in certficate decoded: %s", certdec), certdec.contains("\"testattrDEFAULTATTR\":\"mrAttributesValueDEFAULTATTR\""));
        //Since request and no attribute requests at all defaults should be in certificate.

        assertFalse(format("Contains testattr1 in certificate decoded: %s", certdec), certdec.contains("\"testattr1\"") || certdec.contains("\"mrAttributesValue1\""));
        assertFalse(format("Contains testattr2 in certificate decoded: %s", certdec), certdec.contains("\"testattr2\"") || certdec.contains("\"mrAttributesValue2\""));

    }

    /**
     * Test that we get no attributes.
     *
     * @throws Exception
     */
    @Test
    public void testRegisterAttributesNONE() throws Exception {
        SampleUser user = new SampleUser("mrAttributesNone", TEST_ADMIN_ORG, sampleStore, crypto);

        RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
        String password = "mrAttributespassword";
        rr.setSecret(password);

        rr.addAttribute(new Attribute("testattr1", "mrAttributesValue1"));
        rr.addAttribute(new Attribute("testattr2", "mrAttributesValue2"));
        rr.addAttribute(new Attribute("testattrDEFAULTATTR", "mrAttributesValueDEFAULTATTR", true));
        user.setEnrollmentSecret(client.register(rr, admin));
        if (!user.getEnrollmentSecret().equals(password)) {
            fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
        }

        EnrollmentRequest req = new EnrollmentRequest();
        req.addAttrReq(); // empty ensure no attributes.

        user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret(), req));

        Enrollment enrollment = user.getEnrollment();
        String cert = enrollment.getCert();

        String certdec = getStringCert(cert);

        assertFalse(format("Contains testattrDEFAULTATTR in certificate decoded: %s", certdec),
                certdec.contains("\"testattrDEFAULTATTR\"") || certdec.contains("\"mrAttributesValueDEFAULTATTR\""));
        assertFalse(format("Contains testattr1 in certificate decoded: %s", certdec), certdec.contains("\"testattr1\"") || certdec.contains("\"mrAttributesValue1\""));
        assertFalse(format("Contains testattr2 in certificate decoded: %s", certdec), certdec.contains("\"testattr2\"") || certdec.contains("\"mrAttributesValue2\""));

    }

    private static final Pattern compile = Pattern.compile("^-----BEGIN CERTIFICATE-----$" + "(.*?)" + "\n-----END CERTIFICATE-----\n", Pattern.DOTALL | Pattern.MULTILINE);

    static String getStringCert(String pemFormat) {
        String ret = null;

        final Matcher matcher = compile.matcher(pemFormat);
        if (matcher.matches()) {
            final String base64part = matcher.group(1).replaceAll("\n", "");
            Base64.Decoder b64dec = Base64.getDecoder();
            ret = new String(b64dec.decode(base64part.getBytes(UTF_8)));

        } else {
            fail("Certificate failed to match expected pattern. Certificate:\n" + pemFormat);
        }

        return ret;
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
        EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 1", null);
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

        Calendar calendar = Calendar.getInstance(); // gets a calendar using the default time zone and locale.
        Date revokedTinyBitAgoTime = calendar.getTime(); //avoid any clock skewing.

        SampleUser user = getTestUser(TEST_USER1_ORG);

        if (!user.isRegistered()) {
            RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
            String password = "testUserRevoke";
            rr.setSecret(password);
            rr.addAttribute(new Attribute("user.role", "department lead"));
            rr.addAttribute(new Attribute(HFCAClient.HFCA_ATTRIBUTE_HFREVOKER, "true"));
            user.setEnrollmentSecret(client.register(rr, admin)); // Admin can register other users.
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }

        if (!user.isEnrolled()) {
            EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 2", null);
            req.addHost("example3.ibm.com");
            user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret(), req));

            // verify
            String cert = user.getEnrollment().getCert();
            verifyOptions(cert, req);
        }

        int startedWithRevokes = -1;

        if (!testConfig.isRunningAgainstFabric10()) {
            Thread.sleep(1000); //prevent clock skewing. make sure we request started with revokes.
            startedWithRevokes = getRevokes(null).length; //one more after we do this revoke.
            Thread.sleep(1000); //prevent clock skewing. make sure we request started with revokes.
        }

        // revoke all enrollment of this user
        client.revoke(admin, user.getName(), "revoke user 3");
        if (!testConfig.isRunningAgainstFabric10()) {

            final int newRevokes = getRevokes(null).length;

            assertEquals(format("Expected one more revocation %d, but got %d", startedWithRevokes + 1, newRevokes), startedWithRevokes + 1, newRevokes);

            // see if we can get right number of revokes that we started with by specifying the time: revokedTinyBitAgoTime
            // TODO: Investigate clock scew
//            final int revokestinybitago = getRevokes(revokedTinyBitAgoTime).length; //Should be same number when test case was started.
//            assertEquals(format("Expected same revocations %d, but got %d", startedWithRevokes, revokestinybitago), startedWithRevokes, revokestinybitago);
        }

        // trying to reenroll the revoked user should fail with an EnrollmentException
        client.reenroll(user);
    }

    // Tests revoking a certificate
    @Test
    public void testCertificateRevoke() throws Exception {

        SampleUser user = getTestUser(TEST_USER1_ORG);

        if (!user.isRegistered()) {
            RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
            String password = "testUserRevoke";
            rr.setSecret(password);
            rr.addAttribute(new Attribute("user.role", "department lead"));
            rr.addAttribute(new Attribute(HFCAClient.HFCA_ATTRIBUTE_HFREVOKER, "true"));
            user.setEnrollmentSecret(client.register(rr, admin)); // Admin can register other users.
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }

        if (!user.isEnrolled()) {
            EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 2", null);
            req.addHost("example3.ibm.com");
            user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret(), req));
        }

        // verify
        String cert = user.getEnrollment().getCert();

        BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(cert.getBytes()));
        CertificateFactory certFactory = CertificateFactory.getInstance(Config.getConfig().getCertificateFormat());
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);

        // get its serial number
        String serial = DatatypeConverter.printHexBinary(certificate.getSerialNumber().toByteArray());

        // get its aki
        // 2.5.29.35 : AuthorityKeyIdentifier
        byte[] extensionValue = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        ASN1OctetString akiOc = ASN1OctetString.getInstance(extensionValue);
        String aki = DatatypeConverter.printHexBinary(AuthorityKeyIdentifier.getInstance(akiOc.getOctets()).getKeyIdentifier());

        int startedWithRevokes = -1;

        if (!testConfig.isRunningAgainstFabric10()) {
            Thread.sleep(1000); //prevent clock skewing. make sure we request started with revokes.
            startedWithRevokes = getRevokes(null).length; //one more after we do this revoke.
            Thread.sleep(1000); //prevent clock skewing. make sure we request started with revokes.
        }

        // revoke all enrollment of this user
        client.revoke(admin, serial, aki, "revoke certificate");
        if (!testConfig.isRunningAgainstFabric10()) {

            final int newRevokes = getRevokes(null).length;

            assertEquals(format("Expected one more revocation %d, but got %d", startedWithRevokes + 1, newRevokes), startedWithRevokes + 1, newRevokes);
        }
    }

    // Tests attempting to revoke a user with Null reason
    @Test
    public void testUserRevokeNullReason() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to re-enroll user");

        Calendar calendar = Calendar.getInstance(); // gets a calendar using the default time zone and locale.
        calendar.add(Calendar.SECOND, -1);
        Date revokedTinyBitAgoTime = calendar.getTime(); //avoid any clock skewing.

        SampleUser user = getTestUser(TEST_USER1_ORG);

        if (!user.isRegistered()) {
            RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
            String password = "testUserRevoke";
            rr.setSecret(password);
            rr.addAttribute(new Attribute("user.role", "department lead"));
            rr.addAttribute(new Attribute(HFCAClient.HFCA_ATTRIBUTE_HFREVOKER, "true"));
            user.setEnrollmentSecret(client.register(rr, admin)); // Admin can register other users.
            if (!user.getEnrollmentSecret().equals(password)) {
                fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
            }
        }

        sleepALittle();

        if (!user.isEnrolled()) {
            EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 2", null);
            req.addHost("example3.ibm.com");
            user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret(), req));

            // verify
            String cert = user.getEnrollment().getCert();
            verifyOptions(cert, req);
        }

        sleepALittle();

        int startedWithRevokes = -1;

        if (!testConfig.isRunningAgainstFabric10()) {

            startedWithRevokes = getRevokes(null).length; //one more after we do this revoke.
        }

        // revoke all enrollment of this user
        client.revoke(admin, user.getName(), null);
        if (!testConfig.isRunningAgainstFabric10()) {
            final int newRevokes = getRevokes(null).length;

            assertEquals(format("Expected one more revocation %d, but got %d", startedWithRevokes + 1, newRevokes), startedWithRevokes + 1, newRevokes);
        }

        // trying to reenroll the revoked user should fail with an EnrollmentException
        client.reenroll(user);
    }

    // Tests revoking a user with genCRL using the revoke API
    @Test
    public void testUserRevokeGenCRL() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to re-enroll user");

        Calendar calendar = Calendar.getInstance(); // gets a calendar using the default time zone and locale.
        calendar.add(Calendar.SECOND, -1);
        Date revokedTinyBitAgoTime = calendar.getTime(); //avoid any clock skewing.

        SampleUser user1 = getTestUser(TEST_USER1_ORG);
        SampleUser user2 = getTestUser(TEST_USER1_ORG);

        SampleUser[] users = new SampleUser[] {user1, user2};

        for (SampleUser user : users) {
            if (!user.isRegistered()) {
                RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
                String password = "testUserRevoke";
                rr.setSecret(password);
                rr.addAttribute(new Attribute("user.role", "department lead"));
                rr.addAttribute(new Attribute(HFCAClient.HFCA_ATTRIBUTE_HFREVOKER, "true"));
                user.setEnrollmentSecret(client.register(rr, admin)); // Admin can register other users.
                if (!user.getEnrollmentSecret().equals(password)) {
                    fail("Secret returned from RegistrationRequest not match : " + user.getEnrollmentSecret());
                }
            }

            sleepALittle();

            if (!user.isEnrolled()) {
                EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 2", null);
                req.addHost("example3.ibm.com");
                user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret(), req));

                // verify
                String cert = user.getEnrollment().getCert();
                verifyOptions(cert, req);
            }
        }

        sleepALittle();

        int startedWithRevokes = -1;

        startedWithRevokes = getRevokes(null).length; //one more after we do this revoke.

        // revoke all enrollment of this user and request back a CRL
        String crl = client.revoke(admin, user1.getName(), null, true);
        assertNotNull("Failed to get CRL using the Revoke API", crl);

        final int newRevokes = getRevokes(null).length;

        assertEquals(format("Expected one more revocation %d, but got %d", startedWithRevokes + 1, newRevokes), startedWithRevokes + 1, newRevokes);

        final int crlLength = parseCRL(crl).length;

        assertEquals(format("The number of revokes %d does not equal the number of revoked certificates (%d) in crl", newRevokes, crlLength), newRevokes, crlLength);

        // trying to reenroll the revoked user should fail with an EnrollmentException
        client.reenroll(user1);

        String crl2 = client.revoke(admin, user2.getName(), null, false);
        assertEquals("CRL not requested, CRL should be empty", "", crl2);

    }

    TBSCertList.CRLEntry[] getRevokes(Date r) throws Exception {

        String crl = client.generateCRL(admin, r, null, null, null);

        return parseCRL(crl);
    }

    TBSCertList.CRLEntry[] parseCRL(String crl) throws Exception {

        Base64.Decoder b64dec = Base64.getDecoder();
        final byte[] decode = b64dec.decode(crl.getBytes(UTF_8));

        PEMParser pem = new PEMParser(new StringReader(new String(decode)));
        X509CRLHolder holder = (X509CRLHolder) pem.readObject();

        return holder.toASN1Structure().getRevokedCertificates();
    }

    // Tests getting an identity
    @Test
    public void testCreateAndGetIdentity() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAIdentity ident = getIdentityReq("testuser1", HFCAClient.HFCA_TYPE_PEER);
        createSuccessfulHCAIdentity(ident, admin);

        HFCAIdentity identGet = client.newHFCAIdentity(ident.getEnrollmentId());
        identGet.read(admin);
        assertEquals("Incorrect response for id", ident.getEnrollmentId(), identGet.getEnrollmentId());
        assertEquals("Incorrect response for type", ident.getType(), identGet.getType());
        assertEquals("Incorrect response for affiliation", ident.getAffiliation(), identGet.getAffiliation());
        assertEquals("Incorrect response for max enrollments", ident.getMaxEnrollments(), identGet.getMaxEnrollments());

        Collection<Attribute> attrs = identGet.getAttributes();
        Boolean found = false;
        for (Attribute attr : attrs) {
            if (attr.getName().equals("testattr1")) {
                found = true;
                break;
            }
        }

        if (!found) {
            fail("Incorrect response for attribute");
        }
    }

    // Tests getting an identity that does not exist
    @Test
    public void testGetIdentityNotExist() throws Exception {
        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        setField(client, "statusCode", 405);
        HFCAIdentity ident = client.newHFCAIdentity("fakeUser");
        int statusCode = ident.read(admin);
        if (statusCode != 404) {
            fail("Incorrect status code return for an identity that is not found, should have returned 404 and not thrown an excpetion");
        }
        setField(client, "statusCode", 400);
    }

    // Tests getting all identities for a caller
    @Test
    public void testGetAllIdentity() throws Exception {
        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAIdentity ident = getIdentityReq("testuser2", HFCAClient.HFCA_TYPE_CLIENT);
        createSuccessfulHCAIdentity(ident, admin);

        Collection<HFCAIdentity> foundIdentities = client.getHFCAIdentities(admin);
        String[] expectedIdenities = new String[] {"testuser2", "admin"};
        Integer found = 0;

        for (HFCAIdentity id : foundIdentities) {
            for (String name : expectedIdenities) {
                if (id.getEnrollmentId().equals(name)) {
                    found++;
                }
            }
        }

        if (found != 2) {
            fail("Failed to get the correct number of identities");
        }

    }

    // Tests modifying an identity
    @Test
    public void testModifyIdentity() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAIdentity ident = getIdentityReq("testuser3", HFCAClient.HFCA_TYPE_ORDERER);
        createSuccessfulHCAIdentity(ident, admin);
        assertEquals("Incorrect response for type", "orderer", ident.getType());
        assertNotEquals("Incorrect value for max enrollments", ident.getMaxEnrollments(), new Integer(5));

        ident.setMaxEnrollments(5);
        ident.update(admin);
        assertEquals("Incorrect value for max enrollments", ident.getMaxEnrollments(), new Integer(5));

        ident.setMaxEnrollments(100);
        ident.read(admin);
        assertEquals("Incorrect value for max enrollments", new Integer(5), ident.getMaxEnrollments());
    }

    // Tests deleting an identity
    @Test
    public void testDeleteIdentity() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Failed to get User");

        SampleUser user = new SampleUser("testuser4", TEST_ADMIN_ORG, sampleStore, client.getCryptoSuite());

        HFCAIdentity ident = client.newHFCAIdentity(user.getName());

        createSuccessfulHCAIdentity(ident, admin);
        ident.delete(admin);

        ident.read(admin);
    }

    // Tests deleting an identity and making sure it can't update after deletion
    @Test
    public void testDeleteIdentityFailUpdate() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Identity has been deleted");

        HFCAIdentity ident = client.newHFCAIdentity("deletedUser");

        ident.create(admin);
        ident.delete(admin);

        ident.update(admin);
    }

    // Tests deleting an identity and making sure it can't delete again
    @Test
    public void testDeleteIdentityFailSecondDelete() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expect(IdentityException.class);
        thrown.expectMessage("Identity has been deleted");

        HFCAIdentity ident = client.newHFCAIdentity("deletedUser2");

        createSuccessfulHCAIdentity(ident, admin);
        ident.delete(admin);

        ident.delete(admin);
    }

    // Tests deleting an identity on CA that does not allow identity removal
    @Test
    public void testDeleteIdentityNotAllowed() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Identity removal is disabled");
        SampleUser user = new SampleUser("testuser5", "org2", sampleStore, client.getCryptoSuite());

        HFCAClient client2 = HFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG2).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG2).getCAProperties());
        client2.setCryptoSuite(crypto);

        // SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface
        SampleUser admin2 = sampleStore.getMember(TEST_ADMIN_NAME, "org2");
        if (!admin2.isEnrolled()) { // Preregistered admin only needs to be enrolled with Fabric CA.
            admin2.setEnrollment(client2.enroll(admin.getName(), TEST_ADMIN_PW));
        }

        HFCAIdentity ident = client2.newHFCAIdentity(user.getName());

        createSuccessfulHCAIdentity(ident, admin2);
        ident.delete(admin2);
    }

    // Tests getting an affiliation
    @Test
    public void testGetAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation aff = client.newHFCAAffiliation("org2");
        int resp = aff.read(admin);

        assertEquals("Incorrect response for affiliation name", "org2", aff.getName());
        assertEquals("Incorrect response for child affiliation name", "org2.department1", aff.getChild("department1").getName());
        assertEquals("Incorrect status code", new Integer(200), new Integer(resp));
    }

    // Tests getting all affiliation
    @Test
    public void testGetAllAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation resp = client.getHFCAAffiliations(admin);

        ArrayList<String> expectedFirstLevelAffiliations = new ArrayList<String>(Arrays.asList("org2", "org1"));
        int found = 0;
        for (HFCAAffiliation aff : resp.getChildren()) {
            for (Iterator<String> iter = expectedFirstLevelAffiliations.iterator(); iter.hasNext();
            ) {
                String element = iter.next();
                if (aff.getName().equals(element)) {
                    iter.remove();
                }
            }
        }

        if (!expectedFirstLevelAffiliations.isEmpty()) {
            fail("Failed to get the correct of affiliations, affiliations not returned: %s" + expectedFirstLevelAffiliations.toString());
        }

        ArrayList<String> expectedSecondLevelAffiliations = new ArrayList<String>(Arrays.asList("org2.department1", "org1.department1", "org1.department2"));
        for (HFCAAffiliation aff : resp.getChildren()) {
            for (HFCAAffiliation aff2 : aff.getChildren()) {
                expectedSecondLevelAffiliations.removeIf(element -> aff2.getName().equals(element));
            }
        }

        if (!expectedSecondLevelAffiliations.isEmpty()) {
            fail("Failed to get the correct child affiliations, affiliations not returned: %s" + expectedSecondLevelAffiliations.toString());
        }

    }

    // Tests adding an affiliation
    @Test
    public void testCreateAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation aff = client.newHFCAAffiliation("org3");
        HFCAAffiliationResp resp = aff.create(admin);

        assertEquals("Incorrect status code", new Integer(201), new Integer(resp.getStatusCode()));
        assertEquals("Incorrect response for id", "org3", aff.getName());

        Collection<HFCAAffiliation> children = aff.getChildren();
        assertEquals("Should have no children", 0, children.size());
    }

    // Tests updating an affiliation
    @Test
    public void testUpdateAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation aff = client.newHFCAAffiliation("org4");
        aff.create(admin);

        HFCAIdentity ident = client.newHFCAIdentity("testuser_org4");
        ident.setAffiliation(aff.getName());
        createSuccessfulHCAIdentity(ident, admin);

        HFCAAffiliation aff2 = client.newHFCAAffiliation("org4.dept1");
        aff2.create(admin);

        HFCAIdentity ident2 = client.newHFCAIdentity("testuser_org4.dept1");
        ident2.setAffiliation("org4.dept1");
        createSuccessfulHCAIdentity(ident2, admin);

        HFCAAffiliation aff3 = client.newHFCAAffiliation("org4.dept1.team1");
        aff3.create(admin);

        HFCAIdentity ident3 = client.newHFCAIdentity("testuser_org4.dept1.team1");
        ident3.setAffiliation("org4.dept1.team1");
        createSuccessfulHCAIdentity(ident3, admin);

        aff.setUpdateName("org5");
        // Set force option to true, since their identities associated with affiliations
        // that are getting updated
        HFCAAffiliationResp resp = aff.update(admin, true);

        int found = 0;
        int idCount = 0;
        // Should contain the affiliations affected by the update request
        HFCAAffiliation child = aff.getChild("dept1");
        assertNotNull(child);
        assertEquals("Failed to get correct child affiliation", "org5.dept1", child.getName());
        for (HFCAIdentity id : child.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org4.dept1")) {
                idCount++;
            }
        }
        HFCAAffiliation child2 = child.getChild("team1");
        assertNotNull(child2);
        assertEquals("Failed to get correct child affiliation", "org5.dept1.team1", child2.getName());
        for (HFCAIdentity id : child2.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org4.dept1.team1")) {
                idCount++;
            }
        }

        for (HFCAIdentity id : aff.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org4")) {
                idCount++;
            }
        }

        if (idCount != 3) {
            fail("Incorrect number of ids returned");
        }

        assertEquals("Incorrect response for id", "org5", aff.getName());
        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
    }

    // Tests updating an affiliation that doesn't require force option
    @Test
    public void testUpdateAffiliationNoForce() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation aff = client.newHFCAAffiliation("org_5");
        aff.create(admin);
        aff.setUpdateName("org_6");
        HFCAAffiliationResp resp = aff.update(admin);

        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
        assertEquals("Failed to delete affiliation", "org_6", aff.getName());
    }

    // Trying to update affiliations with child affiliations and identities
    // should fail if not using 'force' option.
    @Test
    public void testUpdateAffiliationInvalid() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Need to use 'force' to remove identities and affiliation");

        HFCAAffiliation aff = client.newHFCAAffiliation("org1.dept1");
        aff.create(admin);

        HFCAAffiliation aff2 = aff.createDecendent("team1");
        aff2.create(admin);

        HFCAIdentity ident = getIdentityReq("testorg1dept1", "client");
        ident.setAffiliation(aff.getName());
        createSuccessfulHCAIdentity(ident, admin);

        aff.setUpdateName("org1.dept2");
        HFCAAffiliationResp resp = aff.update(admin);
        assertEquals("Incorrect status code", new Integer(400), new Integer(resp.getStatusCode()));
    }

    private static int createSuccessfulHCAIdentity(HFCAIdentity ident, User user) throws InvalidArgumentException, IdentityException {

        int rc = ident.create(user);
        assertTrue(rc < 400);
        assertNotNull(ident.getSecret());
        assertFalse(ident.getSecret().isEmpty());
        assertNotNull(ident.getEnrollmentId());
        assertFalse(ident.getEnrollmentId().isEmpty());
        assertNotNull(ident.getType());
        assertFalse(ident.getType().isEmpty());

        return rc;
    }

    // Tests deleting an affiliation
    @Test
    public void testDeleteAffiliation() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Affiliation has been deleted");

        HFCAAffiliation aff = client.newHFCAAffiliation("org6");
        aff.create(admin);

        HFCAIdentity ident = client.newHFCAIdentity("testuser_org6");
        ident.setAffiliation("org6");
        createSuccessfulHCAIdentity(ident, admin);


        HFCAAffiliation aff2 = client.newHFCAAffiliation("org6.dept1");
        aff2.create(admin);

        HFCAIdentity ident2 = client.newHFCAIdentity("testuser_org6.dept1");
        ident2.setAffiliation("org6.dept1");
        createSuccessfulHCAIdentity(ident2, admin);

        HFCAAffiliationResp resp = aff.delete(admin, true);
        int idCount = 0;
        boolean found = false;
        for (HFCAAffiliation childAff : resp.getChildren()) {
            if (childAff.getName().equals("org6.dept1")) {
                found = true;
            }
            for (HFCAIdentity id : childAff.getIdentities()) {
                if (id.getEnrollmentId().equals("testuser_org6.dept1")) {
                    idCount++;
                }
            }
        }

        for (HFCAIdentity id : resp.getIdentities()) {
            if (id.getEnrollmentId().equals("testuser_org6")) {
                idCount++;
            }
        }

        if (!found) {
            fail("Incorrect response received");
        }

        if (idCount != 2) {
            fail("Incorrect number of ids returned");
        }

        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
        assertEquals("Failed to delete affiliation", "org6", aff.getName());

        aff.delete(admin);
    }

    // Tests deleting an affiliation that doesn't require force option
    @Test
    public void testDeleteAffiliationNoForce() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        HFCAAffiliation aff = client.newHFCAAffiliation("org6");
        aff.create(admin);
        HFCAAffiliationResp resp = aff.delete(admin);

        assertEquals("Incorrect status code", new Integer(200), new Integer(resp.getStatusCode()));
        assertEquals("Failed to delete affiliation", "org6", aff.getName());
    }

    // Trying to delete affiliation with child affiliations and identities should result
    // in an error without force option.
    @Test
    public void testForceDeleteAffiliationInvalid() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Authorization failure");

        HFCAAffiliation aff = client.newHFCAAffiliation("org1.dept3");
        aff.create(admin);

        HFCAAffiliation aff2 = client.newHFCAAffiliation("org1.dept3.team1");
        aff2.create(admin);

        HFCAIdentity ident = getIdentityReq("testorg1dept3", "client");
        ident.setAffiliation("org1.dept3");
        createSuccessfulHCAIdentity(ident, admin);

        HFCAAffiliationResp resp = aff.delete(admin);
        assertEquals("Incorrect status code", new Integer(401), new Integer(resp.getStatusCode()));
    }

    // Tests deleting an affiliation on CA that does not allow affiliation removal
    @Test
    public void testDeleteAffiliationNotAllowed() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // needs v1.1
        }

        thrown.expectMessage("Authorization failure");

        HFCAClient client2 = HFCAClient.createNewInstance(
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG2).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG2).getCAProperties());
        client2.setCryptoSuite(crypto);

        // SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface
        SampleUser admin2 = sampleStore.getMember(TEST_ADMIN_NAME, "org2");
        if (!admin2.isEnrolled()) { // Preregistered admin only needs to be enrolled with Fabric CA.
            admin2.setEnrollment(client2.enroll(admin2.getName(), TEST_ADMIN_PW));
        }

        HFCAAffiliation aff = client2.newHFCAAffiliation("org6");
        HFCAAffiliationResp resp = aff.delete(admin2);
        assertEquals("Incorrect status code", new Integer(400), new Integer(resp.getStatusCode()));
    }

    // Tests getting server/ca information
    @Test
    public void testGetInfo() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            HFCAInfo info = client.info();
            assertNull(info.getVersion());
        }

        if (testConfig.isFabricVersionAtOrAfter("1.3")) {
            HFCAInfo info = client.info();
            assertNotNull("client.info returned null.", info);
            String version = info.getVersion();
            assertNotNull("client.info.getVersion returned null.", version);
            assertTrue(format("Version '%s' didn't match expected pattern", version), version.matches("^\\d+\\.\\d+\\.\\d+($|-.*)"));
        }

    }

    // Tests getting certificates
    @Test
    public void testGetCertificates() throws Exception {

        if (testConfig.isRunningAgainstFabric10()) {
            return;
        }

        HFCACertificateRequest certReq = client.newHFCACertificateRequest();

        SampleUser admin2 = sampleStore.getMember("admin2", "org2.department1");
        RegistrationRequest rr = new RegistrationRequest(admin2.getName(), "org2.department1");
        String password = "password";
        rr.setSecret(password);
        rr.addAttribute(new Attribute("hf.Registrar.Roles", "client,peer,user"));

        client.register(rr, admin);
        admin2.setEnrollment(client.enroll(admin2.getName(), password));

        rr = new RegistrationRequest("testUser", "org2.department1");
        rr.setSecret(password);
        client.register(rr, admin);
        Enrollment enroll = client.enroll("testUser", password);

        // Get all certificates that 'admin2' is allowed to see because no attributes are set
        // in the certificate request. This returns 2 certificates, one certificate for the caller
        // itself 'admin2' and the other certificate for 'testuser2'. These are the only two users
        // that fall under the caller's affiliation of 'org2.department1'.
        HFCACertificateResponse resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(2, resp.getCerts().size());
        assertTrue(resultContains(resp.getCerts(), new String[] {"admin", "testUser"}));

        // Get certificate for a specific enrollment id
        certReq.setEnrollmentID("admin2");
        resp = client.getHFCACertificates(admin, certReq);
        assertEquals(1, resp.getCerts().size());
        assertTrue(resultContains(resp.getCerts(), new String[] {"admin"}));

        // Get certificate for a specific serial number
        certReq = client.newHFCACertificateRequest();
        X509Certificate cert = getCert(enroll.getCert().getBytes());
        String serial = cert.getSerialNumber().toString(16);
        certReq.setSerial(serial);
        resp = client.getHFCACertificates(admin, certReq);
        assertEquals(1, resp.getCerts().size());
        assertTrue(resultContains(resp.getCerts(), new String[] {"testUser"}));

        // Get certificate for a specific AKI
        certReq = client.newHFCACertificateRequest();
        String oid = Extension.authorityKeyIdentifier.getId();
        byte[] extensionValue = cert.getExtensionValue(oid);
        ASN1OctetString aki0c = ASN1OctetString.getInstance(extensionValue);
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(aki0c.getOctets());
        String aki2 = DatatypeConverter.printHexBinary(aki.getKeyIdentifier());
        certReq.setAki(aki2);
        resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(2, resp.getCerts().size());

        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");

        // Get certificates that expired before a specific date
        // In this case, using a really old date should return 0 certificates
        certReq = client.newHFCACertificateRequest();
        certReq.setExpiredEnd(formatter.parse("2014-30-31"));
        resp = client.getHFCACertificates(admin, certReq);
        assertEquals(0, resp.getCerts().size());

        // Get certificates that expired before a specific date
        // In this case, using a date far into the future should return all certificates
        certReq = client.newHFCACertificateRequest();
        Calendar cal = Calendar.getInstance();
        Date date = new Date();
        cal.setTime(date);
        cal.add(Calendar.YEAR, 20);
        date = cal.getTime();
        certReq.setExpiredEnd(date);
        resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(2, resp.getCerts().size());
        assertTrue(resultContains(resp.getCerts(), new String[] {"admin2", "testUser"}));

        // Get certificates that expired after specific date
        // In this case, using a really old date should return all certificates that the caller is
        // allowed to see because they all have a future expiration date
        certReq = client.newHFCACertificateRequest();
        certReq.setExpiredStart(formatter.parse("2014-03-31"));
        resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(2, resp.getCerts().size());

        // Get certificates that expired after specified date
        // In this case, using a date far into the future should return zero certificates
        certReq = client.newHFCACertificateRequest();
        certReq.setExpiredStart(date);
        resp = client.getHFCACertificates(admin, certReq);
        assertEquals(0, resp.getCerts().size());

        client.revoke(admin, "testUser", "baduser");

        // Get certificates that were revoked after specific date
        certReq = client.newHFCACertificateRequest();
        certReq.setRevokedStart(formatter.parse("2014-03-31"));
        resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(1, resp.getCerts().size());

        certReq = client.newHFCACertificateRequest();
        certReq.setRevokedEnd(formatter.parse("2014-03-31"));
        resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(0, resp.getCerts().size());

        certReq = client.newHFCACertificateRequest();
        certReq.setRevoked(false);
        resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(1, resp.getCerts().size());
        assertTrue(resultContains(resp.getCerts(), new String[] {"admin2"}));
        assertFalse(resultContains(resp.getCerts(), new String[] {"testUser"}));

        certReq = client.newHFCACertificateRequest();
        certReq.setRevoked(true);
        resp = client.getHFCACertificates(admin2, certReq);
        assertTrue(resultContains(resp.getCerts(), new String[] {"admin2", "testUser"}));
        assertEquals(2, resp.getCerts().size());

        certReq = client.newHFCACertificateRequest();
        certReq.setExpired(false);
        resp = client.getHFCACertificates(admin2, certReq);
        assertEquals(2, resp.getCerts().size());
    }

    private boolean resultContains(Collection<HFCACredential> creds, String[] names) {
        int numFound = 0;
        for (HFCACredential cred : creds) {
            for (int i = 0; i < names.length; i++) {
                HFCAX509Certificate cert = (HFCAX509Certificate) cred;
                if (cert.getX509().getSubjectDN().toString().contains(names[i])) {
                    numFound++;
                    break;
                }
            }
        }
        if (numFound == names.length) {
            return true;
        }
        return false;
    }

    private X509Certificate getCert(byte[] certBytes) throws CertificateException {
        BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certBytes));
        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);
        return certificate;
    }

    @Test
    public void testEnrollNoKeyPair() throws Exception {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("Failed to enroll user");

        SampleUser user = getEnrolledUser(TEST_ADMIN_ORG);

        EnrollmentRequest req = new EnrollmentRequest(DEFAULT_PROFILE_NAME, "label 1", null);
        req.setCsr("test");
        client.enroll(user.getName(), user.getEnrollmentSecret(), req);
    }

    @Test
    public void testRevokeNotAuthorized() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("Error while revoking the user");

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

        // This client does not exist
        String clientName = "test CA client";

        HFCAClient clientWithName = HFCAClient.createNewInstance(clientName,
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCALocation(),
                testConfig.getIntegrationTestsSampleOrg(TEST_WITH_INTEGRATION_ORG).getCAProperties());
        clientWithName.setCryptoSuite(cryptoSuite);

        clientWithName.enroll(admin.getName(), TEST_ADMIN_PW);
    }

    // Tests getting an Idemix credential using an x509 enrollment credential
    @Test
    public void testGetIdemixCred() throws Exception {
        if (testConfig.isFabricVersionBefore("1.3")) {
            return; // needs v1.3
        }

        SampleUser user = getTestUser(TEST_ADMIN_ORG);
        RegistrationRequest rr = new RegistrationRequest(user.getName(), TEST_USER1_AFFILIATION);
        String password = "password";
        rr.setSecret(password);
        user.setEnrollmentSecret(client.register(rr, admin));
        user.setEnrollment(client.enroll(user.getName(), user.getEnrollmentSecret()));

        Enrollment enrollment = client.idemixEnroll(user.getEnrollment(), "idemixMsp");
        assertNotNull(enrollment);
        assertTrue(enrollment instanceof IdemixEnrollment);
    }

    // revoke2: revoke(User revoker, String revokee, String reason)
    @Test
    public void testRevoke2UnknownUser() throws Exception {

        thrown.expect(RevocationException.class);
        thrown.expectMessage("Error while revoking");

        client.revoke(admin, "unknownUser", "remove user2");
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
        out("That's all folks!");
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
                int type = (Integer) item.get(0);
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

    private HFCAIdentity getIdentityReq(String enrollmentID, String type) throws InvalidArgumentException {
        String password = "password";

        HFCAIdentity ident = client.newHFCAIdentity(enrollmentID);
        ident.setSecret(password);
        ident.setAffiliation(TEST_USER1_AFFILIATION);
        ident.setMaxEnrollments(1);
        ident.setType(type);

        Collection<Attribute> attributes = new ArrayList<Attribute>();
        attributes.add(new Attribute("testattr1", "valueattr1"));
        ident.setAttributes(attributes);
        return ident;
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
