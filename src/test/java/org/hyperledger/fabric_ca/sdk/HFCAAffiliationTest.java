/*
 *  Copyright 2016, 2017, 2018 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.exception.AffiliationException;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class HFCAAffiliationTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final String TEST_ADMIN_NAME = "admin";
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
            throw new RuntimeException("HFCAAffiliationTest.setupBeforeClass failed!", e);
        }
    }

    @Before
    public void setup() throws Exception {

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
    public void testHFCAIdentityNewInstance() throws Exception {

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);
        HFCAAffiliation aff = client.newHFCAAffiliation("org1");

        Assert.assertNotNull(aff);
        Assert.assertSame(HFCAAffiliation.class, aff.getClass());
    }

    @Test
    public void testHFCAIdentityCryptoNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Crypto primitives not set");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(null);
        client.newHFCAAffiliation("org1");
    }

    @Test
    public void testHFCAIdentityIDNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Affiliation name cannot be null or empty");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.newHFCAAffiliation(null);
    }

    @Test
    public void testBadAffiliationNameSpace() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Affiliation name cannot contain an empty space or tab");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.newHFCAAffiliation("foo. .bar");
    }

    @Test
    public void testBadAffiliationNameStartingDot() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Affiliation name cannot start with a dot '.'");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.newHFCAAffiliation(".foo");
    }

    @Test
    public void testBadAffiliationNameEndingDot() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Affiliation name cannot end with a dot '.'");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.newHFCAAffiliation("foo.");
    }

    @Test
    public void testBadAffiliationNameMultipleDots() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Affiliation name cannot contain multiple consecutive dots '.'");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.newHFCAAffiliation("foo...bar");
    }

    @Test
    public void getAffiliationNoServerResponse() throws Exception {

        thrown.expect(AffiliationException.class);
        thrown.expectMessage("Error while getting affiliation");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAAffiliation aff = client.newHFCAAffiliation("neworg1");
        aff.read(admin);
    }

    @Test
    public void createAffiliationNoServerResponse() throws Exception {

        thrown.expect(AffiliationException.class);
        thrown.expectMessage("Error while creating affiliation");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAAffiliation aff = client.newHFCAAffiliation("neworg1");
        aff.create(admin);
    }

    @Test
    public void updateAffiliationNoServerResponse() throws Exception {

        thrown.expect(AffiliationException.class);
        thrown.expectMessage("Error while updating affiliation");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAAffiliation aff = client.newHFCAAffiliation("neworg1");
        aff.setUpdateName("neworg1");
        aff.update(admin);
    }

    @Test
    public void deleteAffiliationNoServerResponse() throws Exception {

        thrown.expect(AffiliationException.class);
        thrown.expectMessage("Error while deleting affiliation");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCAAffiliation aff = client.newHFCAAffiliation("neworg1");
        aff.delete(admin);
    }
}
