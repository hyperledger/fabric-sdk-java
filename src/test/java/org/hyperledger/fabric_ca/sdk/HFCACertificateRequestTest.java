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
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.HFCACertificateException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class HFCACertificateRequestTest {

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
    public void testHFCACertificateNewInstance() throws Exception {
        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);
        HFCACertificateRequest certReq = client.newHFCACertificateRequest();

        Assert.assertNotNull(certReq);
        Assert.assertSame(HFCACertificateRequest.class, certReq.getClass());
    }


    @Test
    public void testInvalidRevokedStartDate() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Date can't be null");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);
        HFCACertificateRequest certReq = client.newHFCACertificateRequest();

        certReq.setRevokedStart(null);
    }

    @Test
    public void testInvalidRevokedEndDate() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Date can't be null");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);
        HFCACertificateRequest certReq = client.newHFCACertificateRequest();

        certReq.setRevokedEnd(null);
    }

    @Test
    public void testInvalidExpiredStartDate() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Date can't be null");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);
        HFCACertificateRequest certReq = client.newHFCACertificateRequest();

        certReq.setExpiredStart(null);
    }

    @Test
    public void testInvalidExpiredEndDate() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Date can't be null");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);
        HFCACertificateRequest certReq = client.newHFCACertificateRequest();

        certReq.setExpiredEnd(null);
    }

    @Test
    public void getCertificateNoServerResponse() throws Exception {
        thrown.expect(HFCACertificateException.class);
        thrown.expectMessage("Error while getting certificates");

        HFCAClient client = HFCAClient.createNewInstance("http://localhost:99", null);
        client.setCryptoSuite(crypto);

        HFCACertificateRequest certReq = client.newHFCACertificateRequest();
        client.getHFCACertificates(admin, certReq);
    }
}
