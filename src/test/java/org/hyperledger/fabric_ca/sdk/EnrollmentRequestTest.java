/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
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

package org.hyperledger.fabric_ca.sdk;

import java.security.KeyPair;
import org.junit.Assert;
import org.junit.Test;

public class EnrollmentRequestTest {
    private static final String caName = "certsInc";
    private static final String csr = "11436845810603";
    private static final String profile = "test profile";
    private static final String label = "test label";
    private static final KeyPair keyPair = null;

    @Test
    public void testNewInstanceEmpty() {

        try {
            EnrollmentRequest testEnrollReq = new EnrollmentRequest();
            Assert.assertNull(testEnrollReq.getCsr());
            Assert.assertTrue(testEnrollReq.getHosts().isEmpty());
            Assert.assertNull(testEnrollReq.getProfile());
            Assert.assertNull(testEnrollReq.getLabel());
            Assert.assertNull(testEnrollReq.getKeyPair());

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testNewInstanceParms() {

        try {
            EnrollmentRequest testEnrollReq = new EnrollmentRequest(profile, label, keyPair);
            Assert.assertNull(testEnrollReq.getCsr());
            Assert.assertTrue(testEnrollReq.getHosts().isEmpty());
            Assert.assertEquals(testEnrollReq.getProfile(), profile);
            Assert.assertEquals(testEnrollReq.getLabel(), label);
            Assert.assertNull(testEnrollReq.getKeyPair());

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testEnrollReqSetGet() {

        try {
            EnrollmentRequest testEnrollReq = new EnrollmentRequest();
            testEnrollReq.addHost("d.com");
            testEnrollReq.setCsr(csr);
            testEnrollReq.setCSR(csr); // Unsure why there are two methods that
                                       // set csr
            testEnrollReq.setProfile(profile);
            testEnrollReq.setLabel(label);
            testEnrollReq.setKeyPair(null);
            testEnrollReq.setCAName(caName);
            Assert.assertEquals(testEnrollReq.getCsr(), csr);
            Assert.assertTrue(testEnrollReq.getHosts().contains("d.com"));
            Assert.assertEquals(testEnrollReq.getProfile(), profile);
            Assert.assertEquals(testEnrollReq.getLabel(), label);
            Assert.assertNull(testEnrollReq.getKeyPair());

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testEnrollReqToJson() {

        try {
            EnrollmentRequest testEnrollReq = new EnrollmentRequest();
            testEnrollReq.addHost("d.com");
            testEnrollReq.setCsr(csr);
            testEnrollReq.setCSR(csr); // Two setters perform the same function
            testEnrollReq.setProfile(profile);
            testEnrollReq.setLabel(label);
            testEnrollReq.setKeyPair(null);
            testEnrollReq.setCAName(caName);

            Assert.assertTrue(testEnrollReq.toJson().contains(csr));

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
}