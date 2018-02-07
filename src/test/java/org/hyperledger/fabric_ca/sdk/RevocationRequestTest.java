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

import org.junit.Assert;
import org.junit.Test;

public class RevocationRequestTest {
    private static final String revCAName = "CA";
    private static final String revEnrollmentID = "userid";
    private static final String revSerialNmbr = "987654321";
    private static final String revAKI = "123456789";
    private static final String revReason = "compromised";
    private static final Boolean revGenCRL = true;

    @Test
    public void testNewInstance() {

        try {
            RevocationRequest testRevocationReq = new RevocationRequest(revCAName, revEnrollmentID, revSerialNmbr,
                    revAKI, revReason, revGenCRL);
            Assert.assertEquals(testRevocationReq.getUser(), revEnrollmentID);
            Assert.assertEquals(testRevocationReq.getSerial(), revSerialNmbr);
            Assert.assertEquals(testRevocationReq.getAki(), revAKI);
            Assert.assertEquals(testRevocationReq.getReason(), revReason);
            Assert.assertEquals(testRevocationReq.getGenCRL(), revGenCRL);

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testNewInstanceSetNullIDSerialNmbr() {

        try {
            new RevocationRequest(revCAName, null, null, revAKI, revReason);
            Assert.fail("Expected exception when null is specified for serial number");

        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(),
                    "Enrollment ID is empty, thus both aki and serial must have non-empty values");
        }
    }

    @Test
    public void testNewInstanceSetNullIDAKI() {

        try {
            new RevocationRequest(revCAName, null, revSerialNmbr, null, revReason);
            Assert.fail("Expected exception when null is specified for AKI");

        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(),
                    "Enrollment ID is empty, thus both aki and serial must have non-empty values");
        }
    }

    @Test
    public void testRevocationReqSetGet() {

        try {
            RevocationRequest testRevocationReq = new RevocationRequest(revCAName, revEnrollmentID, revSerialNmbr,
                    revAKI, revReason);
            testRevocationReq.setUser(revEnrollmentID + "update");
            testRevocationReq.setSerial(revSerialNmbr + "000");
            testRevocationReq.setAki(revAKI + "000");
            testRevocationReq.setReason(revReason + "update");
            Assert.assertEquals(testRevocationReq.getUser(), revEnrollmentID + "update");
            Assert.assertEquals(testRevocationReq.getSerial(), revSerialNmbr + "000");
            Assert.assertEquals(testRevocationReq.getAki(), revAKI + "000");
            Assert.assertEquals(testRevocationReq.getReason(), revReason + "update");

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testRevocationReqToJsonNullID() {

        try {
            RevocationRequest testRevocationReq = new RevocationRequest(revCAName, null, revSerialNmbr, revAKI,
                    revReason);
            testRevocationReq.setSerial(revSerialNmbr);
            testRevocationReq.setAki(revAKI + "000");
            testRevocationReq.setReason(revReason + "update");

            Assert.assertTrue(testRevocationReq.toJson().contains(revSerialNmbr));

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testRevocationReqToJson() {

        try {
            RevocationRequest testRevocationReq = new RevocationRequest(revCAName, revEnrollmentID, revSerialNmbr,
                    revAKI, revReason);
            testRevocationReq.setUser(revEnrollmentID + "update");
            testRevocationReq.setSerial(revSerialNmbr + "000");
            testRevocationReq.setAki(revAKI + "000");
            testRevocationReq.setReason(revReason + "update");

            Assert.assertTrue(testRevocationReq.toJson().contains(revReason + "update"));

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
}