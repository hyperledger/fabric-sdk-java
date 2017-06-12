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

public class RegistrationRequestTest {
    private static final String attrName = "some name";
    private static final String attrValue = "some value";
    private static final String regAffiliation = "corporation";
    private static final String regCAName = "CA";
    private static final String regID = "userid";
    private static final String regSecret = "secret";
    private static final String regType = "user";

    private static final int regMaxEnrollments = 5;

    @Test
    public void testNewInstance() {

        try {
            RegistrationRequest testRegisterReq = new RegistrationRequest(regID, regAffiliation);
            Assert.assertEquals(testRegisterReq.getEnrollmentID(), regID);
            Assert.assertEquals(testRegisterReq.getType(), regType);
            Assert.assertEquals(testRegisterReq.getMaxEnrollments(), 0);
            Assert.assertEquals(testRegisterReq.getAffiliation(), regAffiliation);
            Assert.assertTrue(testRegisterReq.getAttributes().isEmpty());

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testNewInstanceSetNullID() {

        try {
            new RegistrationRequest(null, regAffiliation);
            Assert.fail("Expected exception when null is specified for id");

        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "id may not be null");
        }
    }

    @Test
    public void testNewInstanceSetNullAffiliation() {

        try {
            new RegistrationRequest(regID, null);
            Assert.fail("Expected exception when null is specified for affiliation");

        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "affiliation may not be null");
        }
    }

    @Test
    public void testRegisterReqSetGet() {

        try {
            RegistrationRequest testRegisterReq = new RegistrationRequest(regID, regAffiliation);
            testRegisterReq.setEnrollmentID(regID + "update");
            testRegisterReq.setSecret(regSecret);
            testRegisterReq.setMaxEnrollments(regMaxEnrollments);
            testRegisterReq.setType(regType);
            testRegisterReq.setAffiliation(regAffiliation + "update");
            testRegisterReq.setCAName(regCAName);
            testRegisterReq.addAttribute(new Attribute(attrName, attrValue));
            Assert.assertEquals(testRegisterReq.getEnrollmentID(), regID + "update");
            Assert.assertEquals(testRegisterReq.getSecret(), regSecret);
            Assert.assertEquals(testRegisterReq.getType(), regType);
            Assert.assertEquals(testRegisterReq.getAffiliation(), regAffiliation + "update");
            Assert.assertTrue(!testRegisterReq.getAttributes().isEmpty());

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testRegisterReqToJson() {

        try {
            RegistrationRequest testRegisterReq = new RegistrationRequest(regID, regAffiliation);
            testRegisterReq.setEnrollmentID(regID + "update");
            testRegisterReq.setSecret(regSecret);
            testRegisterReq.setMaxEnrollments(regMaxEnrollments);
            testRegisterReq.setType(regType);
            testRegisterReq.setAffiliation(regAffiliation + "update");
            testRegisterReq.setCAName(regCAName);
            testRegisterReq.addAttribute(new Attribute(attrName, attrValue));

            Assert.assertTrue(testRegisterReq.toJson().contains(regAffiliation + "update"));

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
}