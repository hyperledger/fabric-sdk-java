/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.List;

import org.apache.commons.compress.utils.IOUtils;
import org.hyperledger.fabric.protos.common.MspPrincipal;
import org.hyperledger.fabric.protos.common.MspPrincipal.MSPPrincipal;
import org.hyperledger.fabric.protos.common.Policies;
import org.hyperledger.fabric.protos.common.Policies.SignaturePolicy.TypeCase;
import org.hyperledger.fabric.protos.common.Policies.SignaturePolicyEnvelope;
import org.hyperledger.fabric.sdk.exception.ChaincodeEndorsementPolicyParseException;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ChaincodeEndorsementPolicyTest {

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#ChaincodeEndorsementPolicy()}.
     */
    @Test
    public void testPolicyCtor() {
        ChaincodeEndorsementPolicy nullPolicy = new ChaincodeEndorsementPolicy();
        assertNull(nullPolicy.getChaincodeEndorsementPolicyAsBytes());
    }

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#fromFile(File)} (java.io.File)}.
     *
     * @throws IOException
     */
    @Test(expected = IOException.class)
    public void testPolicyCtorFile() throws IOException {
        ChaincodeEndorsementPolicy policy = new ChaincodeEndorsementPolicy();
        policy.fromFile(new File("/does/not/exists"));
    }

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#fromFile(File)} (java.io.File)}.
     *
     * @throws IOException
     */
    @Test
    public void testPolicyCtorValidFile() throws IOException {
        URL url = this.getClass().getResource("/policyBitsAdmin");
        File policyFile = new File(url.getFile());
        ChaincodeEndorsementPolicy policy = new ChaincodeEndorsementPolicy();
        policy.fromFile(policyFile);
        InputStream policyStream = this.getClass().getResourceAsStream("/policyBitsAdmin");
        byte[] policyBits = IOUtils.toByteArray(policyStream);
        assertArrayEquals(policyBits, policy.getChaincodeEndorsementPolicyAsBytes());
    }

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#fromBytes(byte[])}.
     */
    @Test
    public void testPolicyCtorByteArray() {
        byte[] testInput = "this is a test".getBytes(UTF_8);
        ChaincodeEndorsementPolicy fakePolicy = new ChaincodeEndorsementPolicy();
        fakePolicy.fromBytes(testInput);

        assertEquals(fakePolicy.getChaincodeEndorsementPolicyAsBytes(), testInput);
    }

    /**
     * Test method for {@link ChaincodeEndorsementPolicy#fromYamlFile(File)}
     * @throws IOException
     * @throws ChaincodeEndorsementPolicyParseException
     */
    @Test
    public void testSDKIntegrationYaml() throws IOException, ChaincodeEndorsementPolicyParseException {

        ChaincodeEndorsementPolicy itTestPolicy = new ChaincodeEndorsementPolicy();
        itTestPolicy.fromYamlFile(new File("src/test/fixture/sdkintegration/chaincodeendorsementpolicy.yaml"));

        SignaturePolicyEnvelope sigPolEnv = SignaturePolicyEnvelope.parseFrom(itTestPolicy.getChaincodeEndorsementPolicyAsBytes());
        List<MSPPrincipal> identitiesList = sigPolEnv.getIdentitiesList();
        for (MSPPrincipal ident : identitiesList) {

            MSPPrincipal mspPrincipal = MSPPrincipal.parseFrom(ident.getPrincipal());
            MSPPrincipal.Classification principalClassification = mspPrincipal.getPrincipalClassification();
            assertEquals(principalClassification.toString(), MSPPrincipal.Classification.ROLE.name());
            MspPrincipal.MSPRole mspRole = MspPrincipal.MSPRole.parseFrom(ident.getPrincipal());

            String iden = mspRole.getMspIdentifier();
            assertTrue("Org1MSP".equals(iden) || "Org2MSP".equals(iden));
            assertTrue(mspRole.getRole().getNumber() == MspPrincipal.MSPRole.MSPRoleType.ADMIN_VALUE
                    || mspRole.getRole().getNumber() == MspPrincipal.MSPRole.MSPRoleType.MEMBER_VALUE);

        }

        Policies.SignaturePolicy rule = sigPolEnv.getRule();
        TypeCase typeCase = rule.getTypeCase();
        assertEquals(TypeCase.N_OUT_OF.getNumber(), typeCase.getNumber());
    }

    @Test
    public void testBadYaml() throws IOException, ChaincodeEndorsementPolicyParseException {

        try {
            ChaincodeEndorsementPolicy itTestPolicy = new ChaincodeEndorsementPolicy();
            itTestPolicy.fromYamlFile(new File("src/test/fixture/sample_chaincode_endorsement_policies/badusertestCCEPPolicy.yaml"));

            fail("Expected ChaincodeEndorsementPolicyParseException");

        } catch (ChaincodeEndorsementPolicyParseException e) {

        } catch (Exception e) {

            fail("Expected ChaincodeEndorsementPolicyParseException");
        }

    }

    //src/test/fixture/sample_chaincode_endorsement_policies/badusertestCCEPPolicy.yaml

//    /**
//     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#fromBytes(byte[])}.
//     */
//    @Test
//    public void testSetPolicy() {
//        byte[] testInput = "this is a test".getBytes(UTF_8);
//        ChaincodeEndorsementPolicy fakePolicy = new ChaincodeEndorsementPolicy() ;
//        fakePolicy.fromBytes(testInput);
//        assertEquals(fakePolicy.getChaincodeEndorsementPolicyAsBytes(), testInput);
//    }

}
