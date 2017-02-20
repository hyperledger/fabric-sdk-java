/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
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

package org.hyperledger.fabric.sdk;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.apache.commons.compress.utils.IOUtils;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChaincodeEndorsementPolicyTest {

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#ChaincodeEndorsementPolicy()}.
     */
    @Test
    public void testPolicyCtor() {
        ChaincodeEndorsementPolicy nullPolicy = new ChaincodeEndorsementPolicy();
        assertNull(nullPolicy.getChaincodeEndorsementPolicyAsBytes()) ;
    }

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#ChaincodeEndorsementPolicy(java.io.File)}.
     * @throws IOException
     */
    @Test(expected=IOException.class)
    public void testPolicyCtorFile() throws IOException {
        ChaincodeEndorsementPolicy policy = new ChaincodeEndorsementPolicy(new File("/does/not/exists"));
    }

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#ChaincodeEndorsementPolicy(java.io.File)}.
     * @throws IOException
     */
    @Test
    public void testPolicyCtorValidFile() throws IOException {
        URL url = this.getClass().getResource("/policyBitsAdmin");
        File policyFile = new File(url.getFile());
        ChaincodeEndorsementPolicy policy = new ChaincodeEndorsementPolicy(policyFile);
        InputStream policyStream = this.getClass().getResourceAsStream("/policyBitsAdmin");
        byte[] policyBits = IOUtils.toByteArray(policyStream);
        assertArrayEquals(policyBits, policy.getChaincodeEndorsementPolicyAsBytes());
        }

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#ChaincodeEndorsementPolicy(byte[])}.
     */
    @Test
    public void testPolicyCtorByteArray() {
        byte[] testInput = "this is a test".getBytes();
        ChaincodeEndorsementPolicy fakePolicy = new ChaincodeEndorsementPolicy(testInput) ;
        assertEquals(fakePolicy.getChaincodeEndorsementPolicyAsBytes(), testInput);
    }

    /**
     * Test method for {@link org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy#setChaincodeEndorsementPolicy(byte[])}.
     */
    @Test
    public void testSetPolicy() {
        byte[] testInput = "this is a test".getBytes();
        ChaincodeEndorsementPolicy fakePolicy = new ChaincodeEndorsementPolicy() ;
        fakePolicy.setChaincodeEndorsementPolicy(testInput);
        assertEquals(fakePolicy.getChaincodeEndorsementPolicyAsBytes(), testInput);
    }

}
