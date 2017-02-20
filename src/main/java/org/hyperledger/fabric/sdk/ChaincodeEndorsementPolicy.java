/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

/**
 * A wrapper for the Hyperledger Fabric Policy object
 *
 */
public class ChaincodeEndorsementPolicy {
    private byte[] policyBytes = null;

    /**
     * The null constructor for the ChaincodeEndorsementPolicy wrapper. You will
     * need to use the {@link #setChaincodeEndorsementPolicy(byte[])} method to
     * populate the policy
     *
     */
    public ChaincodeEndorsementPolicy() {
    }

    /**
     * constructs a ChaincodeEndorsementPolicy object with the actual policy gotten from the file system
     * @param policyFile The file containing the policy
     * @throws IOException
     */
    public ChaincodeEndorsementPolicy(File policyFile) throws IOException {
        InputStream is = new FileInputStream(policyFile) ;
        this.policyBytes = IOUtils.toByteArray(is);
    }

    /**
     * constructs a ChaincodeEndorsementPolicy object
     * @param policyAsBytes the byte array containing the serialized policy
     */
    public ChaincodeEndorsementPolicy(byte[] policyAsBytes) {
        this.policyBytes = policyAsBytes;
    }

    /**
     * sets the ChaincodeEndorsementPolicy from a byte array
     * @param policyAsBytes the byte array containing the serialized policy
     */
    public void setChaincodeEndorsementPolicy(byte[] policyAsBytes) {
        this.policyBytes = policyAsBytes;
    }

    /**
     * @return the policy serialized per protobuf and ready for inclusion into the various Block/Envelope/ChaincodeInputSpec structures
     */
    public byte[] getChaincodeEndorsementPolicyAsBytes() {
        return this.policyBytes;
    }
}
