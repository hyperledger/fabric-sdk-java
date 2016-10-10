/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
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
/**
 * A transaction.
 */
public interface TransactionProtobuf {
    String getType();
    void setCert(byte[] cert);
    void setSignature(byte[] sig);
    void setConfidentialityLevel(int value);
    int  getConfidentialityLevel();
    void setConfidentialityProtocolVersion(String version);
    void setNonce(byte[] nonce);
    void setToValidators(byte[] buffer);
    byte[] getChaincodeID();
    void setChaincodeID(byte[] buffer);
    byte[] getMetadata();
    void setMetadata(byte[] buffer);
    byte[] getPayload();
    void setPayload(byte[] buffer);
    byte[] toByteArray();
}
