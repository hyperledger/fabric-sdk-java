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

import java.security.PrivateKey;

// The base Certificate class
public class Certificate {
    private byte[] cert;
    private PrivateKey privateKey;
    private PrivacyLevel privLevel;

    public Certificate(byte[] cert,
                PrivateKey privateKey,
                /** Denoting if the Certificate is anonymous or carrying its owner's identity. */
                PrivacyLevel privLevel) {
        this.cert = cert;
        this.privateKey = privateKey;
        this.privLevel = privLevel;
    }

    public byte[] getCert() {
        return this.cert;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
