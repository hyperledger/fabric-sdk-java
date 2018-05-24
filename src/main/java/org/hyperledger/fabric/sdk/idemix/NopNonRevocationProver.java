/*
 *
 *  Copyright 2017, 2018 IBM Corp. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.hyperledger.fabric.sdk.idemix;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * NopNonRevocationProver is a concrete NonRevocationProver for RevocationAlgorithm "ALG_NO_REVOCATION"
 */
class NopNonRevocationProver implements NonRevocationProver {
    private final byte[] empty = new byte[0];

    public byte[] getFSContribution(BIG rh, BIG rRh, Idemix.CredentialRevocationInformation cri) {
        return empty;
    }

    public Idemix.NonRevocationProof getNonRevocationProof(BIG challenge) {
        return Idemix.NonRevocationProof.newBuilder()
                .setRevocationAlg(RevocationAlgorithm.ALG_NO_REVOCATION.ordinal())
                .build();
    }
}