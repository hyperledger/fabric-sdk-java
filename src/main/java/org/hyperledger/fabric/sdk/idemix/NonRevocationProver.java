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
 * A NonRevocationProver is a prover that can prove that an identity mixer credential is not revoked.
 * For every RevocationAlgorithm, there will be an instantiation of NonRevocationProver.
 */
interface NonRevocationProver {

    /**
     * This method provides a concrete non-revocation for a given Revocation algorithm
     *
     * @param algorithm Revocation mechanism to use
     * @return A concrete NonRevocationProver for the given revocation mechanism
     */
    static NonRevocationProver getNonRevocationProver(RevocationAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Revocation algorithm cannot be null");
        }
        switch (algorithm) {
            case ALG_NO_REVOCATION:
                return new NopNonRevocationProver();
            default:
                // Revocation algorithm not supported
                throw new IllegalArgumentException("Revocation algorithm " + algorithm.name() + " not supported");
        }
    }

    /**
     * getFSContribution performs the first round of a two-round zero-knowledge proof,
     * proving that a credential with some revocation handle is not revoked.
     *
     * @param rh  Revocation handle
     * @param rRh r-value used in proving knowledge of rh
     * @param cri Credential revocation information
     * @return proof
     */
    byte[] getFSContribution(BIG rh, BIG rRh, Idemix.CredentialRevocationInformation cri);

    /**
     * getNonRevocationProof performs the second round of a two-round zero-knowledge proof,
     * proving that a credential with some revocation handle is not revoked.
     *
     * @param challenge Fiat-Shamir challenge of the zero-knowledge proof
     * @return proof
     */
    Idemix.NonRevocationProof getNonRevocationProof(BIG challenge);

}