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

import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.FP256BN.FP12;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.hyperledger.fabric.protos.idemix.Idemix;

class PlainSignRevocationVerifier implements RevocationVerifier {

    @Override
    public byte[] recomputeFSContribution(Idemix.NonRevocationProof proof, BIG chal, ECP2 epochPK, BIG proofSRh) {
        Idemix.PlainSigNonRevokedProof proofUnmarshaled = null;
        try {
            proofUnmarshaled = Idemix.PlainSigNonRevokedProof.parseFrom(proof.getNonRevocationProof());
        } catch (InvalidProtocolBufferException e) {
            throw new Error("Failed to unmarshal non-revoked proof");
        }

        ECP sigBar = IdemixUtils.transformFromProto(proofUnmarshaled.getSigmaBar());
        ECP sigPrime = IdemixUtils.transformFromProto(proofUnmarshaled.getSigmaPrime());

        if (sigPrime.is_infinity()) {
            // Nonrevoked proof is invalid, sigPrime = 1
            throw new Error("Invalid non-revoked proof");
        }

        // Check whether sigBar and sigPrime have the right structure
        ECP miniSigPrime = new ECP();
        miniSigPrime.sub(sigPrime);

        FP12 result = PAIR.fexp(PAIR.ate2(epochPK, miniSigPrime, IdemixUtils.genG2, sigBar));
        if (!result.isunity()) {
            // Sigmabar and SigmaPrime do not have the expected structure
            throw new Error("SigmaBar and SigmaPrime do not have the expected structure");
        }

        // Verify ZK proof

        // Recover t-value. Recall t = \sigma'^-rRh \ cdot g1^rRandSig
        ECP t = sigPrime.mul2(BIG.modneg(proofSRh, IdemixUtils.GROUP_ORDER), IdemixUtils.genG1, BIG.fromBytes(proofUnmarshaled.getProofSR().toByteArray()));
        t.sub(sigBar.mul(chal));
//        System.out.printf("Verifier t : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(t)));
//        System.out.printf("Prover sigBar : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(sigBar)));
//        System.out.printf("Prover sigPrime : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(sigPrime)));
//        System.out.printf("Prover EpochPk : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(epochPK)));
//        System.out.printf("Prover t : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(t)));

        // Recompute the contribution.
        // fsBytes will hold three elements of G1, each taking 2*FieldBytes+1 bytes,
        // and one element of G2, which takes 4*FieldBytes
        byte[] fsBytes = new byte[0];
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(sigBar));
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(sigPrime));
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(epochPK));
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(t));

        return fsBytes;
    }
}
