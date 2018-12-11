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

import java.util.Arrays;
import java.util.Iterator;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;


class PlainSigRevocationProver implements RevocationProver {
    private BIG rh;         // revocation handle
    private BIG rRh;        // r-value used in proving knowledge of rh
    private ECP sig;        // signature on rh
    private BIG randSig;    // randomness used to randomize sig
    private BIG rRandSig;   // r-value used in proving knowledge of randSig
    private ECP sigPrime;   // sig^randSig
    private ECP sigBar;    // sigPrime^-rh * genG1^randSig

    @Override
    public byte[] getFSContribution(BIG rh, BIG rRh, Idemix.CredentialRevocationInformation cri) {
        if (cri.getRevocationAlg() != RevocationAlgorithm.ALG_PLAIN_SIGNATURE.ordinal()) {
            throw new Error("The Revocation Credential is not for Plain Signature");
        }

        RAND rng = IdemixUtils.getRand();
        Idemix.PlainSigRevocationData revocationData = null;

        try {
            revocationData = Idemix.PlainSigRevocationData.parseFrom(cri.getRevocationData());
        } catch (InvalidProtocolBufferException e) {
            // Failed to unmarshal revocation data
            throw new Error("Failed to unmarshal revocation data");
        }

        this.rh = rh;
        this.rRh = rRh;
        byte[] rhBytes = IdemixUtils.bigToBytes(rh);

        // Iterate through the messages
        // While messages in the revocation data or until signature != null
        Iterator iterator = revocationData.getSignaturesList().iterator();
        while (iterator.hasNext() && this.sig == null) {
            Idemix.MessageSignature msg = (Idemix.MessageSignature) iterator.next();
            if (Arrays.equals(rhBytes, msg.getRevocationHandle().toByteArray())) {
                this.sig = IdemixUtils.transformFromProto(msg.getRhSignature());
            }
        }

        if (this.sig == null) {
            // No signature for the revocation handle found in the cri.
            throw new Error("No signature found for the revocation handle in the revocation credential");
        }

        // Prove knowledge of \sigma with the ZKP from Camenisch-Drijvers-Hajny: "Scalable Revocation Scheme
        // for Anonymous Credentials Based on n-times Unlinkable Proofs"
        this.randSig = IdemixUtils.randModOrder(rng);
        this.sigPrime = this.sig.mul(this.randSig);
        // \bar\sigma = \sigma'^-rh \cdot g1^randSig
        this.sigBar = this.sigPrime.mul2(BIG.modneg(this.rh, IdemixUtils.GROUP_ORDER), IdemixUtils.genG1, this.randSig);
        this.rRandSig = IdemixUtils.randModOrder(rng);

        // Step 1: First message (t-values)

        // t = \sigma'^-rRh \ cdot g1^rRandSig
        ECP t = this.sigPrime.mul2(BIG.modneg(this.rRh, IdemixUtils.GROUP_ORDER), IdemixUtils.genG1, this.rRandSig);

        // Step 2: Compute the Fiat-Shamir contribution, forming the challenge of the ZKP.
        // fsContribution will hold three elements of G1, each taking 2*FieldBytes+1 bytes,
        // and one element of G2, which takes 4*FieldBytes.
        // Notice that Step 3 is executed in the getNonRevokedProof function
        byte[] fsBytes = new byte[0];
//        System.out.printf("Prover sigBar : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(this.sigBar)));
//        System.out.printf("Prover sigPrime : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(this.sigPrime)));
//        System.out.printf("Prover EpochPk : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(IdemixUtils.transformFromProto(cri.getEpochPk()))));
//        System.out.printf("Prover t : %s\n", Arrays.toString(IdemixUtils.ecpToBytes(t)));
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(this.sigBar));
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(this.sigPrime));
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(IdemixUtils.transformFromProto(cri.getEpochPk())));
        fsBytes = IdemixUtils.append(fsBytes, IdemixUtils.ecpToBytes(t));

        return fsBytes;
    }

    @Override
    public Idemix.NonRevocationProof getNonRevocationProof(BIG challenge) {
        Idemix.NonRevocationProof.Builder retBuilder = Idemix.NonRevocationProof.newBuilder();
        retBuilder.setRevocationAlg(RevocationAlgorithm.ALG_PLAIN_SIGNATURE.ordinal());

        Idemix.PlainSigNonRevokedProof.Builder proofBuilder = Idemix.PlainSigNonRevokedProof.newBuilder();

        // Step 3: reply to the challenge message (s-values)

        // s_r = rRandSig + C \cdot randSig
        BIG proofSR = IdemixUtils.modAdd(this.rRandSig, BIG.modmul(this.randSig, challenge, IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER);

        // marshall proof
        proofBuilder.setProofSR(ByteString.copyFrom(IdemixUtils.bigToBytes(proofSR)));
        proofBuilder.setSigmaBar(IdemixUtils.transformToProto(this.sigBar));
        proofBuilder.setSigmaPrime(IdemixUtils.transformToProto(this.sigPrime));

        retBuilder.setNonRevocationProof(proofBuilder.build().toByteString());
        return retBuilder.build();
    }

}
