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

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.common.primitives.Ints;
import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.FP12;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.sdk.exception.CryptoException;

/**
 * IdemixSignature represents an idemix signature, which is a zero knowledge proof
 * of knowledge of a BBS+ signature. The Camenisch-Drijvers-Lehmann ZKP (ia.cr/2016/663) is used
 */
public class IdemixSignature {

    private final ECP aPrime;
    private final ECP aBar;
    private final ECP bPrime;
    private final BIG proofC;
    private final BIG proofSSk;
    private final BIG proofSE;
    private final BIG proofSR2;
    private final BIG proofSR3;
    private final BIG proofSSPrime;
    private final BIG[] proofSAttrs;
    private final BIG nonce;
    private final ECP nym;
    private final BIG proofSRNym;
    private Idemix.ECP2 revocationPk;
    private byte[] revocationPKSig;
    private long epoch;
    private Idemix.NonRevocationProof nonRevocationProof;

    private static final String SIGN_LABEL = "sign";

    /**
     * Create a new IdemixSignature by proving knowledge of a credential
     *
     * @param c          the credential used to create an idemix signature
     * @param sk         the signer's secret key
     * @param pseudonym  a pseudonym of the signer
     * @param ipk        the issuer public key
     * @param disclosure a bool-array that steers the disclosure of attributes
     * @param msg        the message to be signed
     * @param rhIndex    the index of the attribute that represents the revocation handle
     * @param cri        the credential revocation information that allows the signer to prove non-revocation
     */
    public IdemixSignature(IdemixCredential c, BIG sk, IdemixPseudonym pseudonym, IdemixIssuerPublicKey ipk, boolean[] disclosure, byte[] msg, int rhIndex, Idemix.CredentialRevocationInformation cri) {
        if (c == null || sk == null || pseudonym == null || pseudonym.getNym() == null || pseudonym.getRandNym() == null || ipk == null || disclosure == null || msg == null || cri == null) {
            throw new IllegalArgumentException("Cannot construct idemix signature from null input");
        }

        if (disclosure.length != c.getAttrs().length) {
            throw new IllegalArgumentException("Disclosure length must be the same as the number of attributes");
        }

        if (cri.getRevocationAlg() >= RevocationAlgorithm.values().length) {
            throw new IllegalArgumentException("CRI specifies unknown revocation algorithm");
        }

        if (cri.getRevocationAlg() != RevocationAlgorithm.ALG_NO_REVOCATION.ordinal() && disclosure[rhIndex]) {
            throw new IllegalArgumentException("Attribute " + rhIndex + " is disclosed but also used a revocation handle attribute, which should remain hidden");
        }

        RevocationAlgorithm revocationAlgorithm = RevocationAlgorithm.values()[cri.getRevocationAlg()];

        int[] hiddenIndices = hiddenIndices(disclosure);
        final RAND rng = IdemixUtils.getRand();
        // Start signature
        BIG r1 = IdemixUtils.randModOrder(rng);
        BIG r2 = IdemixUtils.randModOrder(rng);
        BIG r3 = new BIG(r1);
        r3.invmodp(IdemixUtils.GROUP_ORDER);

        nonce = IdemixUtils.randModOrder(rng);

        aPrime = PAIR.G1mul(c.getA(), r1);
        aBar = PAIR.G1mul(c.getB(), r1);
        aBar.sub(PAIR.G1mul(aPrime, c.getE()));

        bPrime = PAIR.G1mul(c.getB(), r1);
        bPrime.sub(PAIR.G1mul(ipk.getHRand(), r2));
        BIG sPrime = new BIG(c.getS());
        sPrime.add(BIG.modneg(BIG.modmul(r2, r3, IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER));
        sPrime.mod(IdemixUtils.GROUP_ORDER);

        //Construct Zero Knowledge Proof
        BIG rsk = IdemixUtils.randModOrder(rng);
        BIG re = IdemixUtils.randModOrder(rng);
        BIG rR2 = IdemixUtils.randModOrder(rng);
        BIG rR3 = IdemixUtils.randModOrder(rng);
        BIG rSPrime = IdemixUtils.randModOrder(rng);
        BIG rRNym = IdemixUtils.randModOrder(rng);
        BIG[] rAttrs = new BIG[hiddenIndices.length];
        for (int i = 0; i < hiddenIndices.length; i++) {
            rAttrs[i] = IdemixUtils.randModOrder(rng);
        }

        // Compute non-revoked proof
        NonRevocationProver prover = NonRevocationProver.getNonRevocationProver(revocationAlgorithm);
        int hiddenRHIndex = Ints.indexOf(hiddenIndices, rhIndex);
        if (hiddenRHIndex < 0) {
            // rhIndex is not present, set to last index position
            hiddenRHIndex = hiddenIndices.length;
        }
        byte[] nonRevokedProofHashData = prover.getFSContribution(BIG.fromBytes(c.getAttrs()[rhIndex]), rAttrs[hiddenRHIndex], cri);
        if (nonRevokedProofHashData == null) {
            throw new RuntimeException("Failed to compute non-revoked proof");
        }

        ECP t1 = aPrime.mul2(re, ipk.getHRand(), rR2);
        ECP t2 = PAIR.G1mul(ipk.getHRand(), rSPrime);
        t2.add(bPrime.mul2(rR3, ipk.getHsk(), rsk));

        for (int i = 0; i < hiddenIndices.length / 2; i++) {
            t2.add(ipk.getHAttrs()[hiddenIndices[2 * i]].mul2(rAttrs[2 * i], ipk.getHAttrs()[hiddenIndices[2 * i + 1]], rAttrs[2 * i + 1]));
        }
        if (hiddenIndices.length % 2 != 0) {
            t2.add(PAIR.G1mul(ipk.getHAttrs()[hiddenIndices[hiddenIndices.length - 1]], rAttrs[hiddenIndices.length - 1]));
        }

        ECP t3 = ipk.getHsk().mul2(rsk, ipk.getHRand(), rRNym);

        // create proofData such that it can contain the sign label, 7 elements in G1 (each of size 2*FIELD_BYTES+1),
        // the ipk hash, the disclosure array, and the message
        byte[] proofData = new byte[0];
        proofData = IdemixUtils.append(proofData, SIGN_LABEL.getBytes());
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t3));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(aPrime));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(aBar));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(bPrime));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(pseudonym.getNym()));
        proofData = IdemixUtils.append(proofData, ipk.getHash());
        proofData = IdemixUtils.append(proofData, disclosure);
        proofData = IdemixUtils.append(proofData, msg);

        BIG cvalue = IdemixUtils.hashModOrder(proofData);

        byte[] finalProofData = new byte[0];
        finalProofData = IdemixUtils.append(finalProofData, IdemixUtils.bigToBytes(cvalue));
        finalProofData = IdemixUtils.append(finalProofData, IdemixUtils.bigToBytes(nonce));

        proofC = IdemixUtils.hashModOrder(finalProofData);

        proofSSk = IdemixUtils.modAdd(rsk, BIG.modmul(proofC, sk, IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER);
        proofSE = IdemixUtils.modSub(re, BIG.modmul(proofC, c.getE(), IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER);
        proofSR2 = IdemixUtils.modAdd(rR2, BIG.modmul(proofC, r2, IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER);
        proofSR3 = IdemixUtils.modSub(rR3, BIG.modmul(proofC, r3, IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER);
        proofSSPrime = IdemixUtils.modAdd(rSPrime, BIG.modmul(proofC, sPrime, IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER);
        proofSRNym = IdemixUtils.modAdd(rRNym, BIG.modmul(proofC, pseudonym.getRandNym(), IdemixUtils.GROUP_ORDER), IdemixUtils.GROUP_ORDER);

        nym = new ECP();
        nym.copy(pseudonym.getNym());

        proofSAttrs = new BIG[hiddenIndices.length];
        for (int i = 0; i < hiddenIndices.length; i++) {
            proofSAttrs[i] = new BIG(rAttrs[i]);
            proofSAttrs[i].add(BIG.modmul(proofC, BIG.fromBytes(c.getAttrs()[hiddenIndices[i]]), IdemixUtils.GROUP_ORDER));
            proofSAttrs[i].mod(IdemixUtils.GROUP_ORDER);
        }

        // include non-revocation proof in signature
        this.revocationPk = cri.getEpochPk();
        this.revocationPKSig = cri.getEpochPkSig().toByteArray();
        this.epoch = cri.getEpoch();
        this.nonRevocationProof = prover.getNonRevocationProof(this.proofC);
    }

    /**
     * Construct a new signature from a serialized IdemixSignature
     *
     * @param proto a protobuf object representing an IdemixSignature
     */
    public IdemixSignature(Idemix.Signature proto) {
        if (proto == null) {
            throw new IllegalArgumentException("Cannot construct idemix signature from null input");
        }
        aBar = IdemixUtils.transformFromProto(proto.getABar());
        aPrime = IdemixUtils.transformFromProto(proto.getAPrime());
        bPrime = IdemixUtils.transformFromProto(proto.getBPrime());
        nym = IdemixUtils.transformFromProto(proto.getNym());
        proofC = BIG.fromBytes(proto.getProofC().toByteArray());
        proofSSk = BIG.fromBytes(proto.getProofSSk().toByteArray());
        proofSE = BIG.fromBytes(proto.getProofSE().toByteArray());
        proofSR2 = BIG.fromBytes(proto.getProofSR2().toByteArray());
        proofSR3 = BIG.fromBytes(proto.getProofSR3().toByteArray());
        proofSSPrime = BIG.fromBytes(proto.getProofSSPrime().toByteArray());
        proofSRNym = BIG.fromBytes(proto.getProofSRNym().toByteArray());
        nonce = BIG.fromBytes(proto.getNonce().toByteArray());
        proofSAttrs = new BIG[proto.getProofSAttrsCount()];
        for (int i = 0; i < proto.getProofSAttrsCount(); i++) {
            proofSAttrs[i] = BIG.fromBytes(proto.getProofSAttrs(i).toByteArray());
        }

        revocationPk = proto.getRevocationEpochPk();
        revocationPKSig = proto.getRevocationPkSig().toByteArray();
        epoch = proto.getEpoch();
        nonRevocationProof = proto.getNonRevocationProof();
    }

    /**
     * Verify this signature
     *
     * @param disclosure      an array indicating which attributes it expects to be disclosed
     * @param ipk             the issuer public key
     * @param msg             the message that should be signed in this signature
     * @param attributeValues BIG array where attributeValues[i] contains the desired attribute value for the i-th attribute if its disclosed
     * @param rhIndex         index of the attribute that represents the revocation-handle
     * @param revPk           the long term public key used to authenticate CRIs
     * @param epoch           monotonically increasing counter representing a time window
     * @return true iff valid
     */
    public boolean verify(boolean[] disclosure, IdemixIssuerPublicKey ipk, byte[] msg, BIG[] attributeValues, int rhIndex, PublicKey revPk, int epoch) throws CryptoException {
        if (disclosure == null || ipk == null || msg == null || attributeValues == null || attributeValues.length != ipk.getAttributeNames().length || disclosure.length != ipk.getAttributeNames().length) {
            return false;
        }
        for (int i = 0; i < ipk.getAttributeNames().length; i++) {
            if (disclosure[i] && attributeValues[i] == null) {
                return false;
            }
        }

        int[] hiddenIndices = hiddenIndices(disclosure);
        if (proofSAttrs.length != hiddenIndices.length) {
            return false;
        }
        if (aPrime.is_infinity()) {
            return false;
        }
        if (nonRevocationProof.getRevocationAlg() >= RevocationAlgorithm.values().length) {
            throw new IllegalArgumentException("CRI specifies unknown revocation algorithm");
        }

        RevocationAlgorithm revocationAlgorithm = RevocationAlgorithm.values()[nonRevocationProof.getRevocationAlg()];

        if (disclosure[rhIndex]) {
            throw new IllegalArgumentException("Attribute " + rhIndex + " is disclosed but also used a revocation handle attribute, which should remain hidden");
        }

        // Verify EpochPK
        if (!RevocationAuthority.verifyEpochPK(revPk, this.revocationPk, this.revocationPKSig, epoch, revocationAlgorithm)) {
            // Signature is based on an invalid revocation epoch public key
            return false;
        }

        FP12 temp1 = PAIR.ate(ipk.getW(), aPrime);
        FP12 temp2 = PAIR.ate(IdemixUtils.genG2, aBar);
        temp2.inverse();
        temp1.mul(temp2);
        if (!PAIR.fexp(temp1).isunity()) {
            return false;
        }

        ECP t1 = aPrime.mul2(proofSE, ipk.getHRand(), proofSR2);
        ECP temp = new ECP();
        temp.copy(aBar);
        temp.sub(bPrime);
        t1.sub(PAIR.G1mul(temp, proofC));

        ECP t2 = PAIR.G1mul(ipk.getHRand(), proofSSPrime);
        t2.add(bPrime.mul2(proofSR3, ipk.getHsk(), proofSSk));

        for (int i = 0; i < hiddenIndices.length / 2; i++) {
            t2.add(ipk.getHAttrs()[hiddenIndices[2 * i]].mul2(proofSAttrs[2 * i], ipk.getHAttrs()[hiddenIndices[2 * i + 1]], proofSAttrs[2 * i + 1]));
        }
        if (hiddenIndices.length % 2 != 0) {
            t2.add(PAIR.G1mul(ipk.getHAttrs()[hiddenIndices[hiddenIndices.length - 1]], proofSAttrs[hiddenIndices.length - 1]));
        }

        temp = new ECP();
        temp.copy(IdemixUtils.genG1);

        for (int i = 0; i < disclosure.length; i++) {
            if (disclosure[i]) {
                temp.add(PAIR.G1mul(ipk.getHAttrs()[i], attributeValues[i]));
            }
        }
        t2.add(PAIR.G1mul(temp, proofC));

        ECP t3 = ipk.getHsk().mul2(proofSSk, ipk.getHRand(), proofSRNym);
        t3.sub(nym.mul(proofC));

        // Check with non-revoked-verifier
        NonRevocationVerifier nonRevokedVerifier = NonRevocationVerifier.getNonRevocationVerifier(revocationAlgorithm);
        int hiddenRHIndex = Ints.indexOf(hiddenIndices, rhIndex);
        if (hiddenRHIndex < 0) {
            // rhIndex is not present, set to last index position
            hiddenRHIndex = hiddenIndices.length;
        }
        BIG proofSRh = proofSAttrs[hiddenRHIndex];
        byte[] nonRevokedProofBytes = nonRevokedVerifier.recomputeFSContribution(this.nonRevocationProof, proofC, IdemixUtils.transformFromProto(this.revocationPk), proofSRh);
        if (nonRevokedProofBytes == null) {
            return false;
        }

        // create proofData such that it can contain the sign label, 7 elements in G1 (each of size 2*FIELD_BYTES+1),
        // the ipk hash, the disclosure array, and the message
        byte[] proofData = new byte[0];
        proofData = IdemixUtils.append(proofData, SIGN_LABEL.getBytes());
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t3));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(aPrime));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(aBar));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(bPrime));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(nym));
        proofData = IdemixUtils.append(proofData, ipk.getHash());
        proofData = IdemixUtils.append(proofData, disclosure);
        proofData = IdemixUtils.append(proofData, msg);

        BIG cvalue = IdemixUtils.hashModOrder(proofData);

        byte[] finalProofData = new byte[0];
        finalProofData = IdemixUtils.append(finalProofData, IdemixUtils.bigToBytes(cvalue));
        finalProofData = IdemixUtils.append(finalProofData, IdemixUtils.bigToBytes(nonce));

        byte[] hashedProofData = IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(finalProofData));
        return Arrays.equals(IdemixUtils.bigToBytes(proofC), hashedProofData);
    }

    /**
     * Convert this signature to a proto
     *
     * @return a protobuf object representing this IdemixSignature
     */
    public Idemix.Signature toProto() {
        Idemix.Signature.Builder builder = Idemix.Signature.newBuilder()
                .setAPrime(IdemixUtils.transformToProto(aPrime))
                .setABar(IdemixUtils.transformToProto(aBar))
                .setBPrime(IdemixUtils.transformToProto(bPrime))
                .setNym(IdemixUtils.transformToProto(nym))
                .setProofC(ByteString.copyFrom(IdemixUtils.bigToBytes(proofC)))
                .setProofSSk(ByteString.copyFrom(IdemixUtils.bigToBytes(proofSSk)))
                .setProofSE(ByteString.copyFrom(IdemixUtils.bigToBytes(proofSE)))
                .setProofSR2(ByteString.copyFrom(IdemixUtils.bigToBytes(proofSR2)))
                .setProofSR3(ByteString.copyFrom(IdemixUtils.bigToBytes(proofSR3)))
                .setProofSRNym(ByteString.copyFrom(IdemixUtils.bigToBytes(proofSRNym)))
                .setProofSSPrime(ByteString.copyFrom(IdemixUtils.bigToBytes(proofSSPrime)))
                .setNonce(ByteString.copyFrom(IdemixUtils.bigToBytes(nonce)))
                .setRevocationEpochPk(revocationPk)
                .setRevocationPkSig(ByteString.copyFrom(revocationPKSig))
                .setEpoch(epoch)
                .setNonRevocationProof(nonRevocationProof);

        for (BIG attr : proofSAttrs) {
            builder.addProofSAttrs(ByteString.copyFrom(IdemixUtils.bigToBytes(attr)));
        }

        return builder.build();
    }

    /**
     * Some attributes may be hidden, some disclosed. The indices of the hidden attributes will be passed.
     *
     * @param disclosure an array where the i-th value indicates whether or not the i-th attribute should be disclosed
     * @return an integer array of the hidden indices
     */
    private int[] hiddenIndices(boolean[] disclosure) {
        if (disclosure == null) {
            throw new IllegalArgumentException("cannot compute hidden indices of null disclosure");
        }
        List<Integer> hiddenIndicesList = new ArrayList<>();
        for (int i = 0; i < disclosure.length; i++) {
            if (!disclosure[i]) {
                hiddenIndicesList.add(i);
            }
        }
        int[] hiddenIndices = new int[hiddenIndicesList.size()];
        for (int i = 0; i < hiddenIndicesList.size(); i++) {
            hiddenIndices[i] = hiddenIndicesList.get(i);
        }

        return hiddenIndices;
    }
}
