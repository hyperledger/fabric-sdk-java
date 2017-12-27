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
import java.util.HashSet;
import java.util.Set;

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * IdemixIssuerPublicKey represents the idemix public key of an issuer (Certificate Authority).
 */
public class IdemixIssuerPublicKey {

    private final String[] AttributeNames;
    private final ECP Hsk;
    private final ECP HRand;
    private final ECP[] HAttrs;
    private final ECP2 W;
    private final ECP BarG1;
    private final ECP BarG2;
    private final BIG ProofC;
    private final BIG ProofS;
    private byte[] Hash = new byte[0];

    /**
     * Constructor
     *
     * @param attributeNames the names of attributes as String array (must not contain duplicates)
     * @param isk            the issuer secret key
     */
     IdemixIssuerPublicKey(String[] attributeNames, BIG isk) {
        // check null input
        if (attributeNames == null || isk == null) {
            throw new IllegalArgumentException("Cannot create IdemixIssuerPublicKey from null input");
        }

        // Checking if attribute names are unique
        Set<String> map = new HashSet<>();
        for (String item : attributeNames) {
            if (!map.add(item)) {
                throw new IllegalArgumentException("Attribute " + item + " appears multiple times in attributeNames");
            }
        }
        final RAND rng = IdemixUtils.getRand();
        // Attaching Attribute Names array correctly
        AttributeNames = attributeNames;

        // Computing W value
        W = IdemixUtils.genG2.mul(isk);

        // Filling up HAttributes correctly in Issuer Public Key, length
        // preserving
        HAttrs = new ECP[attributeNames.length];

        for (int i = 0; i < attributeNames.length; i++) {
            HAttrs[i] = IdemixUtils.genG1.mul(IdemixUtils.randModOrder(rng));
        }

        // Generating Hsk value
        Hsk = IdemixUtils.genG1.mul(IdemixUtils.randModOrder(rng));

        // Generating HRand value
        HRand = IdemixUtils.genG1.mul(IdemixUtils.randModOrder(rng));

        // Generating BarG1 value
        BarG1 = IdemixUtils.genG1.mul(IdemixUtils.randModOrder(rng));

        // Generating BarG2 value
        BarG2 = BarG1.mul(isk);

        // Zero Knowledge Proofs

        // Computing t1 and t2 values with random local variable r for later use
        BIG r = IdemixUtils.randModOrder(rng);
        ECP2 t1 = IdemixUtils.genG2.mul(r);
        ECP t2 = BarG1.mul(r);

        // Generating proofData that will contain 3 elements in G1 (of size 2*FIELD_BYTES+1)and 3 elements in G2 (of size 4 * FIELD_BYTES)
        byte[] proofData = new byte[0];
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(IdemixUtils.genG2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(BarG1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(W));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(BarG2));

        // Hashing proofData to proofC
        ProofC = IdemixUtils.hashModOrder(proofData);

        // Computing ProofS = (ProofC*isk) + r mod GROUP_ORDER
        ProofS = BIG.modmul(ProofC, isk, IdemixUtils.GROUP_ORDER).plus(r);
        ProofS.mod(IdemixUtils.GROUP_ORDER);

        // Compute Hash of IdemixIssuerPublicKey
        byte[] serializedIpk = toProto().toByteArray();
        Hash = IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(serializedIpk));
    }

    /**
     * Construct an IdemixIssuerPublicKey from a serialized issuer public key
     *
     * @param proto a protobuf representation of an issuer public key
     */
     public IdemixIssuerPublicKey(Idemix.IssuerPublicKey proto) {
        // check for bad input
        if (proto == null) {
            throw new IllegalArgumentException("Cannot create IdemixIssuerPublicKey from null input");
        }
        if (proto.getHAttrsCount() < proto.getAttributeNamesCount()) {
            throw new IllegalArgumentException("Serialized IPk does not contain enough HAttr values");
        }

        AttributeNames = new String[proto.getAttributeNamesCount()];
        for (int i = 0; i < proto.getAttributeNamesCount(); i++) {
            AttributeNames[i] = proto.getAttributeNames(i);
        }

        HAttrs = new ECP[proto.getHAttrsCount()];
        for (int i = 0; i < proto.getHAttrsCount(); i++) {
            HAttrs[i] = IdemixUtils.transformFromProto(proto.getHAttrs(i));
        }

        BarG1 = IdemixUtils.transformFromProto(proto.getBarG1());
        BarG2 = IdemixUtils.transformFromProto(proto.getBarG2());
        HRand = IdemixUtils.transformFromProto(proto.getHRand());
        Hsk = IdemixUtils.transformFromProto(proto.getHSk());
        ProofC = BIG.fromBytes(proto.getProofC().toByteArray());
        ProofS = BIG.fromBytes(proto.getProofS().toByteArray());
        W = IdemixUtils.transformFromProto(proto.getW());

        // Compute Hash of IdemixIssuerPublicKey
        byte[] serializedIpk = toProto().toByteArray();
        Hash = IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(serializedIpk));
    }


    /**
     * check whether the issuer public key is correct
     *
     * @return true iff valid
     */
     public boolean check() {
        // check formalities of IdemixIssuerPublicKey
        if (AttributeNames == null || Hsk == null || HRand == null || HAttrs == null
                || BarG1 == null || BarG1.is_infinity() || BarG2 == null
                || HAttrs.length < AttributeNames.length) {
            return false;
        }

        for (int i = 0; i < AttributeNames.length; i++) {
            if (HAttrs[i] == null) {
                return false;
            }
        }

        // check proofs
        ECP2 t1 = IdemixUtils.genG2.mul(ProofS);
        ECP t2 = BarG1.mul(ProofS);

        t1.add(W.mul(BIG.modneg(ProofC, IdemixUtils.GROUP_ORDER)));
        t2.add(BarG2.mul(BIG.modneg(ProofC, IdemixUtils.GROUP_ORDER)));

        // Generating proofData that will contain 3 elements in G1 (of size 2*FIELD_BYTES+1)and 3 elements in G2 (of size 4 * FIELD_BYTES)
        byte[] proofData = new byte[0];
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(IdemixUtils.genG2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(BarG1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(W));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(BarG2));

        // Hash proofData to hproofdata and compare with proofC
        return Arrays.equals(IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(proofData)), IdemixUtils.bigToBytes(ProofC));
    }

    /**
     * @return A proto version of this issuer public key
     */
     Idemix.IssuerPublicKey toProto() {

        Idemix.ECP[] ipkHAttrs = new Idemix.ECP[HAttrs.length];
        for (int i = 0; i < HAttrs.length; i++) {
            ipkHAttrs[i] = IdemixUtils.transformToProto(HAttrs[i]);
        }

        return Idemix.IssuerPublicKey.newBuilder()
                .setProofC(ByteString.copyFrom(IdemixUtils.bigToBytes(ProofC)))
                .setProofS(ByteString.copyFrom(IdemixUtils.bigToBytes(ProofS)))
                .setW(IdemixUtils.transformToProto(W))
                .setHSk(IdemixUtils.transformToProto(Hsk))
                .setHRand(IdemixUtils.transformToProto(HRand))
                .addAllAttributeNames(Arrays.asList(AttributeNames))
                .setHash(ByteString.copyFrom(Hash))
                .setBarG1(IdemixUtils.transformToProto(BarG1))
                .setBarG2(IdemixUtils.transformToProto(BarG2))
                .addAllHAttrs(Arrays.asList(ipkHAttrs))
                .build();
    }

    /**
     * @return The names of the attributes certified with this issuer public key
     */
     public String[] getAttributeNames() {
        return AttributeNames;
    }

    protected ECP getHsk() {
        return Hsk;
    }

    protected ECP getHRand() {
        return HRand;
    }

    protected ECP[] getHAttrs() {
        return HAttrs;
    }

    protected ECP2 getW() {
        return W;
    }

    /**
     * @return A digest of this issuer public key
     */
     public byte[] getHash() {
        return Hash;
    }
}
