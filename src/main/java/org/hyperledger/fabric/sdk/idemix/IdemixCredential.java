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

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * IdemixCredential represents a user's idemix credential,
 * which is a BBS+ signature (see "Constant-Size Dynamic k-TAA" by Man Ho Au, Willy Susilo, Yi Mu)
 * on the user's secret key and attribute values.
 */
public class IdemixCredential {

    private final ECP A;
    private final ECP B;
    private final BIG E;
    private final BIG S;
    private final byte[][] Attrs;

    /**
     * Constructor creating a new credential
     *
     * @param key   the issuer key pair
     * @param m     a credential request
     * @param attrs an array of attribute values as BIG
     */
    IdemixCredential(IdemixIssuerKey key, IdemixCredRequest m, BIG[] attrs) {
        if (key == null || key.getIpk() == null || m == null || attrs == null) {
            throw new IllegalArgumentException("Cannot create idemix credential from null input");
        }
        if (attrs.length != key.getIpk().getAttributeNames().length) {
            throw new IllegalArgumentException("Amount of attribute values does not match amount of attributes in issuer public key");
        }
        final RAND rng = IdemixUtils.getRand();
        // Place a BBS+ signature on the user key and the attribute values
        // (For BBS+, see "Constant-Size Dynamic k-TAA" by Man Ho Au, Willy Susilo, Yi Mu)
        E = IdemixUtils.randModOrder(rng);
        S = IdemixUtils.randModOrder(rng);

        B = new ECP();
        B.copy(IdemixUtils.genG1);
        B.add(m.getNym());
        B.add(key.getIpk().getHRand().mul(S));

        for (int i = 0; i < attrs.length / 2; i++) {
            B.add(key.getIpk().getHAttrs()[2 * i].mul2(attrs[2 * i], key.getIpk().getHAttrs()[2 * i + 1], attrs[2 * i + 1]));
        }
        if (attrs.length % 2 != 0) {
            B.add(key.getIpk().getHAttrs()[attrs.length - 1].mul(attrs[attrs.length - 1]));
        }

        BIG exp = new BIG(key.getIsk()).plus(E);
        exp.mod(IdemixUtils.GROUP_ORDER);
        exp.invmodp(IdemixUtils.GROUP_ORDER);
        A = B.mul(exp);

        Attrs = new byte[attrs.length][IdemixUtils.FIELD_BYTES];
        byte[] b = new byte[IdemixUtils.FIELD_BYTES];
        for (int i = 0; i < attrs.length; i++) {
            attrs[i].toBytes(b);
            System.arraycopy(b, 0, Attrs[i], 0, IdemixUtils.FIELD_BYTES);
        }
    }

    /**
     * Construct an IdemixCredential from a serialized credential
     *
     * @param proto a protobuf representation of a credential
     */
    public IdemixCredential(Idemix.Credential proto) {
        if (proto == null) {
            throw new IllegalArgumentException("Cannot create idemix credential from null input");
        }

        A = IdemixUtils.transformFromProto(proto.getA());
        B = IdemixUtils.transformFromProto(proto.getB());
        E = BIG.fromBytes(proto.getE().toByteArray());
        S = BIG.fromBytes(proto.getS().toByteArray());
        Attrs = new byte[proto.getAttrsCount()][];
        for (int i = 0; i < proto.getAttrsCount(); i++) {
            Attrs[i] = proto.getAttrs(i).toByteArray();
        }
    }

    ECP getA() {
        return A;
    }

    ECP getB() {
        return B;
    }

    BIG getE() {
        return E;
    }

    BIG getS() {
        return S;
    }

    public byte[][] getAttrs() {
        return Attrs;
    }

    /**
     * verify cryptographically verifies the credential
     *
     * @param sk  the secret key of the user
     * @param ipk the public key of the issuer
     * @return true iff valid
     */
    public boolean verify(BIG sk, IdemixIssuerPublicKey ipk) {
        if (ipk == null || Attrs.length != ipk.getAttributeNames().length) {
            return false;
        }
        for (byte[] attr : Attrs) {
            if (attr == null) {
                return false;
            }
        }

        ECP bPrime = new ECP();
        bPrime.copy(IdemixUtils.genG1);
        bPrime.add(ipk.getHsk().mul2(sk, ipk.getHRand(), S));
        for (int i = 0; i < Attrs.length / 2; i++) {
            bPrime.add(ipk.getHAttrs()[2 * i].mul2(BIG.fromBytes(Attrs[2 * i]), ipk.getHAttrs()[2 * i + 1], BIG.fromBytes(Attrs[2 * i + 1])));
        }
        if (Attrs.length % 2 != 0) {
            bPrime.add(ipk.getHAttrs()[Attrs.length - 1].mul(BIG.fromBytes(Attrs[Attrs.length - 1])));
        }
        if (!B.equals(bPrime)) {
            return false;
        }

        ECP2 a = IdemixUtils.genG2.mul(E);
        a.add(ipk.getW());
        a.affine();
        return PAIR.fexp(PAIR.ate(a, A)).equals(PAIR.fexp(PAIR.ate(IdemixUtils.genG2, B)));
    }

    /**
     * @return A proto representation of this credential
     */
    Idemix.Credential toProto() {
        Idemix.Credential.Builder builder = Idemix.Credential.newBuilder()
                .setA(IdemixUtils.transformToProto(A))
                .setB(IdemixUtils.transformToProto(B))
                .setE(ByteString.copyFrom(IdemixUtils.bigToBytes(E)))
                .setS(ByteString.copyFrom(IdemixUtils.bigToBytes(S)));

        for (byte[] attr : Attrs) {
            builder.addAttrs(ByteString.copyFrom(attr));
        }

        return builder.build();
    }
}