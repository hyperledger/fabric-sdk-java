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
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.apache.milagro.amcl.RAND;

/**
 * WeakBB contains the functions to use Weak Boneh-Boyen signatures (https://ia.cr/2004/171)
 */
public class WeakBB {
    private WeakBB() {
        // private constructor for util class
    }

    /**
     * WeakBB.KeyPair represents a key pair for weak Boneh-Boyen signatures
     */
    public static final class KeyPair {
        private final BIG sk;
        private final ECP2 pk;

        private KeyPair() {
            final RAND rng = IdemixUtils.getRand();
            this.sk = IdemixUtils.randModOrder(rng);
            this.pk = IdemixUtils.genG2.mul(sk);
        }

        public BIG getSk() {
            return sk;
        }

        public ECP2 getPk() {
            return pk;
        }
    }

    /**
     * Generate a new key-pair set
     *
     * @return a freshly generated key pair
     */
    public static KeyPair weakBBKeyGen() {
        return new KeyPair();
    }

    /**
     * Produces a WBB signature for a give message
     *
     * @param sk Secret key
     * @param m  Message
     * @return Signature
     */
    public static ECP weakBBSign(BIG sk, BIG m) {
        BIG exp = IdemixUtils.modAdd(sk, m, IdemixUtils.GROUP_ORDER);
        exp.invmodp(IdemixUtils.GROUP_ORDER);

        return IdemixUtils.genG1.mul(exp);
    }

    /**
     * Verify a WBB signature for a certain message
     *
     * @param pk  Public key
     * @param sig Signature
     * @param m   Message
     * @return True iff valid
     */
    public static boolean weakBBVerify(ECP2 pk, ECP sig, BIG m) {
        ECP2 p = new ECP2();
        p.copy(pk);
        p.add(IdemixUtils.genG2.mul(m));
        p.affine();

        return PAIR.fexp(PAIR.ate(p, sig)).equals(IdemixUtils.genGT);
    }

}