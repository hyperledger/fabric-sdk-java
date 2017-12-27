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
import org.apache.milagro.amcl.RAND;

/**
 * The class represents a pseudonym of a user,
 * unlinkable to other pseudonyms of the user.
 */
public class IdemixPseudonym {

    private final ECP Nym;
    private final BIG RandNym;

    /**
     * Constructor
     *
     * @param sk  the secret key of the user
     * @param ipk the public key of the issuer
     */
     public IdemixPseudonym(BIG sk, IdemixIssuerPublicKey ipk) {
        if (sk == null || ipk == null) {
            throw new IllegalArgumentException("Cannot construct idemix pseudonym from null input");
        }
        final RAND rng = IdemixUtils.getRand();
        RandNym = IdemixUtils.randModOrder(rng);
        Nym = ipk.getHsk().mul2(sk, ipk.getHRand(), RandNym);
    }

    /**
     * @return the value of the pseudonym as an ECP
     */
     public ECP getNym() {
        return Nym;
    }

    /**
     * @return the secret randomness used to construct this pseudonym
     */
     BIG getRandNym() {
        return RandNym;
    }
}
