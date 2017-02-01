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

package org.hyperledger.fabric.sdk.shim.crypto;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Security;

public class CryptoPrimitives {
    private int keyLength;
    private String hashingAlgorithm;
    private String secCurve;
    private static final String SEC_256_CURVE = "secp256r1";
    private static final String SEC_384_CURVE = "secp384r1";

    private static X9ECParameters CURVE_PARAMS;
    private static ECDomainParameters CURVE;

    public CryptoPrimitives(int keyLength, String hashingAlgorithm) {

        Security.addProvider(new BouncyCastleProvider());
        this.keyLength = keyLength;
        this.hashingAlgorithm = hashingAlgorithm;

        if (this.keyLength == 256) {
            this.secCurve = SEC_256_CURVE;
        } else if (this.keyLength == 384) {
            this.secCurve = SEC_384_CURVE;
        } else {
            throw new RuntimeException("Unsupported Key length");
        }
        CURVE_PARAMS = CustomNamedCurves.getByName(secCurve);
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());

    }

    public boolean ecdsaVerify(byte[] publicKey, byte[] signature, byte[] payload) {
            ECDSASigner signer = new ECDSASigner();
            ECPublicKeyParameters params = new ECPublicKeyParameters(CURVE.getCurve().decodePoint(publicKey), CURVE);
            signer.init(false, params);
            ASN1InputStream decoder;
            decoder = new ASN1InputStream(signature);
            try {


                DERSequence seq = (DERSequence) decoder.readObject();
                ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
                ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);
                decoder.close();
                return signer.verifySignature(payload, r.getValue(), s.getValue());
            } catch (Exception e) {
                return false;
            }
            finally {
                try {
                    decoder.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
}
