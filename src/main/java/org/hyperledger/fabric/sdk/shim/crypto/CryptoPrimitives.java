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
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

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
    /**
     * 
     * @param certificate
     * @param signature
     * @param plainText
     * @return
     */
    public boolean ecdsaVerify(byte[] certificate, byte[] signature, byte[] plainText) {
    	ASN1InputStream asn1 = null;
    	InputStream in = null;
    	DigestSHA3 sha3 = new DigestSHA3(256);
    	try{
        	in = new ByteArrayInputStream(certificate);
        	CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        	X509Certificate c = (X509Certificate)certFactory.generateCertificate(in);
        	ECPublicKey ecPublicKey = (ECPublicKey) c.getPublicKey();
        	ECDSASigner signer = new ECDSASigner();
        	ECPublicKeyParameters bcPubKeyParams =  (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(ecPublicKey);
        	ECPublicKeyParameters params = new ECPublicKeyParameters(CURVE.getCurve().decodePoint(bcPubKeyParams.getQ().getEncoded(false)), CURVE);
        	signer.init(false, params);
        	asn1 = new ASN1InputStream(signature);
    		DLSequence seq = (DLSequence) asn1.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
            return signer.verifySignature(sha3.digest(plainText), r, s);
    	}catch(Exception e){
    		e.printStackTrace();
    		return false;
    	}finally{
    		if(in!=null){
    			try {
					in.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
    		}
    		if(asn1!=null){
    			try {
					asn1.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
    		}
    	}
    }
}
