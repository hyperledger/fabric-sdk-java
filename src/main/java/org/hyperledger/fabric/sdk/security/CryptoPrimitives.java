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

package org.hyperledger.fabric.sdk.security;

import java.util.ArrayList;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import io.netty.util.internal.StringUtil;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.SDKUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class CryptoPrimitives {
    private static final Config config = Config.getConfig();

    private String hashAlgorithm = config.getDefaultHashAlgorithm();
    private int securityLevel = config.getDefaultSecurityLevel();
    private String curveName;
    private static final String SECURITY_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    private static final String ASYMMETRIC_KEY_TYPE = "EC";
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";
    private static final String SYMMETRIC_KEY_TYPE = "AES";
    private static final int SYMMETRIC_KEY_BYTE_COUNT = 32;
    private static final String SYMMETRIC_ALGORITHM = "AES/CFB/NoPadding";
    private static final int MAC_KEY_BYTE_COUNT = 32;
    
    private static final String CERTIFICATE_FORMAT = "X.509" ;
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA" ; // TODO configure via .properties or genesis block
    
    private static final Log logger = LogFactory.getLog(CryptoPrimitives.class);
    
    public CryptoPrimitives(String hashAlgorithm, int securityLevel) {
        this.hashAlgorithm = hashAlgorithm;
        this.securityLevel = securityLevel;
        Security.addProvider(new BouncyCastleProvider());
        init();
    }
    
    /**
     * Verify a signature 
     * @param plainText original text.
     * @param signature signature generated from plainText
     * @param pemCertificate the X509 certificate to be used for verification
     * @return
     */
    public static boolean verify(byte[] plainText, byte[] signature, byte[] pemCertificate) {
    	boolean isVerified = false ;
    	
    	if (plainText == null || signature == null || pemCertificate == null )
    		return false;
    	
    	logger.debug("plaintext in hex: " + DatatypeConverter.printHexBinary(plainText));
    	logger.debug("signature in hex: " + DatatypeConverter.printHexBinary(signature));
    	logger.debug("PEM cert in hex: " + DatatypeConverter.printHexBinary(pemCertificate));
    	
     	try {
    		BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(pemCertificate));
    		CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT) ;
    		X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);
    		Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM) ;
    		sig.initVerify(certificate);
    		sig.update(plainText);
    		isVerified = sig.verify(signature);
    	} catch (InvalidKeyException | CertificateException e) {
    		logger.error("Cannot verify. Invalid Certificate. Error is: " + 
    	                    e.getMessage() +
    	                    "\r\nCertificate (PEM, hex): " + DatatypeConverter.printHexBinary(pemCertificate));
    	} catch (NoSuchAlgorithmException e) {
    		logger.error("Cannot verify. Signature algorithm is invalid. Error is: " + e.getMessage());
    	} catch (SignatureException e) {
    		logger.error("Cannot verify. Error is: " + e.getMessage());;
    	}

		return isVerified;
    } // verify
 
    // TODO refactor TrustStore, CertFactory depending on whether we want to make CryptoPrimitives static 
    private static KeyStore trustStore ;
    
    public static void setTrustStore(KeyStore keyStore) {
    	CryptoPrimitives.trustStore = keyStore ;
    }
    
    public static KeyStore getTrustStore() {
    	return CryptoPrimitives.trustStore ;
    }
    
    public static boolean validateCertificate(byte[] certPEM) {
    	
    	if (certPEM == null) 
    		return false;
    	
    	try {
    		BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certPEM));
    		CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT) ;
    		X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);
    		return CryptoPrimitives.validateCertificate(certificate);
    		} catch (CertificateException e) {
        		logger.error("Cannot validate certificate. Error is: " + 
	                    e.getMessage() +
	                    "\r\nCertificate (PEM, hex): " + DatatypeConverter.printHexBinary(certPEM));
        		return false ;
		}
    }
    
    public static boolean validateCertificate(Certificate cert) {
    	boolean isValidated = false ;
    	
    	if (cert == null) 
    		return isValidated;
    	
    	try {
    		PKIXParameters parms = new PKIXParameters(CryptoPrimitives.getTrustStore()) ;
    		parms.setRevocationEnabled(false);

    		CertPathValidator certValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType()); // PKIX

    		ArrayList<Certificate> start = new ArrayList<Certificate>(); start.add(cert);
    		CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT) ;
    		CertPath certPath = certFactory.generateCertPath(start) ;

    		certValidator.validate(certPath, parms);
    		isValidated = true ; // if cert not validated, CertPathValidatorException thrown
    		
    	} catch (KeyStoreException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
    			| CertificateException | CertPathValidatorException e) {
    		logger.error("Cannot validate certificate. Error is: " + 
                    e.getMessage() +
                    "\r\nCertificate" + cert.toString());
    		isValidated = false ;
    	}
    	
    	return isValidated;
    } // validateCertificate

    public int getSecurityLevel() {
        return securityLevel;
    }

    public void setSecurityLevel(int securityLevel) {
        this.securityLevel = securityLevel;
    }

    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public void setHashAlgorithm(String algorithm) {
        this.hashAlgorithm = algorithm;
    }

    public KeyPair ecdsaKeyGen() throws CryptoException {
        return generateKey("ECDSA", this.curveName);
    }

    private KeyPair generateKey(String encryptionName, String curveName) throws CryptoException {
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);
            KeyPairGenerator g = KeyPairGenerator.getInstance(encryptionName, SECURITY_PROVIDER);
            g.initialize(ecGenSpec, new SecureRandom());
            KeyPair pair = g.generateKeyPair();
            return pair;
        } catch (Exception exp) {
            throw new CryptoException("Unable to generate key pair", exp);
        }
    }

    public byte[] eciesDecrypt(KeyPair keyPair, byte[] data) throws CryptoException {
        try {
            int ek_len = (int) (Math.floor((this.securityLevel + 7) / 8) * 2 + 1);
            int mk_len = this.securityLevel >> 3;
            int em_len = data.length - ek_len - mk_len;

            byte[] ephemeralPublicKeyBytes = Arrays.copyOfRange(data, 0, ek_len);
            byte[] encryptedMessage = Arrays.copyOfRange(data, ek_len, ek_len + em_len);
            byte[] tag = Arrays.copyOfRange(data, ek_len + em_len, data.length);

            // Parsing public key.
            ECParameterSpec asymmetricKeyParams = generateECParameterSpec();
            KeyFactory asymmetricKeyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE, SECURITY_PROVIDER);

            PublicKey ephemeralPublicKey = asymmetricKeyFactory.generatePublic(new ECPublicKeySpec(
                    asymmetricKeyParams.getCurve().decodePoint(ephemeralPublicKeyBytes), asymmetricKeyParams));

            // Deriving shared secret.
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, SECURITY_PROVIDER);
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(ephemeralPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Deriving encryption and mac keys.
            HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(getHashDigest());

            hkdfBytesGenerator.init(new HKDFParameters(sharedSecret, null, null));
            byte[] encryptionKey = new byte[SYMMETRIC_KEY_BYTE_COUNT];
            hkdfBytesGenerator.generateBytes(encryptionKey, 0, SYMMETRIC_KEY_BYTE_COUNT);

            byte[] macKey = new byte[MAC_KEY_BYTE_COUNT];
            hkdfBytesGenerator.generateBytes(macKey, 0, MAC_KEY_BYTE_COUNT);

            // Verifying Message Authentication Code (aka mac/tag)
            byte[] expectedTag = calculateMac(macKey, encryptedMessage);
            if (!Arrays.areEqual(tag, expectedTag)) {
                throw new RuntimeException("Bad Message Authentication Code!");
            }

            // Decrypting the message.
            byte[] iv = Arrays.copyOfRange(encryptedMessage, 0, 16);
            byte[] encrypted = Arrays.copyOfRange(encryptedMessage, 16, encryptedMessage.length);
            byte[] output = aesDecrypt(encryptionKey, iv, encrypted);

            return output;

        } catch (Exception e) {
            throw new CryptoException("Could not decrypt the message", e);
        }

    }

    private byte[] calculateMac(byte[] macKey, byte[] encryptedMessage)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        HMac hmac = new HMac(getHashDigest());
        hmac.init(new KeyParameter(macKey));
        hmac.update(encryptedMessage, 0, encryptedMessage.length);
        byte[] out = new byte[MAC_KEY_BYTE_COUNT];
        hmac.doFinal(out, 0);
        return out;
    }

    private byte[] aesDecrypt(byte[] encryptionKey, byte[] iv, byte[] encryptedMessage)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, SYMMETRIC_KEY_TYPE), new IvParameterSpec(iv));
        return cipher.doFinal(encryptedMessage);

    }

    private ECNamedCurveParameterSpec generateECParameterSpec() {
        ECNamedCurveParameterSpec bcParams = ECNamedCurveTable.getParameterSpec(this.curveName);
        return bcParams;
    }

    public byte[][] ecdsaSign(PrivateKey privateKey, byte[] data) throws CryptoException {
        try {
            byte[] encoded = SDKUtil.hash(data, getHashDigest());
            X9ECParameters params = SECNamedCurves.getByName(this.curveName);
            ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                    params.getH());

            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA512Digest()));
            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(((ECPrivateKey) privateKey).getS(), ecParams);
            signer.init(true, privKey);
            BigInteger[] sigs = signer.generateSignature(encoded);
            return new byte[][]{sigs[0].toString().getBytes(), sigs[1].toString().getBytes()};
        } catch (Exception e) {
            throw new CryptoException("Could not sign the message using private key", e);
        }

    }

    /**
     * ecdsaSignToBytes - sign to bytes
     *
     * @param privateKey private key.
     * @param data       data to sign
     * @return
     * @throws CryptoException
     */

    public byte[] ecdsaSignToBytes(PrivateKey privateKey, byte[] data) throws CryptoException {
        try {
            byte[] encoded = data;
            encoded = SDKUtil.hash(data, getHashDigest());

//            char[] hexenncoded = Hex.encodeHex(encoded);
//            encoded = new String(hexenncoded).getBytes();

            X9ECParameters params = NISTNamedCurves.getByName(this.curveName);
            BigInteger curve_N = params.getN();

            ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), curve_N,
                    params.getH());


            ECDSASigner signer = new ECDSASigner();

            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(((ECPrivateKey) privateKey).getS(), ecParams);
            signer.init(true, privKey);
            BigInteger[] sigs = signer.generateSignature(encoded);

            sigs = preventMalleability(sigs, curve_N);


            ByteArrayOutputStream s = new ByteArrayOutputStream();

            DERSequenceGenerator seq = new DERSequenceGenerator(s);
            seq.addObject(new ASN1Integer(sigs[0]));
            seq.addObject(new ASN1Integer(sigs[1]));
            seq.close();
            byte[] ret = s.toByteArray();
            return ret;


        } catch (Exception e) {
            throw new CryptoException("Could not sign the message using private key", e);
        }

    }
    
    public static byte[] sign(PrivateKey key, byte[] data) throws CryptoException {
    	byte[] signature ;
    	
    	if (key == null || data == null)
    		throw new CryptoException("Could not sign. Key or plain text is null", new NullPointerException());
    	
    	try {
			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
			sig.initSign(key);
			sig.update(data);
			signature = sig.sign();
			
			// TODO see if BouncyCastle handles sig malleability already under the covers
			
			return signature ;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("Could not sign the message.", e);
		} 
    	
    } // sign

    private BigInteger[] preventMalleability(BigInteger[] sigs, BigInteger curve_n) {
        BigInteger cmpVal = curve_n.divide(BigInteger.valueOf(2l));

        BigInteger sval = sigs[1];

        if(sval.compareTo(cmpVal) == 1){

          sigs[1] = curve_n.subtract(sval);
        }


        return sigs;
    }



    /**
     * generateCertificationRequest
     *
     * @param subject The subject to be added to the certificate
     * @param pair    Public private key pair
     * @return PKCS10CertificationRequest Certificate Signing Request.
     * @throws OperatorCreationException
     */

    public PKCS10CertificationRequest generateCertificationRequest(String subject, KeyPair pair) throws OperatorCreationException {

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=" + subject), pair.getPublic());

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withECDSA");

        //    csBuilder.setProvider("EC");
        ContentSigner signer = csBuilder.build(pair.getPrivate());

        return p10Builder.build(signer);
    }

    /**
     * certificationRequestToPEM - Convert a PKCS10CertificationRequest to PEM format.
     *
     * @param csr The Certificate to convert
     * @return An equivalent PEM format certificate.
     * @throws IOException
     */

    public String certificationRequestToPEM(PKCS10CertificationRequest csr) throws IOException {
        PemObject pemCSR = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());

        StringWriter str = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(str);
        pemWriter.writeObject(pemCSR);
        pemWriter.close();
        str.close();
        return str.toString();
    }


    public PrivateKey ecdsaKeyFromPrivate(byte[] key) throws CryptoException {
        try {
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory generator = KeyFactory.getInstance("ECDSA", SECURITY_PROVIDER);
            PrivateKey privateKey = generator.generatePrivate(privateKeySpec);

            return privateKey;
        } catch (Exception exp) {
            throw new CryptoException("Unable to convert byte[] into PrivateKey", exp);
        }
    }

    public byte[] hash(byte[] input) {
        Digest digest = getHashDigest();
        byte[] retValue = new byte[digest.getDigestSize()];
        digest.update(input, 0, input.length);
        digest.doFinal(retValue, 0);
        return retValue;
    }

    private void init() {
        if (securityLevel != 256 && securityLevel != 384) {
            throw new RuntimeException("Illegal level: " + securityLevel + " must be either 256 or 384");
        }
        if (StringUtil.isNullOrEmpty(this.hashAlgorithm)
                || !(this.hashAlgorithm.equalsIgnoreCase("SHA2") || this.hashAlgorithm.equalsIgnoreCase("SHA3"))) {
            throw new RuntimeException(
                    "Illegal Hash function family: " + this.hashAlgorithm + " - must be either SHA2 or SHA3");
        }

        // this.suite = this.algorithm.toLowerCase() + '-' + this.securityLevel;
        if (this.securityLevel == 256) {
            this.curveName = "P-256"; //Curve that is currently used by FAB services.
            //TODO: HashOutputSize=32 ?
        } else if (this.securityLevel == 384) {
            this.curveName = "secp384r1";
            //TODO: HashOutputSize=48 ?
        }
    }

    private Digest getHashDigest() {
        if (this.hashAlgorithm.equalsIgnoreCase("SHA3")) {
            return new SHA3Digest();
        } else if (this.hashAlgorithm.equalsIgnoreCase("SHA2")) {
            return new SHA256Digest();
        }

        return new SHA256Digest(); // default Digest?
    }

    /**
     * shake256 do shake256 hashing
     *
     * @param in        byte array to be hashed.
     * @param bitLength of the result.
     * @return
     */
    public byte[] shake256(byte[] in, int bitLength) {


        if (bitLength % 8 != 0) {
            throw new IllegalArgumentException("bit length not modulo 8");

        }

        final int byteLen = bitLength / 8;


        SHAKEDigest sd = new SHAKEDigest(256);

        sd.update(in, 0, in.length);

        byte[] out = new byte[byteLen];

        sd.doFinal(out, 0, byteLen);

        return out;

    }

}
