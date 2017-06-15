/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.security;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;
import java.util.Properties;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;

public class CryptoPrimitives implements CryptoSuite {
    private final Config config = Config.getConfig();

    private String curveName;
    private CertificateFactory cf;
    private final String SECURITY_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    private String hashAlgorithm = config.getHashAlgorithm();
    private int securityLevel = config.getSecurityLevel();
    private String CERTIFICATE_FORMAT = config.getCertificateFormat();
    private String DEFAULT_SIGNATURE_ALGORITHM = config.getSignatureAlgorithm();

    // Following configuration settings are hardcoded as they don't deal with any interactions with Fabric MSP and BCCSP components
    // If you wish to make these customizable, follow the logic from setProperties();
    //TODO May need this for TCERTS ?
//    private String ASYMMETRIC_KEY_TYPE = "EC";
//    private String KEY_AGREEMENT_ALGORITHM = "ECDH";
//    private String SYMMETRIC_KEY_TYPE = "AES";
//    private int SYMMETRIC_KEY_BYTE_COUNT = 32;
//    private String SYMMETRIC_ALGORITHM = "AES/CFB/NoPadding";
//    private int MAC_KEY_BYTE_COUNT = 32;

    private static final Log logger = LogFactory.getLog(CryptoPrimitives.class);

    public CryptoPrimitives() {
        Security.addProvider(new BouncyCastleProvider());
    }

//    /**
//     * sets the signature algorithm used for signing/verifying.
//     *
//     * @param sigAlg the name of the signature algorithm. See the list of valid names in the JCA Standard Algorithm Name documentation
//     */
//    public void setSignatureAlgorithm(String sigAlg) {
//        this.DEFAULT_SIGNATURE_ALGORITHM = sigAlg;
//    }

//    /**
//     * returns the signature algorithm used by this instance of CryptoPrimitives.
//     * Note that fabric and fabric-ca have not yet standardized on which algorithms are supported.
//     * While that plays out, CryptoPrimitives will try the algorithm specified in the certificate and
//     * the default SHA256withECDSA that's currently hardcoded for fabric and fabric-ca
//     *
//     * @return the name of the signature algorithm
//     */
//    public String getSignatureAlgorithm() {
//        return this.DEFAULT_SIGNATURE_ALGORITHM;
//    }

    public Certificate bytesToCertificate(byte[] certBytes) throws CryptoException {
        if (certBytes == null || certBytes.length == 0) {
            throw new CryptoException("bytesToCertificate: input null or zero length");
        }

        X509Certificate certificate;
        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certBytes));
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            certificate = (X509Certificate) certFactory.generateCertificate(pem);
        } catch (CertificateException e) {
            String emsg = "Unable to converts byte array to certificate. error : " + e.getMessage();
            logger.error(emsg);
            logger.debug("input bytes array :" + new String(certBytes));
            throw new CryptoException(emsg, e);
        }

        return certificate;
    }

    /**
     * @inheritDoc
     */

    @Override
    public boolean verify(byte[] pemCertificate, String signatureAlgorithm, byte[] signature, byte[] plainText) throws CryptoException {
        boolean isVerified;

        if (plainText == null || signature == null || pemCertificate == null) {
            return false;
        }

        if (config.extraLogLevel(10)) {

            logger.trace("plaintext in hex: " + DatatypeConverter.printHexBinary(plainText));
            logger.trace("signature in hex: " + DatatypeConverter.printHexBinary(signature));
            logger.trace("PEM cert in hex: " + DatatypeConverter.printHexBinary(pemCertificate));

        }

        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(pemCertificate));
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);

            isVerified = validateCertificate(certificate);
            if (isVerified) { // only proceed if cert is trusted

                Signature sig = Signature.getInstance(signatureAlgorithm);
                sig.initVerify(certificate);
                sig.update(plainText);
                isVerified = sig.verify(signature);
            }
        } catch (InvalidKeyException | CertificateException e) {
            CryptoException ex = new CryptoException("Cannot verify signature. Error is: "
                    + e.getMessage() + "\r\nCertificate: "
                    + DatatypeConverter.printHexBinary(pemCertificate), e);
            logger.error(ex.getMessage(), ex);
            throw ex;
        } catch (NoSuchAlgorithmException | SignatureException e) {
            CryptoException ex = new CryptoException("Cannot verify. Signature algorithm is invalid. Error is: " + e.getMessage(), e);
            logger.error(ex.getMessage(), ex);
            throw ex;
        }

        return isVerified;
    } // verify

    private KeyStore trustStore = null;

    private void createTrustStore() throws CryptoException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            setTrustStore(keyStore);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | InvalidArgumentException e) {
            throw new CryptoException("Cannot create trust store. Error: " + e.getMessage(), e);
        }
    }

    /**
     * setTrustStore uses the given KeyStore object as the container for trusted
     * certificates
     *
     * @param keyStore the KeyStore which will be used to hold trusted certificates
     * @throws InvalidArgumentException
     */
    void setTrustStore(KeyStore keyStore) throws InvalidArgumentException {

        if (keyStore == null) {
            throw new InvalidArgumentException("Need to specify a java.security.KeyStore input parameter");
        }

        trustStore = keyStore;
    }

    /**
     * getTrustStore returns the KeyStore object where we keep trusted certificates.
     * If no trust store has been set, this method will create one.
     *
     * @return the trust store as a java.security.KeyStore object
     * @throws CryptoException
     * @see KeyStore
     */
    public KeyStore getTrustStore() throws CryptoException {
        if (trustStore == null) {
            createTrustStore();
        }
        return trustStore;
    }

    /**
     * addCACertificateToTrustStore adds a CA cert to the set of certificates used for signature validation
     *
     * @param caCertPem an X.509 certificate in PEM format
     * @param alias     an alias associated with the certificate. Used as shorthand for the certificate during crypto operations
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    public void addCACertificateToTrustStore(File caCertPem, String alias) throws CryptoException, InvalidArgumentException {

        if (caCertPem == null) {
            throw new InvalidArgumentException("The certificate cannot be null");
        }

        if (alias == null || alias.isEmpty()) {
            throw new InvalidArgumentException("You must assign an alias to a certificate when adding to the trust store");
        }


        BufferedInputStream bis;
        try {

            bis = new BufferedInputStream(new ByteArrayInputStream(FileUtils.readFileToByteArray(caCertPem)));
            Certificate caCert = cf.generateCertificate(bis);
            this.addCACertificateToTrustStore(caCert, alias);
        } catch (CertificateException | IOException e) {
            throw new CryptoException("Unable to add CA certificate to trust store. Error: " + e.getMessage(), e);
        }
    }

    /**
     * addCACertificateToTrustStore adds a CA cert to the set of certificates used for signature validation
     *
     * @param caCert an X.509 certificate
     * @param alias  an alias associated with the certificate. Used as shorthand for the certificate during crypto operations
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    void addCACertificateToTrustStore(Certificate caCert, String alias) throws InvalidArgumentException, CryptoException {

        if (alias == null || alias.isEmpty()) {
            throw new InvalidArgumentException("You must assign an alias to a certificate when adding to the trust store.");
        }
        if (caCert == null) {
            throw new InvalidArgumentException("Certificate cannot be null.");
        }

        try {
            if (config.extraLogLevel(10)) {
                logger.trace("Adding cert to trust store. alias:  " + alias + "cert: " + caCert.toString());
            }
            getTrustStore().setCertificateEntry(alias, caCert);
        } catch (KeyStoreException e) {
            String emsg = "Unable to add CA certificate to trust store. Error: " + e.getMessage();
            logger.error(emsg, e);
            throw new CryptoException(emsg, e);
        }
    }

    @Override
    public void loadCACertificates(Collection<Certificate> certificates) throws CryptoException {
        if (certificates == null || certificates.size() == 0) {
            throw new CryptoException("Unable to load CA certificates. List is empty");
        }

        try {
            for (Certificate cert : certificates) {
                addCACertificateToTrustStore(cert, Integer.toString(cert.hashCode()));
            }
        } catch (InvalidArgumentException e) {
            // Note: This can currently never happen (as cert<>null and alias<>null)
            throw new CryptoException("Unable to add certificate to trust store. Error: " + e.getMessage(), e);
        }
    }

    /* (non-Javadoc)
     * @see org.hyperledger.fabric.sdk.security.CryptoSuite#loadCACertificatesAsBytes(java.util.Collection)
     */
    @Override
    public void loadCACertificatesAsBytes(Collection<byte[]> certificatesBytes) throws CryptoException {
        if (certificatesBytes == null || certificatesBytes.size() == 0) {
            throw new CryptoException("List of CA certificates is empty. Nothing to load.");
        }
        ArrayList<Certificate> certList = new ArrayList<>();
        for (byte[] certBytes : certificatesBytes) {
            logger.trace("certificate to load:\n" + new String(certBytes));
            certList.add(bytesToCertificate(certBytes));
        }
        loadCACertificates(certList);
    }

    /**
     * validateCertificate checks whether the given certificate is trusted. It
     * checks if the certificate is signed by one of the trusted certs in the
     * trust store.
     *
     * @param certPEM the certificate in PEM format
     * @return true if the certificate is trusted
     */
    boolean validateCertificate(byte[] certPEM) {

        if (certPEM == null) {
            return false;
        }

        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certPEM));
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);
            return validateCertificate(certificate);
        } catch (CertificateException e) {
            logger.error("Cannot validate certificate. Error is: " + e.getMessage() + "\r\nCertificate (PEM, hex): "
                    + DatatypeConverter.printHexBinary(certPEM));
            return false;
        }
    }

    boolean validateCertificate(Certificate cert) {
        boolean isValidated;

        if (cert == null) {
            return false;
        }

        try {
            KeyStore keyStore = getTrustStore();

            PKIXParameters parms = new PKIXParameters(keyStore);
            parms.setRevocationEnabled(false);

            CertPathValidator certValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType()); // PKIX

            ArrayList<Certificate> start = new ArrayList<>();
            start.add(cert);
            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
            CertPath certPath = certFactory.generateCertPath(start);

            certValidator.validate(certPath, parms);
            isValidated = true;
        } catch (KeyStoreException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
                | CertificateException | CertPathValidatorException | CryptoException e) {
            logger.error("Cannot validate certificate. Error is: " + e.getMessage() + "\r\nCertificate"
                    + cert.toString());
            isValidated = false;
        }

        return isValidated;
    } // validateCertificate

    /**
     * Security Level determines the elliptic curve used in key generation
     *
     * @param securityLevel currently 256 or 384
     * @throws InvalidArgumentException
     */
    void setSecurityLevel(int securityLevel) throws InvalidArgumentException {
        if (securityLevel != 256 && securityLevel != 384) {
            throw new InvalidArgumentException("Illegal level: " + securityLevel + " must be either 256 or 384");
        }

        // TODO need to get set of supported curves from #fabric-crypto team
        if (this.securityLevel == 256) {
            this.curveName = "P-256";
        } else if (this.securityLevel == 384) {
            this.curveName = "secp384r1";
        }
    }

    void setHashAlgorithm(String algorithm) throws InvalidArgumentException {
        if (Utils.isNullOrEmpty(algorithm)
                || !(algorithm.equalsIgnoreCase("SHA2") || algorithm.equalsIgnoreCase("SHA3"))) {
            throw new InvalidArgumentException("Illegal Hash function family: "
                    + this.hashAlgorithm + " - must be either SHA2 or SHA3");
        }

        this.hashAlgorithm = algorithm;
    }

    @Override
    public KeyPair keyGen() throws CryptoException {
        return ecdsaKeyGen();
    }

    private KeyPair ecdsaKeyGen() throws CryptoException {
        return generateKey("ECDSA", this.curveName);
    }

    private KeyPair generateKey(String encryptionName, String curveName) throws CryptoException {
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);
            KeyPairGenerator g = KeyPairGenerator.getInstance(encryptionName, SECURITY_PROVIDER);
            g.initialize(ecGenSpec, new SecureRandom());
            return g.generateKeyPair();
        } catch (Exception exp) {
            throw new CryptoException("Unable to generate key pair", exp);
        }
    }

//    public String encodePublicKey(PublicKey pk) {
//        return Hex.toHexString(pk.getEncoded());
//    }
//
//    public PublicKey decodePublicKey(String data) throws CryptoException {
//        try {
//            logger.debug("input encoded public key: " + data);
//            KeyFactory asymmetricKeyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE, SECURITY_PROVIDER);
//            X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(Hex.decode(data));
//            return asymmetricKeyFactory.generatePublic(pubX509);
//        } catch (Exception e) {
//            String emsg = "Failed to decode public key: " + data + ". error : " + e.getMessage();
//            logger.error(emsg);
//            throw new CryptoException(emsg, e);
//        }
//    }

//    public byte[] eciesDecrypt(KeyPair keyPair, byte[] data) throws CryptoException {
//        try {
//            int ephemeralKeyLength = (int) (Math.floor((this.securityLevel + 7) / 8) * 2 + 1);
//            int mkLen = this.securityLevel >> 3;
//            int encryptedMessageLength = data.length - ephemeralKeyLength - mkLen;
//
//            byte[] ephemeralPublicKeyBytes = Arrays.copyOfRange(data, 0, ephemeralKeyLength);
//            byte[] encryptedMessage = Arrays.copyOfRange(data, ephemeralKeyLength, ephemeralKeyLength + encryptedMessageLength);
//            byte[] tag = Arrays.copyOfRange(data, ephemeralKeyLength + encryptedMessageLength, data.length);
//
//            // Parsing public key.
//            ECParameterSpec asymmetricKeyParams = generateECParameterSpec();
//            KeyFactory asymmetricKeyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE, SECURITY_PROVIDER);
//
//            PublicKey ephemeralPublicKey = asymmetricKeyFactory.generatePublic(new ECPublicKeySpec(
//                    asymmetricKeyParams.getCurve().decodePoint(ephemeralPublicKeyBytes), asymmetricKeyParams));
//
//            // Deriving shared secret.
//            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, SECURITY_PROVIDER);
//            keyAgreement.init(keyPair.getPrivate());
//            keyAgreement.doPhase(ephemeralPublicKey, true);
//            byte[] sharedSecret = keyAgreement.generateSecret();
//
//            // Deriving encryption and mac keys.
//            HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(getHashDigest());
//
//            hkdfBytesGenerator.init(new HKDFParameters(sharedSecret, null, null));
//            byte[] encryptionKey = new byte[SYMMETRIC_KEY_BYTE_COUNT];
//            hkdfBytesGenerator.generateBytes(encryptionKey, 0, SYMMETRIC_KEY_BYTE_COUNT);
//
//            byte[] macKey = new byte[MAC_KEY_BYTE_COUNT];
//            hkdfBytesGenerator.generateBytes(macKey, 0, MAC_KEY_BYTE_COUNT);
//
//            // Verifying Message Authentication Code (aka mac/tag)
//            byte[] expectedTag = calculateMac(macKey, encryptedMessage);
//            if (!Arrays.areEqual(tag, expectedTag)) {
//                throw new RuntimeException("Bad Message Authentication Code!");
//            }
//
//            // Decrypting the message.
//            byte[] iv = Arrays.copyOfRange(encryptedMessage, 0, 16);
//            byte[] encrypted = Arrays.copyOfRange(encryptedMessage, 16, encryptedMessage.length);
//            byte[] output = aesDecrypt(encryptionKey, iv, encrypted);
//
//            return output;
//
//        } catch (Exception e) {
//            throw new CryptoException("Could not decrypt the message", e);
//        }
//
//    }

//    private byte[] calculateMac(byte[] macKey, byte[] encryptedMessage)
//            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
//        HMac hmac = new HMac(getHashDigest());
//        hmac.init(new KeyParameter(macKey));
//        hmac.update(encryptedMessage, 0, encryptedMessage.length);
//        byte[] out = new byte[MAC_KEY_BYTE_COUNT];
//        hmac.doFinal(out, 0);
//        return out;
//    }
//
//    private byte[] aesDecrypt(byte[] encryptionKey, byte[] iv, byte[] encryptedMessage)
//            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
//            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
//
//        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, SYMMETRIC_KEY_TYPE), new IvParameterSpec(iv));
//        return cipher.doFinal(encryptedMessage);
//
//    }
//
//    private ECNamedCurveParameterSpec generateECParameterSpec() {
//        ECNamedCurveParameterSpec bcParams = ECNamedCurveTable.getParameterSpec(this.curveName);
//        return bcParams;
//    }
//
//    public byte[][] ecdsaSign(PrivateKey privateKey, byte[] data) throws CryptoException {
//        try {
//            byte[] encoded = hash(data);
//            X9ECParameters params = SECNamedCurves.getByName(this.curveName);
//            ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
//                    params.getH());
//
//            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA512Digest()));
//            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(((ECPrivateKey) privateKey).getS(), ecParams);
//            signer.init(true, privKey);
//            BigInteger[] sigs = signer.generateSignature(encoded);
//            return new byte[][] {sigs[0].toString().getBytes(UTF_8), sigs[1].toString().getBytes(UTF_8)};
//        } catch (Exception e) {
//            throw new CryptoException("Could not sign the message using private key", e);
//        }
//
//    }

    /**
     * Sign data with the specified elliptic curve private key.
     *
     * @param privateKey elliptic curve private key.
     * @param data       data to sign
     * @return the signed data.
     * @throws CryptoException
     */
    private byte[] ecdsaSignToBytes(ECPrivateKey privateKey, byte[] data) throws CryptoException {
        try {
            final byte[] encoded = hash(data);

            // char[] hexenncoded = Hex.encodeHex(encoded);
            // encoded = new String(hexenncoded).getBytes();

            X9ECParameters params = NISTNamedCurves.getByName(this.curveName);
            BigInteger curveN = params.getN();

            ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), curveN,
                    params.getH());

            ECDSASigner signer = new ECDSASigner();

            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKey.getS(), ecParams);
            signer.init(true, privKey);
            BigInteger[] sigs = signer.generateSignature(encoded);

            sigs = preventMalleability(sigs, curveN);

            ByteArrayOutputStream s = new ByteArrayOutputStream();

            DERSequenceGenerator seq = new DERSequenceGenerator(s);
            seq.addObject(new ASN1Integer(sigs[0]));
            seq.addObject(new ASN1Integer(sigs[1]));
            seq.close();
            return s.toByteArray();

        } catch (Exception e) {
            throw new CryptoException("Could not sign the message using private key", e);
        }

    }

    /**
     * @throws ClassCastException if the supplied private key is not of type {@link ECPrivateKey}.
     */
    @Override
    public byte[] sign(PrivateKey key, byte[] data) throws CryptoException {
        return ecdsaSignToBytes((ECPrivateKey) key, data);
    }
    /*
     *  code for signing using JCA/JSSE methods only .  Still needed ?
    public byte[] sign(PrivateKey key, byte[] data) throws CryptoException {
        byte[] signature;

        if (key == null || data == null)
            throw new CryptoException("Could not sign. Key or plain text is null", new NullPointerException());

        try {
            Signature sig = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);
            sig.initSign(key);
            sig.update(data);
            signature = sig.sign();

            // TODO see if BouncyCastle handles sig malleability already under
            // the covers

            return signature;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("Could not sign the message.", e);
        }

    }
    */

    private BigInteger[] preventMalleability(BigInteger[] sigs, BigInteger curveN) {
        BigInteger cmpVal = curveN.divide(BigInteger.valueOf(2L));

        BigInteger sval = sigs[1];

        if (sval.compareTo(cmpVal) == 1) {

            sigs[1] = curveN.subtract(sval);
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

    public PKCS10CertificationRequest generateCertificationRequest(String subject, KeyPair pair)
            throws OperatorCreationException {

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=" + subject), pair.getPublic());

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withECDSA");

        // csBuilder.setProvider("EC");
        ContentSigner signer = csBuilder.build(pair.getPrivate());

        return p10Builder.build(signer);
    }

    /**
     * certificationRequestToPEM - Convert a PKCS10CertificationRequest to PEM
     * format.
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

//    public PrivateKey ecdsaKeyFromPrivate(byte[] key) throws CryptoException {
//        try {
//            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
//            KeyFactory generator = KeyFactory.getInstance("ECDSA", SECURITY_PROVIDER);
//            PrivateKey privateKey = generator.generatePrivate(privateKeySpec);
//
//            return privateKey;
//        } catch (Exception exp) {
//            throw new CryptoException("Unable to convert byte[] into PrivateKey", exp);
//        }
//    }

    @Override
    public byte[] hash(byte[] input) {
        Digest digest = getHashDigest();
        byte[] retValue = new byte[digest.getDigestSize()];
        digest.update(input, 0, input.length);
        digest.doFinal(retValue, 0);
        return retValue;
    }

    @Override
    public void init() throws CryptoException, InvalidArgumentException {
        resetConfiguration();
    }

    private Digest getHashDigest() {
        if (this.hashAlgorithm.equalsIgnoreCase("SHA3")) {
            return new SHA3Digest();
        } else {
            // Default to SHA2
            return new SHA256Digest();
        }
    }

//    /**
//     * Shake256 hash the supplied byte data.
//     *
//     * @param in        byte array to be hashed.
//     * @param bitLength of the result.
//     * @return the hashed byte data.
//     */
//    public byte[] shake256(byte[] in, int bitLength) {
//
//        if (bitLength % 8 != 0) {
//            throw new IllegalArgumentException("bit length not modulo 8");
//
//        }
//
//        final int byteLen = bitLength / 8;
//
//        SHAKEDigest sd = new SHAKEDigest(256);
//
//        sd.update(in, 0, in.length);
//
//        byte[] out = new byte[byteLen];
//
//        sd.doFinal(out, 0, byteLen);
//
//        return out;
//
//    }

    /**
     * Resets curve name, hash algorithm and cert factory. Call this method when a config value changes
     *
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    private void resetConfiguration() throws CryptoException, InvalidArgumentException {

        this.setSecurityLevel(this.securityLevel);

        this.setHashAlgorithm(this.hashAlgorithm);

        try {
            cf = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
        } catch (CertificateException e) {
            CryptoException ex = new CryptoException("Cannot initialize " + CERTIFICATE_FORMAT + " certificate factory. Error = " + e.getMessage(), e);
            logger.error(ex.getMessage(), ex);
            throw ex;
        }
    }

    /* (non-Javadoc)
     * @see org.hyperledger.fabric.sdk.security.CryptoSuite#setProperties(java.util.Properties)
     */
    @Override
    public void setProperties(Properties properties) throws CryptoException, InvalidArgumentException {
        if (properties != null) {
            hashAlgorithm = Optional.ofNullable(properties.getProperty(Config.HASH_ALGORITHM)).orElse(hashAlgorithm);
            String secLevel = Optional.ofNullable(properties.getProperty(Config.SECURITY_LEVEL)).orElse(Integer.toString(securityLevel));
            securityLevel = Integer.parseInt(secLevel);
            CERTIFICATE_FORMAT = Optional.ofNullable(properties.getProperty(Config.CERTIFICATE_FORMAT)).orElse(CERTIFICATE_FORMAT);
            DEFAULT_SIGNATURE_ALGORITHM = Optional.ofNullable(properties.getProperty(Config.SIGNATURE_ALGORITHM)).orElse(DEFAULT_SIGNATURE_ALGORITHM);

            resetConfiguration();
        }
    }

    /* (non-Javadoc)
     * @see org.hyperledger.fabric.sdk.security.CryptoSuite#getProperties()
     */
    @Override
    public Properties getProperties() {
        Properties properties = new Properties();
        properties.setProperty(Config.HASH_ALGORITHM, hashAlgorithm);
        properties.setProperty(Config.SECURITY_LEVEL, Integer.toString(securityLevel));
        properties.setProperty(Config.CERTIFICATE_FORMAT, CERTIFICATE_FORMAT);
        properties.setProperty(Config.SIGNATURE_ALGORITHM, DEFAULT_SIGNATURE_ALGORITHM);
        return properties;
    }

    public byte[] certificateToDER(String certificatePEM) {

        byte[] content = null;

        try (PemReader pemReader = new PemReader(new StringReader(certificatePEM))) {
            final PemObject pemObject = pemReader.readPemObject();
            content = pemObject.getContent();

        } catch (IOException e) {
            // best attempt
        }

        return content;
    }

}
