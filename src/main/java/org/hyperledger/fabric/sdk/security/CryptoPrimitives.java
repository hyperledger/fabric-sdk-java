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
import java.security.Provider;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;

public class CryptoPrimitives implements CryptoSuite {
    private static final Log logger = LogFactory.getLog(CryptoPrimitives.class);
    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    private static final Config config = Config.getConfig();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;

    private String curveName;
    private CertificateFactory cf;
    private Provider SECURITY_PROVIDER;
    private String hashAlgorithm = config.getHashAlgorithm();
    private int securityLevel = config.getSecurityLevel();
    private String CERTIFICATE_FORMAT = config.getCertificateFormat();
    private String DEFAULT_SIGNATURE_ALGORITHM = config.getSignatureAlgorithm();

    private Map<Integer, String> securityCurveMapping = config.getSecurityCurveMapping();

    // Following configuration settings are hardcoded as they don't deal with any interactions with Fabric MSP and BCCSP components
    // If you wish to make these customizable, follow the logic from setProperties();
    //TODO May need this for TCERTS ?
//    private String ASYMMETRIC_KEY_TYPE = "EC";
//    private String KEY_AGREEMENT_ALGORITHM = "ECDH";
//    private String SYMMETRIC_KEY_TYPE = "AES";
//    private int SYMMETRIC_KEY_BYTE_COUNT = 32;
//    private String SYMMETRIC_ALGORITHM = "AES/CFB/NoPadding";
//    private int MAC_KEY_BYTE_COUNT = 32;

    public CryptoPrimitives() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        String securityProviderClassName = config.getSecurityProviderClassName();

        SECURITY_PROVIDER = setUpExplicitProvider(securityProviderClassName);

        //Decided TO NOT do this as it can have affects over the whole JVM and could have
        // unexpected results.  The embedding application can easily do this!
        // Leaving this here as a warning.
        // Security.insertProviderAt(SECURITY_PROVIDER, 1); // 1 is top not 0 :)
    }

    Provider setUpExplicitProvider(String securityProviderClassName) throws InstantiationException, ClassNotFoundException, IllegalAccessException {
        if (null == securityProviderClassName) {
            throw new InstantiationException(format("Security provider class name property (%s) set to null  ", Config.SECURITY_PROVIDER_CLASS_NAME));
        }

        if (CryptoSuiteFactory.DEFAULT_JDK_PROVIDER.equals(securityProviderClassName)) {
            return null;
        }

        Class<?> aClass = Class.forName(securityProviderClassName);
        if (!Provider.class.isAssignableFrom(aClass)) {
            throw new InstantiationException(format("Class for security provider %s is not a Java security provider", aClass.getName()));
        }
        Provider securityProvider = (Provider) aClass.newInstance();
        return securityProvider;
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

        return getX509Certificate(certBytes);
//        X509Certificate certificate;
//        try {
//            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(certBytes));
//            CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
//            certificate = (X509Certificate) certFactory.generateCertificate(pem);
//        } catch (CertificateException e) {
//            String emsg = "Unable to converts byte array to certificate. error : " + e.getMessage();
//            logger.error(emsg);
//            logger.debug("input bytes array :" + new String(certBytes));
//            throw new CryptoException(emsg, e);
//        }
//
//        return certificate;
    }

    /**
     * Return X509Certificate  from pem bytes.
     * So you may ask why this ?  Well some providers (BC) seems to have problems with creating the
     * X509 cert from bytes so here we go through all available providers till one can convert. :)
     *
     * @param pemCertificate
     * @return
     */
    private X509Certificate getX509CertificateInternal(byte[] pemCertificate) throws CryptoException {
        X509Certificate ret = null;
        CryptoException rete = null;

        List<Provider> providerList = new LinkedList<>(Arrays.asList(Security.getProviders()));
        if (SECURITY_PROVIDER != null) {
            // Add if overridden. Note it is added to the end of the provider list so is only invoked if all other providers fail.
            providerList.add(SECURITY_PROVIDER);
        }

        providerList.add(BOUNCY_CASTLE_PROVIDER);

        for (Provider provider : providerList) {
            try {
                if (null == provider) {
                   continue;
                }
                CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_FORMAT, provider);
                try (ByteArrayInputStream bis = new ByteArrayInputStream(pemCertificate)) {
                    Certificate certificate = certFactory.generateCertificate(bis);

                    if (certificate instanceof X509Certificate) {
                        ret = (X509Certificate) certificate;
                        rete = null;
                        break;
                    }
                }
            } catch (Exception e) {
                rete = new CryptoException(e.getMessage(), e);
            }
        }

        if (null != rete) {
            throw rete;
        }

        if (ret == null) {
            logger.error("Could not convert pem bytes");
        }

        return ret;
    }

    private X509Certificate getX509Certificate(byte[] pemCertificate) throws CryptoException {
        return getCertificateValue(pemCertificate).getX509();
    }

    /**
     * Return PrivateKey  from pem bytes.
     *
     * @param pemKey pem-encoded private key
     * @return
     */
    public PrivateKey bytesToPrivateKey(byte[] pemKey) throws CryptoException {
        PrivateKey pk;

        try {
            PemReader pr = new PemReader(new StringReader(new String(pemKey)));
            PemObject po = pr.readPemObject();
            PEMParser pem = new PEMParser(new StringReader(new String(pemKey)));

            if (po.getType().equals("PRIVATE KEY")) {
                pk = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) pem.readObject());
            } else {
                logger.trace("Found private key with type " + po.getType());
                PEMKeyPair kp = (PEMKeyPair) pem.readObject();
                pk = new JcaPEMKeyConverter().getPrivateKey(kp.getPrivateKeyInfo());
            }
        } catch (Exception e) {
            throw new CryptoException("Failed to convert private key bytes", e);
        }
        return pk;
    }

    @Override
    public boolean verify(byte[] pemCertificate, String signatureAlgorithm, byte[] signature, byte[] plainText) throws CryptoException {
        boolean isVerified = false;

        if (plainText == null || signature == null || pemCertificate == null) {
            return false;
        }

        if (config.extraLogLevel(10)) {
            if (null != diagnosticFileDumper) {
                String message = "plaintext in hex: " + DatatypeConverter.printHexBinary(plainText) + '\n' +
                        "signature in hex: " + DatatypeConverter.printHexBinary(signature) + '\n' +
                        "PEM cert in hex: " + DatatypeConverter.printHexBinary(pemCertificate);
                logger.trace("verify :  " +
                        diagnosticFileDumper.createDiagnosticFile(message));
            }
        }

        X509Certificate certificate = getValidCertificate(pemCertificate);

        try {
            if (certificate != null) {
                Signature sig = Signature.getInstance(signatureAlgorithm);
                sig.initVerify(certificate);
                sig.update(plainText);
                isVerified = sig.verify(signature);
            }
        } catch (InvalidKeyException e) {
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
    private void setTrustStore(KeyStore keyStore) throws InvalidArgumentException {

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

        try {
            try (BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(FileUtils.readFileToByteArray(caCertPem)))) {

                Certificate caCert = cf.generateCertificate(bis);
                addCACertificateToTrustStore(caCert, alias);
            }
        } catch (CertificateException | IOException e) {
            throw new CryptoException("Unable to add CA certificate to trust store. Error: " + e.getMessage(), e);
        }

    }

    /**
     * addCACertificatesToTrustStore adds a CA certs in a stream to the trust store  used for signature validation
     *
     * @param bis an X.509 certificate stream in PEM format in bytes
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    public void addCACertificatesToTrustStore(BufferedInputStream bis) throws CryptoException, InvalidArgumentException {

        if (bis == null) {
            throw new InvalidArgumentException("The certificate stream bis cannot be null");
        }

        try {
            final Collection<? extends Certificate> certificates = cf.generateCertificates(bis);
            for (Certificate certificate : certificates) {
                addCACertificateToTrustStore(certificate);
            }

        } catch (CertificateException e) {
            throw new CryptoException("Unable to add CA certificate to trust store. Error: " + e.getMessage(), e);
        }
    }

    final Set<String> certificateSet = ConcurrentHashMap.newKeySet();

    private void addCACertificateToTrustStore(Certificate certificate) throws InvalidArgumentException, CryptoException {

        String alias;
        if (certificate instanceof X509Certificate) {
            alias = ((X509Certificate) certificate).getSerialNumber().toString();
        } else { // not likely ...
            alias = Integer.toString(certificate.hashCode());
        }
        addCACertificateToTrustStore(certificate, alias);
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
                if (null != diagnosticFileDumper) {
                    logger.trace(format("Adding cert to trust store. alias: %s. certificate:", alias) + diagnosticFileDumper.createDiagnosticFile(alias + "cert: " + caCert.toString()));
                }
            }
            synchronized (certificateSet) {
                if (certificateSet.contains(alias)) {
                    return;
                }

                getTrustStore().setCertificateEntry(alias, caCert);
                certificateSet.add(alias);

            }
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

                addCACertificateToTrustStore(cert);
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
            certList.add(bytesToCertificate(certBytes));
        }
        loadCACertificates(certList);

    }

    /**
     * Adds a CA certificate with a private key and password.
     *
     * @param clientKey the private key bytes input stream. Cannot be null.
     * @param clientCert the client certificate bytes input stream. Cannot be null.
     * @param clientKeyPassword the password as a String. Can be null.
     */
    public void addClientCACertificateToTrustStore(byte[] clientKey, byte[] clientCert, String clientKeyPassword) throws CryptoException, IllegalArgumentException {
        if (clientKey == null) {
            throw new IllegalArgumentException("Client key byte input stream is required.");
        }
        if (clientCert == null) {
            throw new IllegalArgumentException("Client certificate byte input stream is required.");
        }
        try {
            Certificate tlsClientCertificate = bytesToCertificate(clientCert);

            String alias;
            if (tlsClientCertificate instanceof X509Certificate) {
                alias = ((X509Certificate) tlsClientCertificate).getSerialNumber().toString();
            } else { // not likely ...
                alias = Integer.toString(tlsClientCertificate.hashCode());
            }
            char[] password = clientKeyPassword == null ? new char[0] : clientKeyPassword.toCharArray();

            getTrustStore().setKeyEntry(alias, bytesToPrivateKey(clientKey), password, new Certificate[] {tlsClientCertificate});
        } catch (KeyStoreException e) {
            throw new CryptoException("Unable to add client CA certificate to trust store.", e);
        }
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
            return x509Cache.get(new CertKey(certPEM)).isValid();
        } catch (ExecutionException | CryptoException e) {
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
    void setSecurityLevel(final int securityLevel) throws InvalidArgumentException {
        logger.trace(format("setSecurityLevel to %d", securityLevel));

        if (securityCurveMapping.isEmpty()) {
            throw new InvalidArgumentException("Security curve mapping has no entries.");
        }

        if (!securityCurveMapping.containsKey(securityLevel)) {
            StringBuilder sb = new StringBuilder();
            String sp = "";
            for (int x : securityCurveMapping.keySet()) {
                sb.append(sp).append(x);

                sp = ", ";

            }
            throw new InvalidArgumentException(format("Illegal security level: %d. Valid values are: %s", securityLevel, sb.toString()));
        }

        String lcurveName = securityCurveMapping.get(securityLevel);

        logger.debug(format("Mapped curve strength %d to %s", securityLevel, lcurveName));

        X9ECParameters params = ECNamedCurveTable.getByName(lcurveName);
        //Check if can match curve name to requested strength.
        if (params == null) {

            InvalidArgumentException invalidArgumentException = new InvalidArgumentException(
                    format("Curve %s defined for security strength %d was not found.", curveName, securityLevel));

            logger.error(invalidArgumentException);
            throw invalidArgumentException;

        }

        curveName = lcurveName;
        this.securityLevel = securityLevel;
    }

    void setHashAlgorithm(String algorithm) throws InvalidArgumentException {
        if (isNullOrEmpty(algorithm)
                || !("SHA2".equals(algorithm) || "SHA3".equals(algorithm))) {
            throw new InvalidArgumentException("Illegal Hash function family: "
                    + algorithm + " - must be either SHA2 or SHA3");
        }

        hashAlgorithm = algorithm;
    }

    @Override
    public KeyPair keyGen() throws CryptoException {
        return ecdsaKeyGen();
    }

    private KeyPair ecdsaKeyGen() throws CryptoException {
        return generateKey("EC", curveName);
    }

    private KeyPair generateKey(String encryptionName, String curveName) throws CryptoException {
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);
            KeyPairGenerator g = SECURITY_PROVIDER == null ? KeyPairGenerator.getInstance(encryptionName) :
                    KeyPairGenerator.getInstance(encryptionName, SECURITY_PROVIDER);
            g.initialize(ecGenSpec, new SecureRandom());
            return g.generateKeyPair();
        } catch (Exception exp) {
            throw new CryptoException("Unable to generate key pair", exp);
        }
    }

    /**
     * Decodes an ECDSA signature and returns a two element BigInteger array.
     *
     * @param signature ECDSA signature bytes.
     * @return BigInteger array for the signature's r and s values
     * @throws Exception
     */
    private static BigInteger[] decodeECDSASignature(byte[] signature) throws Exception {

        try (ByteArrayInputStream inStream = new ByteArrayInputStream(signature)) {
            ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
            ASN1Primitive asn1 = asnInputStream.readObject();

            BigInteger[] sigs = new BigInteger[2];
            int count = 0;
            if (asn1 instanceof ASN1Sequence) {
                ASN1Sequence asn1Sequence = (ASN1Sequence) asn1;
                ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
                for (ASN1Encodable asn1Encodable : asn1Encodables) {
                    ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
                    if (asn1Primitive instanceof ASN1Integer) {
                        ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
                        BigInteger integer = asn1Integer.getValue();
                        if (count < 2) {
                            sigs[count] = integer;
                        }
                        count++;
                    }
                }
            }
            if (count != 2) {
                throw new CryptoException(format("Invalid ECDSA signature. Expected count of 2 but got: %d. Signature is: %s", count,
                        DatatypeConverter.printHexBinary(signature)));
            }
            return sigs;
        }

    }

    /**
     * Sign data with the specified elliptic curve private key.
     *
     * @param privateKey elliptic curve private key.
     * @param data       data to sign
     * @return the signed data.
     * @throws CryptoException
     */
    private byte[] ecdsaSignToBytes(ECPrivateKey privateKey, byte[] data) throws CryptoException {
        if (data == null) {
            throw new CryptoException("Data that to be signed is null.");
        }
        if (data.length == 0) {
            throw new CryptoException("Data to be signed was empty.");
        }

        try {
            X9ECParameters params = ECNamedCurveTable.getByName(curveName);
            BigInteger curveN = params.getN();

            Signature sig = SECURITY_PROVIDER == null ? Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM) :
                    Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM, SECURITY_PROVIDER);
            sig.initSign(privateKey);
            sig.update(data);
            byte[] signature = sig.sign();

            BigInteger[] sigs = preventMalleability(decodeECDSASignature(signature), curveN);

            try (ByteArrayOutputStream s = new ByteArrayOutputStream()) {

                DERSequenceGenerator seq = new DERSequenceGenerator(s);
                seq.addObject(new ASN1Integer(sigs[0]));
                seq.addObject(new ASN1Integer(sigs[1]));
                seq.close();
                return s.toByteArray();
            }

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

    private BigInteger[] preventMalleability(BigInteger[] sigs, BigInteger curveN) {
        BigInteger cmpVal = curveN.divide(BigInteger.valueOf(2L));

        BigInteger sval = sigs[1];

        if (sval.compareTo(cmpVal) > 0) {

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

    public String generateCertificationRequest(String subject, KeyPair pair)
            throws InvalidArgumentException {

        try {
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Principal("CN=" + subject), pair.getPublic());

            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withECDSA");

            if (null != SECURITY_PROVIDER) {
                csBuilder.setProvider(SECURITY_PROVIDER);
            }
            ContentSigner signer = csBuilder.build(pair.getPrivate());

            return certificationRequestToPEM(p10Builder.build(signer));
        } catch (Exception e) {

            logger.error(e);
            throw new InvalidArgumentException(e);

        }

    }

    /**
     * certificationRequestToPEM - Convert a PKCS10CertificationRequest to PEM
     * format.
     *
     * @param csr The Certificate to convert
     * @return An equivalent PEM format certificate.
     * @throws IOException
     */

    private String certificationRequestToPEM(PKCS10CertificationRequest csr) throws IOException {
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
//            KeyFactory generator = KeyFactory.getInstance("ECDSA", SECURITY_PROVIDER_NAME);
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
    public CryptoSuiteFactory getCryptoSuiteFactory() {
        return HLSDKJCryptoSuiteFactory.instance(); //Factory for this crypto suite.
    }

    private final AtomicBoolean inited = new AtomicBoolean(false);

    // @Override
    public void init() throws CryptoException, InvalidArgumentException {
        if (inited.getAndSet(true)) {
            throw new InvalidArgumentException("Crypto suite already initialized");
        } else {
            resetConfiguration();
        }

    }

    private Digest getHashDigest() {
        if ("SHA3".equals(hashAlgorithm)) {
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

        setSecurityLevel(securityLevel);

        setHashAlgorithm(hashAlgorithm);

        try {
            cf = CertificateFactory.getInstance(CERTIFICATE_FORMAT);
        } catch (CertificateException e) {
            CryptoException ex = new CryptoException("Cannot initialize " + CERTIFICATE_FORMAT + " certificate factory. Error = " + e.getMessage(), e);
            logger.error(ex.getMessage(), ex);
            throw ex;
        }
    }

    //    /* (non-Javadoc)
//     * @see org.hyperledger.fabric.sdk.security.CryptoSuite#setProperties(java.util.Properties)
//     */
//    @Override
    void setProperties(Properties properties) throws CryptoException, InvalidArgumentException {
        if (properties == null) {
            throw new InvalidArgumentException("properties must not be null");
        }
        //        if (properties != null) {
        hashAlgorithm = Optional.ofNullable(properties.getProperty(Config.HASH_ALGORITHM)).orElse(hashAlgorithm);
        String secLevel = Optional.ofNullable(properties.getProperty(Config.SECURITY_LEVEL)).orElse(Integer.toString(securityLevel));
        securityLevel = Integer.parseInt(secLevel);
        if (properties.containsKey(Config.SECURITY_CURVE_MAPPING)) {
            securityCurveMapping = Config.parseSecurityCurveMappings(properties.getProperty(Config.SECURITY_CURVE_MAPPING));
        } else {
            securityCurveMapping = config.getSecurityCurveMapping();
        }

        final String providerName = properties.containsKey(Config.SECURITY_PROVIDER_CLASS_NAME) ?
                properties.getProperty(Config.SECURITY_PROVIDER_CLASS_NAME) :
                config.getSecurityProviderClassName();

        try {
            SECURITY_PROVIDER = setUpExplicitProvider(providerName);
        } catch (Exception e) {
            throw new InvalidArgumentException(format("Getting provider for class name: %s", providerName), e);

        }
        CERTIFICATE_FORMAT = Optional.ofNullable(properties.getProperty(Config.CERTIFICATE_FORMAT)).orElse(CERTIFICATE_FORMAT);
        DEFAULT_SIGNATURE_ALGORITHM = Optional.ofNullable(properties.getProperty(Config.SIGNATURE_ALGORITHM)).orElse(DEFAULT_SIGNATURE_ALGORITHM);

        resetConfiguration();

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


    private static final long X509_RECHECK_MILLIS = TimeUnit.MINUTES.toMillis(30);

    /**
     * Cache for key for X.509 certificates.
     */
    private static class CertKey {
        /** Pre-generated hash code for performance. */
        final int hashCode;

        /** The raw PEM data. */
        final byte[] pemData;


        /**
         * New instance.
         *
         * @param pemData the PEM data
         */
        CertKey(byte[] pemData) {
            // defensive copy
            this.pemData = pemData.clone();

            // pre-calculate the hash code
            hashCode = Arrays.hashCode(pemData);
        }


        @Override
        public boolean equals(Object o) {
            if (this == o) {
                 return true;
            }
            if (!(o instanceof CertKey)) {
                return false;
            }
            CertKey certKey = (CertKey) o;
            return hashCode == certKey.hashCode && Arrays.equals(pemData, certKey.pemData);
        }


        @Override
        public int hashCode() {
            return hashCode;
        }

    }


    /** A cached X.509 certificate. */
    private class CertValue {
        /** Link back to the cache key. */
        final CertKey key;

        /** Indicator if the X.509 certificate is currently valid. Note: it may become valid at some point in the future. */
        boolean isValid;

        /** The next time this certificate will be checked, in milliseconds since the epoch. */
        long nextCheckTime;

        /** The certificate derived from the PEM data. */
        X509Certificate x509;


        /**
         * New instance.
         *
         * @param key the cache key
         */
        CertValue(CertKey key) {
            this.key = key;
            x509 = null;
            isValid = false;
            nextCheckTime = Long.MIN_VALUE;
        }


        /**
         * Get the certificate if it is valid.
         *
         * @return the certificate, or null
         *
         * @throws CryptoException if the certificate cannot be parsed.
         */
        public synchronized X509Certificate getValid() throws CryptoException {
            return isValid() ? getX509() : null;
        }


        /**
         * Get the X.509 certificate.
         *
         * @return the certificate
         *
         * @throws CryptoException if the PEM data cannot be parsed.
         */
        public synchronized X509Certificate getX509() throws CryptoException {
            if (x509 == null) {
                // If the security providers change then something that could not be parsed could become parsable.
                try {
                    x509 = getX509CertificateInternal(key.pemData);
                } catch (CryptoException e) {
                    isValid = false;
                    nextCheckTime = System.currentTimeMillis() + X509_RECHECK_MILLIS;
                    logger.error("Unable to recover X.509 certificate from provided binary data", e);
                    throw e;
                }
            }
            return x509;
        }


        /**
         * Is the X.509 certificate currently valid?
         *
         * @return true if the certificate is valid
         *
         * @throws CryptoException if the certificate cannot be validated
         */
        public synchronized boolean isValid() throws CryptoException {
            // Only re-check if a reasonable amount of time has passed.
            long now = System.currentTimeMillis();
            if (nextCheckTime >= now) {
                return isValid;
            }

            nextCheckTime = now + X509_RECHECK_MILLIS;
            isValid = validateCertificate(getX509());
            return isValid;
        }

    }


    private final LoadingCache<CertKey, CertValue> x509Cache = CacheBuilder.newBuilder().maximumSize(1000).build(new CacheLoader<CertKey, CertValue>() {
        @Override
        public CertValue load(CertKey key) {
            return new CertValue(key);
        }
    });

    public void clearCertificateCache() {
      x509Cache.invalidateAll();
    }

    private CertValue getCertificateValue(byte[] pemCertificate) throws CryptoException {
        try {
            return x509Cache.get(new CertKey(pemCertificate));
        } catch (ExecutionException e) {
            Throwable thrown = e.getCause();
            if (thrown instanceof CryptoException) {
                throw (CryptoException) thrown;
            }
            if (thrown instanceof Exception) {
                throw new CryptoException("Error whilst processing certificate", (Exception) thrown);
            }
            throw new CryptoException("Error whilst processing certificate", e);
        }
    }


    private X509Certificate getValidCertificate(byte[] pemCertificate) throws CryptoException {
        return getCertificateValue(pemCertificate).getValid();
    }

}
