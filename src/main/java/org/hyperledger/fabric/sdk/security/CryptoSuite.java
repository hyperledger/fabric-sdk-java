/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.hyperledger.fabric.sdk.security;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Properties;

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

/**
 * All packages for PKI key creation/signing/verification implement this interface
 */
public interface CryptoSuite {

    /**
     * Get Crypto Suite Factory for this implementation.
     *
     * @return MUST return the one and only one instance of a factory that produced this crypto suite.
     */

    CryptoSuiteFactory getCryptoSuiteFactory();

    /**
     * @return the {@link Properties} object containing implementation specific key generation properties
     */
    Properties getProperties();

    /**
     * Set the Certificate Authority certificates to be used when validating a certificate chain of trust
     *
     * @param certificates A collection of {@link java.security.cert.Certificate}s
     * @throws CryptoException
     */
    void loadCACertificates(Collection<Certificate> certificates) throws CryptoException;

    /**
     * Set the Certificate Authority certificates to be used when validating a certificate chain of trust.
     *
     * @param certificates a collection of certificates in PEM format
     * @throws CryptoException
     */
    void loadCACertificatesAsBytes(Collection<byte[]> certificates) throws CryptoException;

    /**
     * Generate a key.
     *
     * @return the generated key.
     * @throws CryptoException
     */
    KeyPair keyGen() throws CryptoException;

    /**
     * Sign the specified byte string.
     *
     * @param key       the {@link java.security.PrivateKey} to be used for signing
     * @param plainText the byte string to sign
     * @return the signed data.
     * @throws CryptoException
     */
    byte[] sign(PrivateKey key, byte[] plainText) throws CryptoException;

    /**
     * Verify the specified signature
     *
     * @param certificate        the certificate of the signer as the contents of the PEM file
     * @param signatureAlgorithm the algorithm used to create the signature.
     * @param signature          the signature to verify
     * @param plainText          the original text that is to be verified
     * @return {@code true} if the signature is successfully verified; otherwise {@code false}.
     * @throws CryptoException
     */
    boolean verify(byte[] certificate, String signatureAlgorithm, byte[] signature, byte[] plainText) throws CryptoException;

    /**
     * Hash the specified text byte data.
     *
     * @param plainText the text to hash
     * @return the hashed data.
     */
    byte[] hash(byte[] plainText);

    /**
     * Generates a CertificationRequest
     *
     * @param user
     * @param keypair
     * @return String in PEM format for certificate request.
     * @throws InvalidArgumentException
     */
    String generateCertificationRequest(String user, KeyPair keypair) throws InvalidArgumentException;

    /**
     * Convert bytes in PEM format to Certificate.
     *
     * @param certBytes
     * @return Certificate
     * @throws CryptoException
     */
    Certificate bytesToCertificate(byte[] certBytes) throws CryptoException;

    /**
     * The CryptoSuite factory. Currently {@link #getCryptoSuite} will always
     * give you a {@link CryptoPrimitives} object
     */

    class Factory {
        private Factory() {

        }

        /**
         * Get a crypto suite with the default factory with default settings.
         * Settings which can define such parameters such as curve strength, are specific to the crypto factory.
         *
         * @return Default crypto suite.
         * @throws IllegalAccessException
         * @throws InstantiationException
         * @throws ClassNotFoundException
         * @throws CryptoException
         * @throws InvalidArgumentException
         * @throws NoSuchMethodException
         * @throws InvocationTargetException
         */

        public static CryptoSuite getCryptoSuite() throws IllegalAccessException, InstantiationException,
                ClassNotFoundException, CryptoException, InvalidArgumentException, NoSuchMethodException,
                InvocationTargetException {
            return CryptoSuiteFactory.getDefault().getCryptoSuite();
        }

        /**
         * Get a crypto suite with the default factory with settings defined by properties
         * Properties are uniquely defined by the specific crypto factory.
         *
         * @param properties properties that define suite characteristics such as strength, curve, hashing .
         * @return
         * @throws IllegalAccessException
         * @throws InstantiationException
         * @throws ClassNotFoundException
         * @throws CryptoException
         * @throws InvalidArgumentException
         * @throws NoSuchMethodException
         * @throws InvocationTargetException
         */
        public static CryptoSuite getCryptoSuite(Properties properties) throws IllegalAccessException, InstantiationException,
                ClassNotFoundException, CryptoException, InvalidArgumentException, NoSuchMethodException,
                InvocationTargetException {
            return CryptoSuiteFactory.getDefault().getCryptoSuite(properties);
        }

    }
}
