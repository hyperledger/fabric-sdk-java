/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.security.cert.Certificate;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Collection;
import java.util.Properties;

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

/**
 * All packages for PKI key creation/signing/verification implement this interface
 *
 */
public interface CryptoSuite {
    /**
     * implementation specific initialization. Whoever constructs a CryptoSuite instance <b>MUST</b> call
     * init before using the instance
     * @throws CryptoException
     */
    public void init() throws CryptoException, InvalidArgumentException ;
    /**
     * Pass in implementation specific properties to the CryptoSuite
     * @param properties A {@link java.util.Properties} object. The key/value pairs are implementation specific
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    public void setProperties(Properties properties) throws CryptoException, InvalidArgumentException ;
    /**
     * @return the {@link java.util.Properties) object containing implementation specific key generation properties
     */
    public Properties getProperties();
    /**
     * Set the Certificate Authority certificates to be used when validating a certificate chain of trust
     * @param CACertificates A collection of {@link java.security.cert.Certificate}s
     * @throws CryptoException
     */
    public void loadCACertificates(Collection<Certificate> CACertificates) throws CryptoException;
    /**
     * Set the Certificate Authority certificates to be used when validating a certificate chain of trust.
     *
     * @param CACertificates a collection of certificates in PEM format
     * @throws CryptoException
     */
    public void loadCACertificatesAsBytes(Collection<byte[]> CACertificatesBytes) throws CryptoException;
    /**
     * @return a {@link java.security.KeyPair} according to the options set via {@link #setKeyGenProperties}
     * @throws CryptoException
     */
    public KeyPair keyGen() throws CryptoException;
    /**
     * Sign the inputted byte string.
     * @param key the {@link java.security.PrivateKey} to be used for signing
     * @param plainText the byte string to sign
     * @return
     * @throws CryptoException
     */
    public byte[] sign(PrivateKey key, byte[] plainText) throws CryptoException ;
    /**
     * Verify the inputted signature
     * @param plainText the original text
     * @param signature the signature to verify
     * @param certificate the certificate of the signer as the contents of the PEM file
     * @return
     * @throws CryptoException
     */
    public boolean verify(byte[] plainText, byte[] signature, byte[] certificate) throws CryptoException ;
    /**
     * Hash the inputted byte string according to the options set via {@link #setHashProperties}
     * @param plainText the text to hash
     * @return
     * @throws CryptoException
     */
    public byte[] hash(byte[] plainText) ;

    /**
     * The CryptoSuite factory. Currently {@link #getCryptoSuite} will always
     * give you a {@link CryptoPrimitives} object
     *
     */
    public static class Factory {
        public static CryptoSuite getCryptoSuite() {
            return new CryptoPrimitives() ;
        }

        /* TODO create a version of getCryptoSuite that allows pluggable implementations
         * possibly : getCryptoSuite("org.x.my.crypto.myClass") and use reflection to
         * invoke the constructor
         *
        public static CryptoSuite getCryptoSuite(String type) {
            CryptoSuite cryptoSuite;
            switch (type) {
            // add additional cases when we have multiple CryptoSuite implementations
            case "DEFAULT":
                // fall through
            default:
                cryptoSuite = new CryptoPrimitives() ;
            }
            return cryptoSuite;
        }
        */
    }
}
