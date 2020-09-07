/*
 *
 *  Copyright 2018 IBM - All Rights Reserved.
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
package org.hyperledger.fabric.sdk.security.certgen;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Holds PEM encoded TLS certificate key pairs.
 */
public class TLSCertificateKeyPair {
    private byte[] certPemBytes;
    private byte[] certDerBytes;
    private byte[] keyPemBytes;

    private TLSCertificateKeyPair(byte[] certPemBytes, byte[] certDerBytes, byte[] keyPemBytes) {
        this.certPemBytes = certPemBytes;
        this.certDerBytes = certDerBytes;
        this.keyPemBytes = keyPemBytes;
    }

    /***
     * Creates a TLSCertificateKeyPair out of the given {@link X509Certificate} and {@link KeyPair}
     * encoded in PEM and also in DER for the certificate
     * @param x509Cert the certificate to process
     * @param keyPair  the key pair to process
     * @return a TLSCertificateKeyPair
     * @throws IOException upon failure
     */
    static TLSCertificateKeyPair fromX509CertKeyPair(X509Certificate x509Cert, KeyPair keyPair) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(baos);
        JcaPEMWriter w = new JcaPEMWriter(writer);
        w.writeObject(x509Cert);
        w.flush();
        w.close();
        byte[] pemBytes = baos.toByteArray();

        InputStreamReader isr = new InputStreamReader(new ByteArrayInputStream(pemBytes));
        PemReader pr = new PemReader(isr);
        PemObject pem = pr.readPemObject();
        byte[] derBytes = pem.getContent();

        baos = new ByteArrayOutputStream();
        writer = new OutputStreamWriter(baos);
        w = new JcaPEMWriter(writer);
        JcaPKCS8Generator keygen = new JcaPKCS8Generator(keyPair.getPrivate(), null);
        w.writeObject(keygen.generate());
        w.flush();
        w.close();
        byte[] keyBytes = baos.toByteArray();
        return new TLSCertificateKeyPair(pemBytes, derBytes, keyBytes);
    }

    /***
     * @return the certificate, in PEM encoding
     */
    public byte[] getCertPEMBytes() {
        return certPemBytes;
    }

    /***
     * @return the certificate, in DER encoding
     */
    public byte[] getCertDERBytes() {
        return certDerBytes;
    }

    /***
     * @return the key, in PEM encoding
     */
    public byte[] getKeyPemBytes() {
        return keyPemBytes;
    }
}
