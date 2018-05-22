package org.hyperledger.fabric.sdk.identity;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.PrivateKey;

import org.hyperledger.fabric.sdk.Enrollment;

public class X509Enrollment implements Enrollment, Serializable {

    private final PrivateKey key;
    private final String cert;

    public X509Enrollment(KeyPair signingKeyPair, String signedPem) {
        this.key = signingKeyPair.getPrivate();
        this.cert = signedPem;
    }

    public X509Enrollment(PrivateKey key, String signedPem) {
        this.key = key;
        this.cert = signedPem;
    }

    public PrivateKey getKey() {
        return key;
    }

    public String getCert() {
        return cert;
    }

}
