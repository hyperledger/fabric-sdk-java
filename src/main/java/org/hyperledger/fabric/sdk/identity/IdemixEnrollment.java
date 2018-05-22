package org.hyperledger.fabric.sdk.identity;

import java.security.KeyPair;
import java.security.PrivateKey;

import org.hyperledger.fabric.sdk.Enrollment;

public class IdemixEnrollment implements Enrollment {

    private KeyPair key;
    private String cert;

    public IdemixEnrollment(KeyPair signingKeyPair, String signedPem) {
        this.key = signingKeyPair;
        this.cert = signedPem;
    }

    public PrivateKey getKey() {
        return key.getPrivate();
    }

    public String getCert() {
        return cert;
    }

}
