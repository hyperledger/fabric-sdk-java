package org.hyperledger.fabric.sdk.identity;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

public class IdentityFactory {
    private IdentityFactory() {
        // private constructor for utility class
    }

    public static SigningIdentity getSigningIdentity(CryptoSuite cryptoSuite, User user) {
        Enrollment enrollment = user.getEnrollment();

        try {
            if (enrollment instanceof IdemixEnrollment) { // Need Idemix signer for this.
                return new IdemixSigningIdentity((IdemixEnrollment) enrollment);
            } else { // for now all others are x509
                return new X509SigningIdentity(cryptoSuite, user);
            }

        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

}
