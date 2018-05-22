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

        if (enrollment instanceof X509Enrollment) {
            return new X509SigningIdentity(cryptoSuite, user);
        }

        throw new IllegalStateException("Invalid enrollment. Expected X509Enrollment. " + enrollment);
    }

}
