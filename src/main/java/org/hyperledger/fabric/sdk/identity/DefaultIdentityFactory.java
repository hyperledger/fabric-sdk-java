package org.hyperledger.fabric.sdk.identity;

import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

/**
 * Default implementation of Identity Factory. It used the custom SDK methods to generate a SigningIdentity. For custom methods, implement {@link IdentityFactory} class and
 * register your factory using {@link IdentityFactory#configureCustomIdentityFactory(IdentityFactory)} method
 */
public class DefaultIdentityFactory extends IdentityFactory {
    DefaultIdentityFactory() {
    }

    @Override
    public SigningIdentity createIdentity(CryptoSuite cryptoSuite, User user) {
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
