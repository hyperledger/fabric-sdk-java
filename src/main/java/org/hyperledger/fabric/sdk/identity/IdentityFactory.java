package org.hyperledger.fabric.sdk.identity;

import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

public abstract class IdentityFactory {

    private static IdentityFactory instance;

    IdentityFactory() {
        // private constructor for utility class
    }

    /**
     * Define a custom Identity factory to be used, allowing client defines its own implementation
     *
     * @param factory IdentityFactory to be used
     */
    public static void configureCustomIdentityFactory(final IdentityFactory factory) {
        instance = factory;
    }

    public static SigningIdentity getSigningIdentity(CryptoSuite cryptoSuite, User user) {
        if (instance == null) {
            instance = new DefaultIdentityFactory();
        }

        return instance.createIdentity(cryptoSuite, user);

        /*
         * Enrollment enrollment = user.getEnrollment();
         *
         * try { if (enrollment instanceof IdemixEnrollment) { // Need Idemix signer for this. return new IdemixSigningIdentity((IdemixEnrollment) enrollment); } else { //
         * for now all others are x509 return new X509SigningIdentity(cryptoSuite, user); }
         *
         * } catch (Exception e) { throw new IllegalStateException(e.getMessage(), e); }
         */
    }

    /**
     * Create a new SigningIdentity based on a given user and using the provided crypto suite
     *
     * @param cryptoSuite Crypto suite to be used by the signing identity
     * @param user User referenced by the signing identity
     * @return SigningIdentity created with the given parameters
     */
    public abstract SigningIdentity createIdentity(CryptoSuite cryptoSuite, User user);

}
