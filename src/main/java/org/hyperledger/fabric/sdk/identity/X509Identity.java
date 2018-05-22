package org.hyperledger.fabric.sdk.identity;

import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.transaction.ProtoUtils;

public class X509Identity implements Identity {

    protected final User user;

    public X509Identity(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User is null");
        }
        if (user.getEnrollment() == null) {
            throw new IllegalArgumentException("user.getEnrollment() is null");
        }
        if (user.getEnrollment().getCert() == null) {
            throw new IllegalArgumentException("user.getEnrollment().getCert() is null");
        }

        this.user = user;
    }

    @Override
    public Identities.SerializedIdentity createSerializedIdentity() {
        return ProtoUtils.createSerializedIdentity(user);
    }
}
