package org.hyperledger.fabric.sdk.identity;

import java.security.PrivateKey;
import org.hyperledger.fabric.sdk.Enrollment;



public class IdemixEnrollmentSerialized implements Enrollment {

    private static final String algo = "idemix";

    protected final String ipkSerializedString;
    protected final String revocationPkSerializedString;
    protected final String mspId;
    protected final String skSerializedString;
    protected final String credentialSerializedString;
    protected final String criSerializedString;
    protected final String ou;
    protected final String roleMask;

    public IdemixEnrollmentSerialized(String ipkSerializedString, String revocationPkSerializedString, String mspId, String skSerializedString, String credentialSerializedString, String criSerializedString, String ou, String roleMask) {
        this.ipkSerializedString = ipkSerializedString;
        this.revocationPkSerializedString = revocationPkSerializedString;
        this.mspId = mspId;
        this.skSerializedString = skSerializedString;
        this.credentialSerializedString = credentialSerializedString;
        this.criSerializedString = criSerializedString;
        this.ou = ou;
        this.roleMask = roleMask;
    }

    public PrivateKey getKey() {
        return null;
    }

    public String getCert() {
        return null;
    }

    public String getIpk() {
        return this.ipkSerializedString;
    }

    public String getRevocationPk() {
        return this.revocationPkSerializedString;
    }

    public String getMspId() {
        return this.mspId;
    }

    public String getSk() {
        return this.skSerializedString;
    }

    public String getCred() {
        return this.credentialSerializedString;
    }

    public String getCri() {
        return this.criSerializedString;
    }

    public String getOu() {
        return this.ou;
    }

    public String getRoleMask() {
        return this.roleMask;
    }
}
