package org.hyperledger.fabric.sdk.user;

import java.security.PublicKey;
import java.util.Set;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.idemix.IdemixCredential;
import org.hyperledger.fabric.sdk.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollment;

public class IdemixUser implements User {

    protected final String name;
    protected final String mspId;
    protected final IdemixEnrollment enrollment;

    public IdemixUser(String name, String mspId, IdemixEnrollment enrollment) {
        this.name = name;
        this.mspId = mspId;
        this.enrollment = enrollment;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public Set<String> getRoles() {
        return null;
    }

    @Override
    public String getAccount() {
        return null;
    }

    @Override
    public String getAffiliation() {
        return null;
    }

    @Override
    public Enrollment getEnrollment() {
        return this.enrollment;
    }

    @Override
    public String getMspId() {
        return this.mspId;
    }

    public IdemixIssuerPublicKey getIpk() {
        return this.enrollment.getIpk();
    }

    public IdemixCredential getIdemixCredential() {
        return this.enrollment.getCred();
    }

    public Idemix.CredentialRevocationInformation getCri() {
        return this.enrollment.getCri();
    }

    public BIG getSk() {
        return this.enrollment.getSk();
    }

    public PublicKey getRevocationPk() {
        return this.enrollment.getRevocationPk();
    }

    public String getOu() {
        return this.enrollment.getOu();
    }

    public int getRoleMask() {
        return this.enrollment.getRoleMask();
    }
}
