package org.hyperledger.fabric.sdk.identity;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.protos.idemix.Idemix.CredentialRevocationInformation;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.idemix.IdemixCredential;
import org.hyperledger.fabric.sdk.idemix.IdemixIssuerPublicKey;

public class IdemixEnrollment implements Enrollment {

    private static final String algo = "idemix";


    protected final IdemixIssuerPublicKey ipk;
    protected final PublicKey revocationPk;
    protected final String mspId;
    protected final BIG sk;
    protected final IdemixCredential cred;
    protected final CredentialRevocationInformation cri;
    protected final String ou;
    protected final int roleMask;

    public IdemixEnrollment(IdemixIssuerPublicKey ipk, PublicKey revocationPk, String mspId, BIG sk, IdemixCredential cred, CredentialRevocationInformation cri, String ou, int roleMask) {
        this.ipk = ipk;
        this.revocationPk = revocationPk;
        this.mspId = mspId;
        this.sk = sk;
        this.cred = cred;
        this.cri = cri;
        this.ou = ou;
        this.roleMask = roleMask;
    }

    public PrivateKey getKey() {
        return null;
    }

    public String getCert() {
        return null;
    }

    public IdemixIssuerPublicKey getIpk() {
        return this.ipk;
    }

    public PublicKey getRevocationPk() {
        return this.revocationPk;
    }

    public String getMspId() {
        return this.mspId;
    }

    public BIG getSk() {
        return this.sk;
    }

    public IdemixCredential getCred() {
        return this.cred;
    }

    public CredentialRevocationInformation getCri() {
        return this.cri;
    }

    public String getOu() {
        return this.ou;
    }

    public int getRoleMask() {
        return this.roleMask;
    }
}