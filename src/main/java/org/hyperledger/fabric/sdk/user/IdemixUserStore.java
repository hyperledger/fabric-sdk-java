package org.hyperledger.fabric.sdk.user;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.protos.msp.MspConfig;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.idemix.IdemixCredential;
import org.hyperledger.fabric.sdk.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollment;

public class IdemixUserStore {

    private static final String USER_PATH = "user";
    private static final String VERIFIER_PATH = "msp";
    private static final String IPK_CONFIG = "IssuerPublicKey";
    private static final String REVOCATION_PUBLIC_KEY = "RevocationPublicKey";


    protected final String storePath;
    protected final String mspId;
    protected final IdemixIssuerPublicKey ipk;

    public IdemixUserStore(String storePath, String mspId) throws CryptoException {
        this.storePath = storePath;
        this.mspId = mspId;
        Idemix.IssuerPublicKey ipkProto =  readIdemixIssuerPublicKey(Paths.get(mspId, VERIFIER_PATH + IPK_CONFIG).toString());
        this.ipk = new IdemixIssuerPublicKey(ipkProto);
        if (!this.ipk.check()) {
            throw new CryptoException("Failed verifying issuer public key.");
        }
    }

    public User getUser(String id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        MspConfig.IdemixMSPSignerConfig signerConfig = readIdemixMSPConfig(Paths.get(this.mspId, USER_PATH + id).toString());
        PublicKey revocationPk = readIdemixRevocationPublicKey(this.mspId);
        BIG sk = BIG.fromBytes(signerConfig.getSk().toByteArray());
        IdemixCredential cred = new IdemixCredential(Idemix.Credential.parseFrom(signerConfig.getCred()));
        Idemix.CredentialRevocationInformation cri = Idemix.CredentialRevocationInformation.parseFrom(signerConfig.getCredentialRevocationInformation());

        IdemixEnrollment enrollment = new IdemixEnrollment(this.ipk, revocationPk, this.mspId, sk, cred, cri, signerConfig.getOrganizationalUnitIdentifier(), signerConfig.getRole());
        return new IdemixUser(id, this.mspId, enrollment);
    }

    /**
     * Helper function: parse Idemix MSP Signer config (is part of the MSPConfig proto) from path
     *
     * @param id
     * @return IdemixMSPSignerConfig proto
     */
    protected MspConfig.IdemixMSPSignerConfig readIdemixMSPConfig(String id) throws IOException {
        Path path = Paths.get(this.storePath + id);
        return MspConfig.IdemixMSPSignerConfig.parseFrom(Files.readAllBytes(path));
    }

    /**
     * Parse Idemix issuer public key from the config file
     *
     * @param id
     * @return Idemix IssuerPublicKey proto
     */
    protected Idemix.IssuerPublicKey readIdemixIssuerPublicKey(String id) {
        Path path = Paths.get(this.storePath + id);
        byte[] data = null;
        try {
            data = Files.readAllBytes(path);
        } catch (IOException e) {
            e.printStackTrace();
        }

        Idemix.IssuerPublicKey ipk = null;

        try {
            ipk = Idemix.IssuerPublicKey.parseFrom(data);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return ipk;
    }

    /**
     * Parse Idemix long-term revocation public key
     *
     * @param id
     * @return idemix long-term revocation public key
     */
    protected PublicKey readIdemixRevocationPublicKey(String id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(this.mspId, VERIFIER_PATH + id);
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(path)));
    }
}
