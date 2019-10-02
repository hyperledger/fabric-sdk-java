/*
 *
 *  Copyright IBM Corp. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdk.identity;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.protos.msp.Identities.SerializedIdentity;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.idemix.IdemixCredential;
import org.hyperledger.fabric.sdk.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.sdk.idemix.IdemixPseudonym;
import org.hyperledger.fabric.sdk.idemix.IdemixPseudonymSignature;
import org.hyperledger.fabric.sdk.idemix.IdemixSignature;
import org.hyperledger.fabric.sdk.idemix.IdemixUtils;

/**
 * IdemixSigningIdentity is an Idemix implementation of the SigningIdentity It
 * contains IdemixIdentity (a public part) and a corresponding secret part that
 * contains the user secret key and the commitment opening (randomness) to the
 * pseudonym value (a commitment to the user secret)
 * <p>
 * We note that since the attributes and their disclosure is fixed we are not
 * adding them as fields here.
 */
public class IdemixSigningIdentity implements SigningIdentity {

    // public part of the signing identity (passed with the signature)
    private final IdemixIdentity idemixIdentity;

    // public key of the Idemix CA (issuer)
    private final IdemixIssuerPublicKey ipk;

    // user's secret
    private final BIG sk;

    // idemix pseudonym (represents Idemix identity)
    private final IdemixPseudonym pseudonym;

    // credental revocation information
    private final Idemix.CredentialRevocationInformation cri;

    // proof that the identity is valid (proof of possession of a credential
    // with respect to a pseudonym.
    private final IdemixSignature proof;

    // discloseFlags will be passed to the idemix signing and verification
    // routines.
    // It informs idemix to disclose both attributes (OU and Role) when signing.
    private static final boolean[] disclosedFlags = new boolean[]{true, true, false, false};

    // empty message to sign in the validate identity proof
    private static final byte[] msgEmpty = {};

    // the revocation handle is always the third attribute
    private static final int rhIndex = 3;

    private static final Log logger = LogFactory.getLog(IdemixSigningIdentity.class);

    public IdemixSigningIdentity(IdemixEnrollment enrollment) throws CryptoException, InvalidArgumentException {
        this(enrollment.ipk, enrollment.revocationPk, enrollment.mspId, enrollment.sk, enrollment.cred,
                enrollment.cri, enrollment.ou, enrollment.roleMask);
    }

    /**
     * Create new Idemix Signing Identity with a fresh pseudonym
     *
     * @param ipk          issuer public key
     * @param revocationPk the issuer's long term revocation public key
     * @param mspId        MSP identifier
     * @param sk           user's secret
     * @param cred         idemix credential
     * @param cri          the credential revocation information
     * @param ou           is OU attribute
     * @param role         is role attribute
     * @throws CryptoException
     * @throws InvalidArgumentException
     */
    public IdemixSigningIdentity(IdemixIssuerPublicKey ipk, PublicKey revocationPk, String mspId, BIG sk, IdemixCredential cred, Idemix.CredentialRevocationInformation cri, String ou, int role)
            throws CryptoException, InvalidArgumentException {

        // input checks
        if (ipk == null) {
            throw new InvalidArgumentException("Issuer Public Key (IPK) must not be null");
        }

        if (revocationPk == null) {
            throw new InvalidArgumentException("Revocation PK must not be null");
        }

        if (mspId == null) {
            throw new InvalidArgumentException("MSP ID must not be null");
        }

        if (mspId.isEmpty()) {
            throw new InvalidArgumentException("MSP ID must not be empty");
        }

        if (ou == null) {
            throw new InvalidArgumentException("OU must not be null");
        }

        if (ou.isEmpty()) {
            throw new InvalidArgumentException("OU must not be empty");
        }

        if (sk == null) {
            throw new InvalidArgumentException("SK must not be null");
        }

        if (cred == null) {
            throw new InvalidArgumentException("Credential must not be null");
        }

        if (cri == null) {
            throw new InvalidArgumentException("Credential revocation information must not be null");
        }

        logger.trace("Verifying public key with hash: " + Arrays.toString(ipk.getHash()) +
                " \nAttributes: " + Arrays.toString(ipk.getAttributeNames()));

        if (!ipk.check()) {
            CryptoException e = new CryptoException("Issuer public key is not valid");
            logger.error("", e);
            throw e;
        }

        this.ipk = ipk;
        this.sk = sk;
        this.cri = cri;

        logger.trace("Verifying the credential");

        // cryptographically verify credential
        // (check if the issuer's signature is valid)
        if (!cred.verify(sk, ipk)) {
            CryptoException e = new CryptoException("Credential is not cryptographically valid");
            logger.error("", e);
            throw e;
        }

        logger.trace("Checking attributes");

        // attribute checks
        // 4 attributes are expected:
        // - organization unit (disclosed)
        // - role: admin or member (disclosed)
        // - enrollment id (hidden, for future auditing feature and authorization with CA)
        // - revocation handle (hidden, for future revocation support)
        if (cred.getAttrs().length != 4) {
            throw new CryptoException("Error: There are " + cred.getAttrs().length + " attributes and the expected are 4");
        }
        byte[] ouBytes = cred.getAttrs()[0];
        byte[] roleBytes = cred.getAttrs()[1];
        byte[] eIdBytes = cred.getAttrs()[2];
        byte[] rHBytes = cred.getAttrs()[3];

        BIG[] attributes = new BIG[4];
        attributes[0] = BIG.fromBytes(ouBytes);
        attributes[1] = BIG.fromBytes(roleBytes);
        attributes[2] = BIG.fromBytes(eIdBytes);
        attributes[3] = BIG.fromBytes(rHBytes);

        // check that the OU string matches the credential's attribute value
        if (!Arrays.equals(IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(ou.getBytes(StandardCharsets.UTF_8))), ouBytes)) {
            throw new IllegalArgumentException("the OU string does not match the credential");
        }

        // check that the role matches the credential's attribute value
        if (!Arrays.equals(IdemixUtils.bigToBytes(new BIG(role)), roleBytes)) {
            throw new IllegalArgumentException("the role does not match the credential");
        }

        logger.trace("Generating fresh pseudonym and proof");
        // generate a fresh pseudonym
        this.pseudonym = new IdemixPseudonym(this.sk, this.ipk);

        // generate a fresh proof of possession of a credential
        // with respect to a freshly generated pseudonym
        this.proof = new IdemixSignature(cred, this.sk, this.pseudonym, this.ipk, IdemixSigningIdentity.disclosedFlags, IdemixSigningIdentity.msgEmpty, rhIndex, cri);
        logger.trace("Verifying the proof");
        // verify the proof
        if (!this.proof.verify(IdemixSigningIdentity.disclosedFlags, this.ipk, IdemixSigningIdentity.msgEmpty, attributes, rhIndex, revocationPk, (int) cri.getEpoch())) {
            throw new CryptoException("Generated proof of identity is not valid");
        }

        logger.trace("Generating the Identity Object");
        // generate a fresh identity with new pseudonym
        this.idemixIdentity = new IdemixIdentity(mspId, this.ipk, this.pseudonym.getNym(), ou, role, this.proof);
        logger.trace(this.idemixIdentity.toString());
    }

    @Override
    public byte[] sign(byte[] msg) throws CryptoException, InvalidArgumentException {
        if (msg == null) {
            throw new InvalidArgumentException("Input must not be null");
        }
        return new IdemixPseudonymSignature(this.sk, this.pseudonym, this.ipk, msg).toProto().toByteArray();
    }

    @Override
    public SerializedIdentity createSerializedIdentity() {
        return this.idemixIdentity.createSerializedIdentity();
    }

    @Override
    public boolean verifySignature(byte[] msg, byte[] sig) throws CryptoException, InvalidArgumentException {

        if (msg == null) {
            throw new InvalidArgumentException("Message must not be null");
        }

        if (sig == null) {
            throw new InvalidArgumentException("Signature must not be null");
        }

        Idemix.NymSignature nymSigProto = null;
        try {
            nymSigProto = Idemix.NymSignature.parseFrom(sig);
        } catch (InvalidProtocolBufferException e) {
            logger.error("Idemix Nym Signature parsing error, dumping \nSignature: " + Arrays.toString(sig) + " \nMessage: " + Arrays.toString(msg));
            throw new CryptoException("Could not parse Idemix Nym Signature", e);
        }

        IdemixPseudonymSignature nymSig = new IdemixPseudonymSignature(nymSigProto);
        if (!nymSig.verify(this.pseudonym.getNym(), this.ipk, msg)) {
            logger.error("Idemix Nym Signature verification error, dumping \nSignature: " + Arrays.toString(sig) + " \nMessage: " + Arrays.toString(msg));
            return false;
        }

        return true;
    }

    public IdemixPseudonym getNym() {
        return this.pseudonym;
    }

    public IdemixSignature getProof() {
        return this.proof;
    }
}
