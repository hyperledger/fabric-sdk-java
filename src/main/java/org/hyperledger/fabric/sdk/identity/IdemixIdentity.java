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

import java.util.Arrays;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.hyperledger.fabric.protos.common.MspPrincipal;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.sdk.idemix.IdemixSignature;
import org.hyperledger.fabric.sdk.idemix.IdemixUtils;

/**
 * IdemixIdentity is a public serializable part of the IdemixSigningIdentity.
 * It contains an (un)linkable pseudonym, revealed attribute values, and a
 * corresponding proof of possession of an Idemix credential
 */
public class IdemixIdentity implements Identity {

    private static final Log logger = LogFactory.getLog(IdemixIdentity.class);

    // MSP identifier
    private final String mspId;

    private final byte[] ipkHash;

    // Idemix Pseudonym
    private final ECP pseudonym;

    // Organization Unit attribute
    private final String ou;

    // Role attribute
    private final boolean role;

    // Proof of possession of Idemix credential
    // with respect to the pseudonym (nym)
    // and the corresponding attributes (ou, role)
    private final IdemixSignature associationProof;

    /**
     * Create Idemix Identity from a Serialized Identity
     *
     * @param proto
     */
    public IdemixIdentity(Identities.SerializedIdentity proto) throws CryptoException, InvalidArgumentException {
        if (proto == null) {
            throw new InvalidArgumentException("Input must not be null");
        }

        this.mspId = proto.getMspid();

        try {
            logger.trace("Fetching Idemix Proto");
            Identities.SerializedIdemixIdentity idemixProto = Identities.SerializedIdemixIdentity.parseFrom(proto.getIdBytes());

            if (idemixProto == null) {
                throw new IllegalArgumentException("The identity does not contain a serialized idemix identity");
            }
            logger.trace("Deserializing Nym and attribute values");
            this.pseudonym = new ECP(BIG.fromBytes(idemixProto.getNymX().toByteArray()),
                    BIG.fromBytes(idemixProto.getNymY().toByteArray()));

            MspPrincipal.OrganizationUnit ou = MspPrincipal.OrganizationUnit.parseFrom(idemixProto.getOu());
            MspPrincipal.MSPRole role = MspPrincipal.MSPRole.parseFrom(idemixProto.getRole());

            this.ou = ou.getOrganizationalUnitIdentifier();
            this.role = role.getRole().getNumber() == 1;
            this.ipkHash = ou.getCertifiersIdentifier().toByteArray();

            logger.trace("Deserializing Proof");
            this.associationProof = new IdemixSignature(Idemix.Signature.parseFrom(idemixProto.getProof().toByteArray()));

        } catch (InvalidProtocolBufferException e) {
            throw new CryptoException("Cannot deserialize MSP ID", e);
        }
    }

    /**
     * Create Idemix Identity from the following inputs:
     *
     * @param mspId is MSP ID sting
     * @param nym   is Identity Mixer Pseudonym
     * @param ou    is OU attribute
     * @param role  is Role attribute
     * @param proof is Proof
     */
    public IdemixIdentity(String mspId, IdemixIssuerPublicKey ipk, ECP nym, String ou, boolean role, IdemixSignature proof)
            throws InvalidArgumentException {

        if (mspId == null) {
            throw new InvalidArgumentException("MSP ID must not be null");
        }

        if (mspId.isEmpty()) {
            throw new InvalidArgumentException("MSP ID must not be empty");
        }

        if (ipk == null) {
            throw new InvalidArgumentException("Issuer Public Key must not be empty");
        }

        if (nym == null) {
            throw new InvalidArgumentException("Identity Mixer Pseudonym (nym) must not be null");
        }

        if (ou == null) {
            throw new InvalidArgumentException("OU attribute must not be null");
        }

        if (ou.isEmpty()) {
            throw new InvalidArgumentException("OU attribute must not be empty");
        }

        if (proof == null) {
            throw new InvalidArgumentException("Proof must not be null");
        }


        this.mspId = mspId;
        this.ipkHash = ipk.getHash();
        this.pseudonym = nym;
        this.ou = ou;
        this.role = role;
        this.associationProof = proof;
    }

    /**
     * Serialize Idemix Identity
     */
    @Override
    public Identities.SerializedIdentity createSerializedIdentity() {
        MspPrincipal.OrganizationUnit ou = MspPrincipal.OrganizationUnit.newBuilder()
                .setCertifiersIdentifier(ByteString.copyFrom(this.ipkHash))
                .setMspIdentifier(this.mspId)
                .setOrganizationalUnitIdentifier(this.ou)
                .build();

        MspPrincipal.MSPRole role = MspPrincipal.MSPRole.newBuilder()
                .setRole(this.role ? MspPrincipal.MSPRole.MSPRoleType.ADMIN : MspPrincipal.MSPRole.MSPRoleType.MEMBER)
                .setMspIdentifier(this.mspId)
                .build();

        Identities.SerializedIdemixIdentity serializedIdemixIdentity = Identities.SerializedIdemixIdentity.newBuilder()
                .setProof(ByteString.copyFrom(this.associationProof.toProto().toByteArray()))
                .setOu(ByteString.copyFrom(ou.toByteArray()))
                .setRole(ByteString.copyFrom(role.toByteArray()))
                .setNymY(ByteString.copyFrom(IdemixUtils.bigToBytes(this.pseudonym.getY())))
                .setNymX(ByteString.copyFrom(IdemixUtils.bigToBytes(this.pseudonym.getX())))
                .build();

        return Identities.SerializedIdentity.newBuilder()
                .setIdBytes(ByteString.copyFrom(serializedIdemixIdentity.toByteArray()))
                .setMspid(this.mspId)
                .build();
    }

    public String getOuValue() {
        return this.ou;
    }

    public boolean getRoleValue() {
        return this.role;
    }

    @Override
    public String toString() {
        return "IdemixIdentity" +
                " [ MSP ID: " + this.mspId +
                " Issuer Public Key Hash: " + Arrays.toString(this.ipkHash) +
                " Pseudonym: " + this.pseudonym.toRawString() +
                " OU: " + this.ou +
                " Role: " + this.role +
                " Association Proof: " + this.associationProof.toProto().toString() +
                " ]";
    }
}
