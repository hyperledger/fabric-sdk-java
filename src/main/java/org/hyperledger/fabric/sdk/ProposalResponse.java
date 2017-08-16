/*
 Copyright IBM Corp. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/
package org.hyperledger.fabric.sdk;

import java.lang.ref.WeakReference;

import javax.xml.bind.DatatypeConverter;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.ledger.rwset.Rwset.TxReadWriteSet;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeHeaderExtension;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

public class ProposalResponse extends ChaincodeResponse {

    private static final Log logger = LogFactory.getLog(ProposalResponse.class);
    private static final Config config = Config.getConfig();

    private boolean isVerified = false;

    private WeakReference<ProposalResponsePayloadDeserializer> proposalResponsePayload;
    private FabricProposal.Proposal proposal;
    private FabricProposalResponse.ProposalResponse proposalResponse;
    private Peer peer = null;
    private ChaincodeID chaincodeID = null;

    ProposalResponse(String transactionID, String chaincodeID, int status, String message) {
        super(transactionID, chaincodeID, status, message);

    }

    ProposalResponsePayloadDeserializer getProposalResponsePayloadDeserializer() throws InvalidArgumentException {
        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        ProposalResponsePayloadDeserializer ret = null;

        if (proposalResponsePayload != null) {
            ret = proposalResponsePayload.get();

        }
        if (ret == null) {

            try {
                ret = new ProposalResponsePayloadDeserializer(proposalResponse.getPayload());
            } catch (Exception e) {
                throw new InvalidArgumentException(e);
            }

            proposalResponsePayload = new WeakReference<>(ret);
        }

        return ret;

    }

    public boolean isVerified() {
        return isVerified;
    }

    /*
     * Verifies that a Proposal response is properly signed. The payload is the
     * concatenation of the response payload byte string and the endorsement The
     * certificate (public key) is gotten from the Endorsement.Endorser.IdBytes
     * field
     *
     * @param crypto the CryptoPrimitives instance to be used for signing and
     * verification
     *
     * @return true/false depending on result of signature verification
     */
    public boolean verify(CryptoSuite crypto) {

        if (isVerified()) { // check if this proposalResponse was already verified   by client code
            return isVerified();
        }

        if (isInvalid()) {
            this.isVerified = false;
        }

        FabricProposalResponse.Endorsement endorsement = this.proposalResponse.getEndorsement();
        ByteString sig = endorsement.getSignature();

        try {
            Identities.SerializedIdentity endorser = Identities.SerializedIdentity
                    .parseFrom(endorsement.getEndorser());
            ByteString plainText = proposalResponse.getPayload().concat(endorsement.getEndorser());

            if (config.extraLogLevel(10)) {

                logger.trace("payload TransactionBuilderbytes in hex: " + DatatypeConverter.printHexBinary(proposalResponse.getPayload().toByteArray()));
                logger.trace("endorser bytes in hex: "
                        + DatatypeConverter.printHexBinary(endorsement.getEndorser().toByteArray()));
                logger.trace("plainText bytes in hex: " + DatatypeConverter.printHexBinary(plainText.toByteArray()));
            }

            this.isVerified = crypto.verify(endorser.getIdBytes().toByteArray(), config.getSignatureAlgorithm(),
                    sig.toByteArray(), plainText.toByteArray()
            );
        } catch (InvalidProtocolBufferException | CryptoException e) {
            logger.error("verify: Cannot retrieve peer identity from ProposalResponse. Error is: " + e.getMessage(), e);
            this.isVerified = false;
        }

        return this.isVerified;
    } // verify

    public FabricProposal.Proposal getProposal() {
        return proposal;
    }

    public void setProposal(FabricProposal.SignedProposal signedProposal) throws ProposalException {

        try {
            this.proposal = FabricProposal.Proposal.parseFrom(signedProposal.getProposalBytes());
        } catch (InvalidProtocolBufferException e) {
            throw new ProposalException("Proposal exception", e);

        }
    }

    /**
     * Get response to the proposal returned by the peer.
     *
     * @return peer response.
     */

    public FabricProposalResponse.ProposalResponse getProposalResponse() {
        return proposalResponse;
    }

    public void setProposalResponse(FabricProposalResponse.ProposalResponse proposalResponse) {
        this.proposalResponse = proposalResponse;
    }

    /**
     * The peer this proposal was created on.
     *
     * @return See {@link Peer}
     */

    public Peer getPeer() {
        return this.peer;
    }

    void setPeer(Peer peer) {
        this.peer = peer;
    }

//    public ByteString getPayload() {
//        return proposalResponse.getPayload();
//    }

    /**
     * Chaincode ID that was executed.
     *
     * @return See {@link ChaincodeID}
     * @throws InvalidArgumentException
     */

    public ChaincodeID getChaincodeID() throws InvalidArgumentException {

        try {

            if (chaincodeID == null) {

                Header header = Header.parseFrom(proposal.getHeader());
                Common.ChannelHeader channelHeader = Common.ChannelHeader.parseFrom(header.getChannelHeader());
                ChaincodeHeaderExtension chaincodeHeaderExtension = ChaincodeHeaderExtension.parseFrom(channelHeader.getExtension());
                chaincodeID = new ChaincodeID(chaincodeHeaderExtension.getChaincodeId());
            }
            return chaincodeID;

        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }

    }

    /**
     * ChaincodeActionResponsePayload is the result of the executing chaincode.
     *
     * @return the result of the executing chaincode.
     * @throws InvalidArgumentException
     */

    public byte[] getChaincodeActionResponsePayload() throws InvalidArgumentException {

        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        try {

            final ProposalResponsePayloadDeserializer proposalResponsePayloadDeserializer = getProposalResponsePayloadDeserializer();
            ByteString ret = proposalResponsePayloadDeserializer.getExtension().getChaincodeAction().getResponse().getPayload();
            if (null == ret) {
                return null;
            }
            return ret.toByteArray();
        } catch (InvalidArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }
    }

    /**
     * getChaincodeActionResponseStatus returns the what chaincode executions set as the return status.
     *
     * @return status code.
     * @throws InvalidArgumentException
     */

    public int getChaincodeActionResponseStatus() throws InvalidArgumentException {
        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        try {

            final ProposalResponsePayloadDeserializer proposalResponsePayloadDeserializer = getProposalResponsePayloadDeserializer();
            return proposalResponsePayloadDeserializer.getExtension().getResponseStatus();

        } catch (InvalidArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }

    }

    /**
     * getChaincodeActionResponseReadWriteSetInfo get this proposals read write set.
     *
     * @return The read write set. See {@link TxReadWriteSetInfo}
     * @throws InvalidArgumentException
     */

    public TxReadWriteSetInfo getChaincodeActionResponseReadWriteSetInfo() throws InvalidArgumentException {

        if (isInvalid()) {
            throw new InvalidArgumentException("Proposal response is invalid.");
        }

        try {

            final ProposalResponsePayloadDeserializer proposalResponsePayloadDeserializer = getProposalResponsePayloadDeserializer();

            TxReadWriteSet txReadWriteSet = proposalResponsePayloadDeserializer.getExtension().getResults();

            if (txReadWriteSet == null) {
                return null;
            }

            return new TxReadWriteSetInfo(txReadWriteSet);

        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }

    }

}
