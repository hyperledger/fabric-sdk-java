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
import org.hyperledger.fabric.protos.ledger.rwset.Rwset;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.toHexString;

public class ProposalResponse extends ChaincodeResponse {

    private static final Log logger = LogFactory.getLog(ProposalResponse.class);
    private static final Config config = Config.getConfig();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;

    private boolean isVerified = false;
    private boolean hasBeenVerified = false;

    private WeakReference<ProposalResponsePayloadDeserializer> proposalResponsePayload;
    private ProposalPackage.Proposal proposal;
    private ProposalResponsePackage.ProposalResponse proposalResponse;
    private Peer peer = null;
    private ChaincodeID chaincodeID = null;
    private final TransactionContext transactionContext;

    ProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext.getTxID(), transactionContext.getChannelID(), status, message);
        this.transactionContext = transactionContext;
    }

    TransactionContext getTransactionContext() {
        return transactionContext;
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

    ByteString getPayloadBytes() {
        return proposalResponse.getPayload();
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
    boolean verify(CryptoSuite crypto) {
        logger.trace(format("%s verifying transaction: %s endorsement.", peer, getTransactionID()));

        if (hasBeenVerified) { // check if this proposalResponse was already verified   by client code
            logger.trace(format("%s transaction: %s was already verified returned %b", peer, getTransactionID(), isVerified));
            return this.isVerified;
        }

        try {
            if (isInvalid()) {
                this.isVerified = false;
                logger.debug(format("%s for transaction %s returned invalid. Setting verify to false", peer, getTransactionID()));
                return false;
            }

            ProposalResponsePackage.Endorsement endorsement = this.proposalResponse.getEndorsement();
            ByteString sig = endorsement.getSignature();
            byte[] endorserCertifcate = null;
            byte[] signature = null;
            byte[] data = null;

            try {
                Identities.SerializedIdentity endorser = Identities.SerializedIdentity
                        .parseFrom(endorsement.getEndorser());
                ByteString plainText = proposalResponse.getPayload().concat(endorsement.getEndorser());

                if (config.extraLogLevel(10)) {
                    if (null != diagnosticFileDumper) {
                        StringBuilder sb = new StringBuilder(10000);
                        sb.append("payload TransactionBuilderbytes in hex: " + DatatypeConverter.printHexBinary(proposalResponse.getPayload().toByteArray()));
                        sb.append("\n");
                        sb.append("endorser bytes in hex: "
                                + DatatypeConverter.printHexBinary(endorsement.getEndorser().toByteArray()));
                        sb.append("\n");
                        sb.append("plainText bytes in hex: " + DatatypeConverter.printHexBinary(plainText.toByteArray()));

                        logger.trace("payload TransactionBuilderbytes:  " +
                                diagnosticFileDumper.createDiagnosticFile(sb.toString()));
                    }
                }

                if (sig == null || sig.isEmpty()) { // we shouldn't get here ...
                    logger.warn(format("%s %s returned signature is empty verify set to false.", peer, getTransactionID()));
                    this.isVerified = false;
                } else {
                    endorserCertifcate = endorser.getIdBytes().toByteArray();
                    signature = sig.toByteArray();
                    data = plainText.toByteArray();

                    this.isVerified = crypto.verify(endorserCertifcate, config.getSignatureAlgorithm(),
                            signature, data);
                    if (!this.isVerified) {
                        logger.warn(format("%s transaction: %s verify: Failed to verify. Endorsers certificate: %s, " +
                                        "signature: %s, signing algorithm: %s, signed data: %s.",
                                peer, getTransactionID(), toHexString(endorserCertifcate), toHexString(signature),
                                config.getSignatureAlgorithm(), toHexString(data)
                        ));
                    }
                }

            } catch (InvalidProtocolBufferException | CryptoException e) {
                logger.error(format("%s transaction: %s verify: Failed to verify. Endorsers certificate: %s, " +
                                "signature: %s, signing algorithm: %s, signed data: %s.",
                        peer, getTransactionID(), toHexString(endorserCertifcate), toHexString(signature),
                        config.getSignatureAlgorithm(), toHexString(data)
                ), e);

                logger.error(format("%s transaction: %s verify: Cannot retrieve peer identity from ProposalResponse. Error is: %s", peer, getTransactionID(), e.getMessage()), e);
                this.isVerified = false;
            }

            logger.debug(format("%s finished verify for transaction %s returning %b", peer, getTransactionID(), this.isVerified));

            return this.isVerified;
        } finally {
            hasBeenVerified = true;
        }
    } // verify

    public ProposalPackage.Proposal getProposal() {
        return proposal;
    }

    public void setProposal(ProposalPackage.SignedProposal signedProposal) throws ProposalException {
        try {
            this.proposal = ProposalPackage.Proposal.parseFrom(signedProposal.getProposalBytes());
        } catch (InvalidProtocolBufferException e) {
            throw new ProposalException(format("%s transaction: %s Proposal exception", peer, getTransactionID()), e);
        }
    }

    /**
     * Get response to the proposal returned by the peer.
     *
     * @return peer response.
     */
    public ProposalResponsePackage.ProposalResponse getProposalResponse() {
        return proposalResponse;
    }

    public void setProposalResponse(ProposalResponsePackage.ProposalResponse proposalResponse) {
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
                ProposalPackage.ChaincodeHeaderExtension chaincodeHeaderExtension = ProposalPackage.ChaincodeHeaderExtension.parseFrom(channelHeader.getExtension());
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
            return ret != null ? ret.toByteArray() : null;
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
        if (statusReturnCode != -1) {
            return statusReturnCode;
        }

        try {
            final ProposalResponsePayloadDeserializer proposalResponsePayloadDeserializer = getProposalResponsePayloadDeserializer();
            statusReturnCode = proposalResponsePayloadDeserializer.getExtension().getResponseStatus();
            return statusReturnCode;
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
            Rwset.TxReadWriteSet txReadWriteSet = proposalResponsePayloadDeserializer.getExtension().getResults();
            return txReadWriteSet != null ? new TxReadWriteSetInfo(txReadWriteSet) : null;
        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }
    }
}
