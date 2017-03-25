package org.hyperledger.fabric.sdk;

import javax.xml.bind.DatatypeConverter;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

public class ProposalResponse extends ChainCodeResponse {

    private static final Log logger = LogFactory.getLog(ProposalResponse.class);

    private FabricProposal.SignedProposal signedProposal;

    private boolean isVerified = false;

    ProposalResponse(String transactionID, String chainCodeID, int status, String message) {
        super(transactionID, chainCodeID, status, message);

    }

    public boolean isVerified() {
        return this.isVerified;
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

        if (isVerified()) // check if this proposalResponse was already verified
            // by client code
            return isVerified();

        FabricProposalResponse.Endorsement endorsement = this.proposalResponse.getEndorsement();
        ByteString sig = endorsement.getSignature();

        try {
            Identities.SerializedIdentity endorser = Identities.SerializedIdentity
                    .parseFrom(endorsement.getEndorser());
            ByteString plainText = this.getPayload().concat(endorsement.getEndorser());

            logger.trace("payload TransactionBuilderbytes in hex: " + DatatypeConverter.printHexBinary(this.getPayload().toByteArray()));
            logger.trace("endorser bytes in hex: "
                    + DatatypeConverter.printHexBinary(endorsement.getEndorser().toByteArray()));
            logger.trace("plainText bytes in hex: " + DatatypeConverter.printHexBinary(plainText.toByteArray()));

            this.isVerified = crypto.verify(plainText.toByteArray(), sig.toByteArray(),
                    endorser.getIdBytes().toByteArray());
        } catch (InvalidProtocolBufferException | CryptoException e) {
            logger.error("verify: Cannot retrieve peer identity from ProposalResponse. Error is: " + e.getMessage(), e);
            this.isVerified = false;
        }

        return this.isVerified;
    } // verify

    private  FabricProposal.Proposal proposal;

    public FabricProposal.Proposal getProposal() {
        return proposal;
    }

    public FabricProposalResponse.ProposalResponse getProposalResponse() {
        return proposalResponse;
    }

    private FabricProposalResponse.ProposalResponse proposalResponse;

    public void setProposal(FabricProposal.SignedProposal signedProposal) throws ProposalException {

        try {
            this.signedProposal = signedProposal;
            this.proposal = FabricProposal.Proposal.parseFrom(signedProposal.getProposalBytes());
        } catch (InvalidProtocolBufferException e) {
            throw new ProposalException("Proposal exception", e);

        }
    }

    public void setProposalResponse(FabricProposalResponse.ProposalResponse proposalResponse) {
        this.proposalResponse = proposalResponse;
    }

    private Peer peer = null;

    public void setPeer(Peer peer) {
        this.peer = peer;
    }

    public Peer getPeer() {
        return this.peer;
    }

    public ByteString getPayload() {
        return proposalResponse.getPayload();
    }

    // public ByteString getPayload2(){
    // ByteString x = proposalResponse.getPayload();
    // return proposalResponse.getPayload();
    // }

    public ChainCodeID getChainCodeID() {

        Chaincode.ChaincodeID chaincodeID = null; // TODO NEED to clean up
        try {
            FabricProposal.ChaincodeProposalPayload ppl = FabricProposal.ChaincodeProposalPayload
                    .parseFrom(proposal.getPayload());
            Chaincode.ChaincodeInvocationSpec ccis = Chaincode.ChaincodeInvocationSpec.parseFrom(ppl.getInput());
            Chaincode.ChaincodeSpec scs = ccis.getChaincodeSpec();
            Chaincode.ChaincodeInput cci = scs.getInput();
            ByteString deps = cci.getArgs(1);
            Chaincode.ChaincodeDeploymentSpec chaincodeDeploymentSpec = Chaincode.ChaincodeDeploymentSpec
                    .parseFrom(deps.toByteArray());
            chaincodeID = chaincodeDeploymentSpec.getChaincodeSpec().getChaincodeId();
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return new ChainCodeID(chaincodeID);
    }

}
