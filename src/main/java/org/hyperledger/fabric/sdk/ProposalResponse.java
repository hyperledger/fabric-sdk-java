package org.hyperledger.fabric.sdk;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import javax.xml.bind.DatatypeConverter;

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
     * Verifies that a Proposal response is properly signed.
     * The payload is the concatenation of the response payload byte string and the endorsement
     * The certificate (public key) is gotten from the Endorsement.Endorser.IdBytes field
     * @return true/false depending on result of signature verification
     */
    public boolean verify() {

        if (isVerified()) // check if this proposalResponse was already verified by client code
            return isVerified();

        ByteString sig = this.endorsement.getSignature();

        try {
            Identities.SerializedIdentity endorser = Identities.SerializedIdentity.parseFrom(this.endorsement.getEndorser());
            // TODO check chain of trust. Need to handle CA certs somewhere
            ByteString plainText = this.getPayload().concat(endorsement.getEndorser());

            logger.debug("payload bytes in hex: " + DatatypeConverter.printHexBinary(this.getPayload().toByteArray()));
            logger.debug("endorser bytes in hex: " + DatatypeConverter.printHexBinary(this.endorsement.getEndorser().toByteArray()));
            logger.debug("plainText bytes in hex: " + DatatypeConverter.printHexBinary(plainText.toByteArray()));

            this.isVerified = CryptoPrimitives.verify(plainText.toByteArray(), sig.toByteArray(), endorser.getIdBytes().toByteArray());
        } catch (InvalidProtocolBufferException e) {
            logger.error("verify: Cannot retrieve peer identity from ProposalResponse. Error is: " + e.getMessage());
            this.isVerified = false;
        }

        return this.isVerified;
    } // verify

    FabricProposal.Proposal proposal;

    public FabricProposal.Proposal getProposal() {
        return proposal;
    }

    public FabricProposalResponse.ProposalResponse getProposalResponse() {
        return proposalResponse;
    }

    FabricProposalResponse.ProposalResponse proposalResponse;


    public void setProposal(FabricProposal.SignedProposal signedProposal) {

        try {
            this.signedProposal = signedProposal;
            this.proposal = FabricProposal.Proposal.parseFrom(signedProposal.getProposalBytes());
        } catch (InvalidProtocolBufferException e) {
            throw new DeploymentException("Proposal exception", e);

        }
    }

    private FabricProposalResponse.Endorsement endorsement;

    public void setProposalResponse(FabricProposalResponse.ProposalResponse proposalResponse) {
        this.proposalResponse = proposalResponse;
        this.endorsement = proposalResponse.getEndorsement();
    }

    Peer peer = null;

    public void setPeer(Peer peer) {
        this.peer = peer;
    }

    public ByteString getPayload() {
        return proposalResponse.getPayload();
    }

//    public ByteString getPayload2(){
//        ByteString x = proposalResponse.getPayload();
//        return proposalResponse.getPayload();
//    }

    public ChainCodeID getChainCodeID() {

        Chaincode.ChaincodeID chaincodeID = null; //TODO NEED to clean up
        try {
            FabricProposal.ChaincodeProposalPayload ppl = FabricProposal.ChaincodeProposalPayload.parseFrom(proposal.getPayload());
            Chaincode.ChaincodeInvocationSpec ccis = Chaincode.ChaincodeInvocationSpec.parseFrom(ppl.getInput());
            Chaincode.ChaincodeSpec scs = ccis.getChaincodeSpec();
            Chaincode.ChaincodeInput cci = scs.getInput();
            ByteString deps = cci.getArgs(2);
            Chaincode.ChaincodeDeploymentSpec chaincodeDeploymentSpec = Chaincode.ChaincodeDeploymentSpec.parseFrom(deps.toByteArray());
            chaincodeID = chaincodeDeploymentSpec.getChaincodeSpec().getChaincodeID();
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return new ChainCodeID(chaincodeID);
    }


}
