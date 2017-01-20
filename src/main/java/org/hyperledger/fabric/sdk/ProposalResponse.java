package org.hyperledger.fabric.sdk;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;


public class ProposalResponse extends ChainCodeResponse {

    private FabricProposal.SignedProposal signedProposal;


    ProposalResponse(String transactionID, String chainCodeID, int status, String message) {
        super(transactionID, chainCodeID, status, message);

    }

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
            throw new DeploymentException("Proposal exception",e);

        }
    }

    public void setProposalResponse(FabricProposalResponse.ProposalResponse proposalResponse) {
        this.proposalResponse = proposalResponse;
    }

    Peer peer = null;

    public void setPeer(Peer peer) {
        this.peer = peer;
    }

    public ByteString getPayload() {
        return proposalResponse.getResponse().getPayload();
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
