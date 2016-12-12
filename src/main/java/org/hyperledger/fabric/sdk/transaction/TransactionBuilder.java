package org.hyperledger.fabric.sdk.transaction;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.ChainHeader;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.peer.ChaincodeTransaction.ChaincodeActionPayload;
import org.hyperledger.fabric.protos.peer.ChaincodeTransaction.ChaincodeEndorsedAction;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.protos.peer.FabricTransaction.Transaction;
import org.hyperledger.fabric.protos.peer.FabricTransaction.TransactionAction;

import com.google.protobuf.ByteString;

public class TransactionBuilder {

    private Log logger = LogFactory.getLog(TransactionBuilder.class);
    private FabricProposal.Proposal chaincodeProposal;
    private Collection<FabricProposalResponse.Endorsement> endorsements;
    private ByteString proposalResponcePayload;
    private TransactionContext context;

    public static TransactionBuilder newBuilder() {
        return new TransactionBuilder();
    }

    public TransactionBuilder context(TransactionContext context ){
        this.context = context;
        return this;
    }

    public TransactionBuilder chaincodeProposal(FabricProposal.Proposal chaincodeProposal ){
        this.chaincodeProposal = chaincodeProposal;
        return this;
    }

    public TransactionBuilder endorsements(Collection<FabricProposalResponse.Endorsement> endorsements ){
        this.endorsements = endorsements;
        return this;
    }

    public TransactionBuilder proposalResponcePayload(ByteString proposalResponcePayload ){
        this.proposalResponcePayload = proposalResponcePayload;
        return this;
    }

    public Envelope build(){
        return createTransactionEnvelope(chaincodeProposal, proposalResponcePayload, endorsements );
    }

    private Common.Envelope createTransactionEnvelope(FabricProposal.Proposal chaincodeProposal, ByteString proposalResponcePayload,
                                                     Collection<FabricProposalResponse.Endorsement> endorsements) {

        ChaincodeEndorsedAction ccea = ChaincodeEndorsedAction.newBuilder()
        		.setProposalResponsePayload(proposalResponcePayload)
        		.addAllEndorsements(endorsements)
        		.build();

        ChaincodeActionPayload ccap = ChaincodeActionPayload.newBuilder()
        		.setAction(ccea)
        		.setChaincodeProposalPayload(chaincodeProposal.toByteString())
        		.build();
        
        TransactionAction ta = TransactionAction.newBuilder()
        		.setHeader(chaincodeProposal.getHeader())
        		.setPayload(ccap.toByteString())
        		.build();
        
        Transaction transaction = Transaction.newBuilder()
        		.addActions(ta)
        		.build();

        ChainHeader chainHeader = ChainHeader.newBuilder()
        		.setType(HeaderType.ENDORSER_TRANSACTION_VALUE)
        		.setVersion(0)
//        		.setChainID(byte[0])
        		.build();
        
        Header header = Header.newBuilder()
        		.setChainHeader(chainHeader)
        		.build();
        
        Payload payload = Payload.newBuilder()
        		.setHeader(header)
        		.setData(transaction.toByteString())
        		.build();

        Envelope ce = Envelope.newBuilder()
        		.setPayload(payload.toByteString())
        		.build();


        logger.debug("Done creating transaction ready for orderer");

        return ce;

    }
}