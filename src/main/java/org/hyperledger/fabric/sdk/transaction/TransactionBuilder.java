/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.transaction;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.peer.FabricProposal;
//import org.hyperledger.fabric.protos.peer.FabricTransaction;
//import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.protos.peer.FabricTransaction;

import java.util.Arrays;
import java.util.Collection;
import java.util.function.Function;

public class TransactionBuilder {

    private Log logger = LogFactory.getLog(TransactionBuilder.class);
    private FabricProposal.Proposal chaincodeProposal;
    private Collection<FabricProposalResponse.Endorsement> endorsements;
    private FabricProposal.ChaincodeProposalPayload proposalResponcePayload;
    private Function<byte[], byte[]> hash;


    public static TransactionBuilder newBuilder() {
        return new TransactionBuilder();
    }


    public TransactionBuilder hash(Function<byte[], byte[]> hash) {
        this.hash = hash;
        return this;
    }

    public TransactionBuilder chaincodeProposal(FabricProposal.Proposal chaincodeProposal) {
        this.chaincodeProposal = chaincodeProposal;
        return this;
    }

    public TransactionBuilder endorsements(Collection<FabricProposalResponse.Endorsement> endorsements) {
        this.endorsements = endorsements;
        return this;
    }

    public TransactionBuilder proposalResponcePayload(FabricProposal.ChaincodeProposalPayload proposalResponcePayload) {
        this.proposalResponcePayload = proposalResponcePayload;
        return this;
    }


    public Common.Payload build() throws InvalidProtocolBufferException {

        return createTransactionCommonPayload(chaincodeProposal, proposalResponcePayload, endorsements);

    }


    private Common.Payload createTransactionCommonPayload(FabricProposal.Proposal chaincodeProposal, FabricProposal.ChaincodeProposalPayload proposalResponcePayload,
                                                          Collection<FabricProposalResponse.Endorsement> endorsements) throws InvalidProtocolBufferException {

        //ChaincodeEndorsedAction
        // -- proposalResponcePayload
        // -- Endorsemens
        FabricTransaction.ChaincodeEndorsedAction.Builder chaincodeEndorsedActionBuilder = FabricTransaction.ChaincodeEndorsedAction.newBuilder();
        chaincodeEndorsedActionBuilder.setProposalResponsePayload(proposalResponcePayload.toByteString());
        chaincodeEndorsedActionBuilder.addAllEndorsements(endorsements);

        //ChaincodeActionPayload
        FabricTransaction.ChaincodeActionPayload.Builder chaincodeActionPayloadBuilder = FabricTransaction.ChaincodeActionPayload.newBuilder();
        chaincodeActionPayloadBuilder.setAction(chaincodeEndorsedActionBuilder.build());

        //We need to remove any transient fields - they are not part of what the peer uses to calculate hash.
        FabricProposal.ChaincodeProposalPayload.Builder chaincodeProposalPayloadNoTransBuilder = FabricProposal.ChaincodeProposalPayload.newBuilder();
        chaincodeProposalPayloadNoTransBuilder.mergeFrom(chaincodeProposal.getPayload());
        chaincodeProposalPayloadNoTransBuilder.clearTransient();

        byte[] bhash = hash.apply(chaincodeProposalPayloadNoTransBuilder.build().toByteArray());


        chaincodeActionPayloadBuilder.setChaincodeProposalPayload(ByteString.copyFrom(bhash));

        //TransactionAction
        // --Header
        // --payload (chaincodeActionPayload)
        FabricTransaction.TransactionAction.Builder transactionActionBuilder = FabricTransaction.TransactionAction.newBuilder();

        Common.Header header = Common.Header.parseFrom(chaincodeProposal.getHeader());

        logger.trace("transaction header bytes:" + Arrays.toString(header.toByteArray()));
        logger.trace("transaction header sig bytes:" + Arrays.toString(header.getSignatureHeader().toByteArray()));

        transactionActionBuilder.setHeader(header.getSignatureHeader().toByteString());

        FabricTransaction.ChaincodeActionPayload chaincodeActionPayload = chaincodeActionPayloadBuilder.build();
        logger.trace("transactionActionBuilder.setPayload" + Arrays.toString(chaincodeActionPayload.toByteString().toByteArray()));
        transactionActionBuilder.setPayload(chaincodeActionPayload.toByteString());

        //Transaction
        FabricTransaction.Transaction.Builder transactionBuilder = FabricTransaction.Transaction.newBuilder();
        transactionBuilder.addActions(transactionActionBuilder.build());


        //Build message Payload
        // --Header
        // --Data (transaction)
        Common.Payload.Builder payload = Common.Payload.newBuilder();
        payload.setHeader(header);
        payload.setData(transactionBuilder.build().toByteString());

        return payload.build();


    }

}
