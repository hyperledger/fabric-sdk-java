/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.util.List;

import com.google.protobuf.ByteString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInput;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInvocationSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeHeaderExtension;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeProposalPayload;
import org.hyperledger.fabric.sdk.exception.CryptoException;

import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createChannelHeader;


public class ProposalBuilder {


    private final Log logger = LogFactory.getLog(ProposalBuilder.class);


    private Chaincode.ChaincodeID chaincodeID;
    private List<ByteString> argList;
    protected TransactionContext context;
    private ChaincodeSpec.Type ccType = ChaincodeSpec.Type.GOLANG;
    private String chainID;


    protected ProposalBuilder() {
    }

    public static ProposalBuilder newBuilder() {
        return new ProposalBuilder();
    }

    public ProposalBuilder chaincodeID(Chaincode.ChaincodeID chaincodeID) {
        this.chaincodeID = chaincodeID;
        return this;
    }

    public ProposalBuilder args(List<ByteString> argList) {
        this.argList = argList;
        return this;
    }

    public ProposalBuilder context(TransactionContext context) {
        this.context = context;
        if (null == chainID) {
            chainID = context.getChain().getName(); //Default to context chain.
        }
        return this;
    }

    /**
     * The chain that is being targeted . note blank string means no specific chain.
     *
     * @param chainID
     */

    public void chainID(String chainID) {
        this.chainID = chainID;
    }


    public FabricProposal.Proposal build() throws Exception {
        return createFabricProposal(chainID, chaincodeID, argList);
    }


    private FabricProposal.Proposal createFabricProposal(String chainID, Chaincode.ChaincodeID chaincodeID, List<ByteString> argList) throws CryptoException {


        ChaincodeHeaderExtension chaincodeHeaderExtension = ChaincodeHeaderExtension.newBuilder()
                .setChaincodeId(chaincodeID).build();

        Common.ChannelHeader chainHeader = createChannelHeader(HeaderType.ENDORSER_TRANSACTION,
                context.getTxID(), chainID, context.getEpoch(), chaincodeHeaderExtension);

        Common.SignatureHeader sigHeader = Common.SignatureHeader.newBuilder()
                .setCreator(context.getIdentity().toByteString())
                .setNonce(context.getNonce()).build();

        ChaincodeInvocationSpec chaincodeInvocationSpec = createChaincodeInvocationSpec(
                chaincodeID,
                ccType, argList);

        ChaincodeProposalPayload payload = ChaincodeProposalPayload.newBuilder()
                .setInput(chaincodeInvocationSpec.toByteString())
                .build();

        Common.Header header = Common.Header.newBuilder()
                .setSignatureHeader(sigHeader.toByteString())
                .setChannelHeader(chainHeader.toByteString())
                .build();

        return FabricProposal.Proposal.newBuilder()
                .setHeader(header.toByteString())
                .setPayload(payload.toByteString())
                .build();

    }


    private ChaincodeInvocationSpec createChaincodeInvocationSpec(Chaincode.ChaincodeID chainCodeId, ChaincodeSpec.Type langType, List<ByteString> args) {

        ChaincodeInput chaincodeInput = ChaincodeInput.newBuilder().addAllArgs(args).build();

        ChaincodeSpec chaincodeSpec = ChaincodeSpec.newBuilder()
                .setType(langType)
                .setChaincodeId(chainCodeId)
                .setInput(chaincodeInput)
                .build();

        return ChaincodeInvocationSpec.newBuilder()
                .setChaincodeSpec(chaincodeSpec).build();

    }


    public ProposalBuilder ccType(ChaincodeSpec.Type ccType) {
        this.ccType = ccType;
        return this;
    }

}