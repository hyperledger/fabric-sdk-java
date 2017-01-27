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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.ChainHeader;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeHeaderExtension;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;
import java.util.List;

import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createChainHeader;


public class ProposalBuilder {


    private final Log logger = LogFactory.getLog(ProposalBuilder.class);


    private Chaincode.ChaincodeID chaincodeID;
    private List<ByteString> argList;
    protected TransactionContext context;
    private Chaincode.ChaincodeSpec.Type ccType = Chaincode.ChaincodeSpec.Type.GOLANG;


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
        return this;
    }


    public FabricProposal.Proposal build() throws Exception {
        return createFabricProposal(context.getChain().getName(), chaincodeID, argList);
    }


    private FabricProposal.Proposal createFabricProposal(String chainID, Chaincode.ChaincodeID chaincodeID, List<ByteString> argList) throws Exception {

        Chaincode.ChaincodeInvocationSpec chaincodeInvocationSpec = createChaincodeInvocationSpec(
                chaincodeID,
                ccType, argList);


        ChaincodeHeaderExtension.Builder chaincodeHeaderExtension = ChaincodeHeaderExtension.newBuilder();


        chaincodeHeaderExtension.setChaincodeID(chaincodeID);


        ChainHeader chainHeader = createChainHeader(HeaderType.ENDORSER_TRANSACTION,
                context.getTxID(), chainID, 0, chaincodeHeaderExtension.build());

        Common.SignatureHeader.Builder sigHeaderBldr = Common.SignatureHeader.newBuilder();

        Identities.SerializedIdentity.Builder identity = Identities.SerializedIdentity.newBuilder();
        identity.setIdBytes(ByteString.copyFromUtf8(context.getCreator()));
        identity.setMspid(context.getMSPID());


        sigHeaderBldr.setCreator(identity.build().toByteString());
        sigHeaderBldr.setNonce(context.getNonce());

        Common.SignatureHeader sigHeader = sigHeaderBldr.build();
        logger.trace("proposal header sig bytes:" + Arrays.toString(sigHeader.toByteArray()));


        Common.Header.Builder headerbldr = Common.Header.newBuilder();
        headerbldr.setSignatureHeader(sigHeader);
        headerbldr.setChainHeader(chainHeader);

        FabricProposal.ChaincodeProposalPayload.Builder payloadBuilder = FabricProposal.ChaincodeProposalPayload.newBuilder();

        payloadBuilder.setInput(chaincodeInvocationSpec.toByteString());
        FabricProposal.ChaincodeProposalPayload payload = payloadBuilder.build();

        logger.trace("proposal payload. length " + payload.toByteArray().length + ",  hashcode:" + payload.toByteArray().hashCode() + ", hex:" + DatatypeConverter.printHexBinary(payload.toByteArray()));
        logger.trace("256 HASH: " + DatatypeConverter.printHexBinary(context.getCryptoPrimitives().hash(payload.toByteArray())));


        FabricProposal.Proposal.Builder proposalBuilder = FabricProposal.Proposal.newBuilder();


        Common.Header header = headerbldr.build();
        logger.trace("proposal header bytes:" + Arrays.toString(header.toByteArray()));

        proposalBuilder.setHeader(headerbldr.build().toByteString());
        proposalBuilder.setPayload(payload.toByteString());


        return proposalBuilder.build();

    }


    private Chaincode.ChaincodeInvocationSpec createChaincodeInvocationSpec(Chaincode.ChaincodeID chainCodeId, Chaincode.ChaincodeSpec.Type langType, List<ByteString> args) {

        Chaincode.ChaincodeInvocationSpec.Builder invocationSpecBuilder = Chaincode.ChaincodeInvocationSpec.newBuilder();
        Chaincode.ChaincodeSpec.Builder chaincodeSpecBuilder = Chaincode.ChaincodeSpec.newBuilder();

        chaincodeSpecBuilder.setType(langType);

        chaincodeSpecBuilder.setChaincodeID(chainCodeId);

        Chaincode.ChaincodeInput chaincodeInput = Chaincode.ChaincodeInput.newBuilder().addAllArgs(args).build();

        chaincodeSpecBuilder.setInput(chaincodeInput);

        invocationSpecBuilder.setChaincodeSpec(chaincodeSpecBuilder.build());

        // invocationSpecBuilder.setIdGenerationAlg("");


        return invocationSpecBuilder.build();

    }


    public ProposalBuilder ccType(Chaincode.ChaincodeSpec.Type ccType) {
        this.ccType = ccType;
        return this;
    }
}