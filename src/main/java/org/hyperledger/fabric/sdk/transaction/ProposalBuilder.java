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

import io.netty.util.internal.StringUtil;

import org.hyperledger.fabric.protos.common.Common.ChainHeader;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.common.Common.SignatureHeader;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInput;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInvocationSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec;
import org.hyperledger.fabric.protos.peer.ChaincodeProposal.ChaincodeHeaderExtension;
import org.hyperledger.fabric.protos.peer.ChaincodeProposal.ChaincodeProposalPayload;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal.Proposal;
import org.hyperledger.fabric.sdk.ChaincodeLanguage;

import java.util.List;


public class ProposalBuilder {

    private Chaincode.ChaincodeID chaincodeID;
    private List<ByteString> argList;
    protected TransactionContext context;
    private Chaincode.ChaincodeSpec.Type ccType = Chaincode.ChaincodeSpec.Type.GOLANG ;

    protected ProposalBuilder() {}

    public static ProposalBuilder newBuilder() {
        return new ProposalBuilder();
    }

    public ProposalBuilder chaincodeID(Chaincode.ChaincodeID chaincodeID ) {
        this.chaincodeID = chaincodeID;
        return this;
    }

    public ProposalBuilder args(List<ByteString> argList ) {
        this.argList = argList;
        return this;
    }

    public ProposalBuilder context(TransactionContext context) {
        this.context = context;
        return this;
    }


    public FabricProposal.Proposal build() {
       return createFabricProposal(chaincodeID, argList);
    }

    public Chaincode.ChaincodeID getChaincodeID() {
		return chaincodeID;
	}

	public List<ByteString> getArgList() {
		return argList;
	}

	public TransactionContext getContext() {
		return context;
	}

	public Chaincode.ChaincodeSpec.Type getChaincodeType() {
		return ccType;
	}

	private  FabricProposal.Proposal createFabricProposal(Chaincode.ChaincodeID chaincodeID, List<ByteString> argList) {

        Chaincode.ChaincodeInvocationSpec chaincodeInvocationSpec = createChaincodeInvocationSpec(
                chaincodeID,
                ccType, argList);

        ChaincodeHeaderExtension chaincodeHeaderExtension = 
        		ChaincodeHeaderExtension.newBuilder()
        		.setChaincodeID(chaincodeID).build();
        
        ChainHeader chainHeader = ChainHeader.newBuilder()
        		.setType(HeaderType.ENDORSER_TRANSACTION.getNumber())
        		.setVersion(0)
        		.setChainID(chaincodeID.getName())
        		.setExtension(chaincodeHeaderExtension.toByteString()).build();
        
        SignatureHeader signHeader = SignatureHeader.newBuilder()
        //TODO: set creator and nonce
//        		.setCreator(context.getCreator())
//        		.setNonce(context.getNonce())
        		.build();
        
        Header header =  Header.newBuilder()
        		.setSignatureHeader(signHeader)
        		.setChainHeader(chainHeader)
        		.build();

        ChaincodeProposalPayload payload = ChaincodeProposalPayload.newBuilder()
        		.setInput(chaincodeInvocationSpec.toByteString())
        		.build();

        Proposal proposal = Proposal.newBuilder()
        		.setHeader(header.toByteString())
        		.setPayload(payload.toByteString())
        		.build();

        return proposal;

    }


    private Chaincode.ChaincodeInvocationSpec createChaincodeInvocationSpec(Chaincode.ChaincodeID chainCodeId, Chaincode.ChaincodeSpec.Type langType, List<ByteString> args) {
        ChaincodeInput chaincodeInput = ChaincodeInput.newBuilder()
        		.addAllArgs(args)
        		.build();
        
        ChaincodeSpec chaincodeSpec = ChaincodeSpec.newBuilder()
        		.setType(langType)
        		.setChaincodeID(chainCodeId)
        		.setCtorMsg(chaincodeInput)
        		.build();

        ChaincodeInvocationSpec invocationSpec = ChaincodeInvocationSpec.newBuilder()
        		.setChaincodeSpec(chaincodeSpec)
        		.setIdGenerationAlg("").build();

        return invocationSpec;
    }

    public ProposalBuilder chaincodeType(String lang) {
    	if (!StringUtil.isNullOrEmpty(lang)) {
    		if ("java".equalsIgnoreCase(lang)) {
    			this.ccType = Chaincode.ChaincodeSpec.Type.JAVA;
    		} else {
    			this.ccType = Chaincode.ChaincodeSpec.Type.GOLANG;
    		}
    		
    	}
        
        return this;
    }
    
    public ProposalBuilder chaincodeType(ChaincodeLanguage lang) {
    	if (lang == null) {
    		lang = ChaincodeLanguage.GO_LANG;
    	}
    	
    	switch(lang) {
    	case GO_LANG:
    		this.ccType = Chaincode.ChaincodeSpec.Type.GOLANG;
    		break;
    	case JAVA:
    		this.ccType = Chaincode.ChaincodeSpec.Type.JAVA;
    		break;
    	}   	
        
        return this;
    }
}
