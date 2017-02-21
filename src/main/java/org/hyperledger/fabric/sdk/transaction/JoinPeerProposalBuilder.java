/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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


import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.ProposalException;

import static org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec.Type.GOLANG;

public class JoinPeerProposalBuilder extends ProposalBuilder {
    private static final Log logger = LogFactory.getLog(ProposalBuilder.class);

    private static final String CSCC_CHAIN_NAME = "cscc";

    private static final Chaincode.ChaincodeID CHAINCODE_ID_CSCC =
            Chaincode.ChaincodeID.newBuilder().setName(CSCC_CHAIN_NAME).build();

    private Block genesisBlock;

    public JoinPeerProposalBuilder genesisBlock(Block genesisBlock) {
        this.genesisBlock = genesisBlock;
        return this;
    }

    @Override
    public JoinPeerProposalBuilder context(TransactionContext context) {
        return (JoinPeerProposalBuilder) super.context(context);
    }

    private JoinPeerProposalBuilder() {

    }

    public static JoinPeerProposalBuilder newBuilder() {
        return new JoinPeerProposalBuilder();
    }


    @Override
    public FabricProposal.Proposal build() throws ProposalException, CryptoException {

        if (genesisBlock == null) {
            ProposalException exp = new ProposalException("No genesis block for Join proposal.");
            logger.error(exp.getMessage(), exp);
            throw exp;
        }

        ccType(GOLANG);
        chaincodeID(CHAINCODE_ID_CSCC);

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom("JoinChain", StandardCharsets.UTF_8));
        argList.add(genesisBlock.toByteString());
        args(argList);

        chainID(""); //no specific chain -- system chain.

        return super.build();

    }
}

