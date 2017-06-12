/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
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
import org.hyperledger.fabric.sdk.exception.ProposalException;

public class JoinPeerProposalBuilder extends CSCCProposalBuilder {
    private static final Log logger = LogFactory.getLog(JoinPeerProposalBuilder.class);

    public JoinPeerProposalBuilder genesisBlock(Block genesisBlock) throws ProposalException {

        if (genesisBlock == null) {
            ProposalException exp = new ProposalException("No genesis block for Join proposal.");
            JoinPeerProposalBuilder.logger.error(exp.getMessage(), exp);
            throw exp;
        }

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom("JoinChain", StandardCharsets.UTF_8));
        argList.add(genesisBlock.toByteString());
        args(argList);
        return this;
    }

    private JoinPeerProposalBuilder() {

    }

    @Override
    public JoinPeerProposalBuilder context(TransactionContext context) {
        super.context(context);
        return this;
    }

    public static JoinPeerProposalBuilder newBuilder() {
        return new JoinPeerProposalBuilder();
    }

}

