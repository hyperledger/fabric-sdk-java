/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk.transaction;

import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;

public class LifecycleQueryChaincodeDefinitionBuilder extends LifecycleProposalBuilder {

    private String chaincodeName;

    private LifecycleQueryChaincodeDefinitionBuilder() {
    }

    @Override
    public LifecycleQueryChaincodeDefinitionBuilder context(TransactionContext context) {
        super.context(context);
        return this;
    }

    public static LifecycleQueryChaincodeDefinitionBuilder newBuilder() {
        return new LifecycleQueryChaincodeDefinitionBuilder();
    }

    public void setChaincodeName(String chaincodeName) {
        this.chaincodeName = chaincodeName;
    }

    @Override
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("QueryChaincodeDefinition"));
        argList.add(Lifecycle.QueryChaincodeDefinitionArgs.newBuilder().setName(chaincodeName).build().toByteString());
        args(argList);
        return super.build();
    }
}
