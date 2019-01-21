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
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;

public class LifecycleQueryNamespaceDefinitionsBuilder extends LifecycleProposalBuilder {

    private LifecycleQueryNamespaceDefinitionsBuilder() {
    }

    @Override
    public LifecycleQueryNamespaceDefinitionsBuilder context(TransactionContext context) {
        super.context(context);
        return this;
    }

    public static LifecycleQueryNamespaceDefinitionsBuilder newBuilder() {
        return new LifecycleQueryNamespaceDefinitionsBuilder();
    }

    @Override
    public FabricProposal.Proposal build() throws ProposalException, InvalidArgumentException {

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("QueryNamespaceDefinitions"));
        argList.add(Lifecycle.QueryNamespaceDefinitionsArgs.getDefaultInstance().toByteString());
        args(argList);
        return super.build();
    }
}
