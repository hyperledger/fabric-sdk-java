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

public class LifecycleQueryChaincodeDefinitionsBuilder extends LifecycleProposalBuilder {

    private LifecycleQueryChaincodeDefinitionsBuilder() {
    }

    @Override
    public LifecycleQueryChaincodeDefinitionsBuilder context(TransactionContext context) {
        super.context(context);
        return this;
    }

    public static LifecycleQueryChaincodeDefinitionsBuilder newBuilder() {
        return new LifecycleQueryChaincodeDefinitionsBuilder();
    }

    @Override
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {
        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("QueryChaincodeDefinitions"));
        argList.add(Lifecycle.QueryChaincodeDefinitionsArgs.getDefaultInstance().toByteString());
        args(argList);
        return super.build();
    }
}
