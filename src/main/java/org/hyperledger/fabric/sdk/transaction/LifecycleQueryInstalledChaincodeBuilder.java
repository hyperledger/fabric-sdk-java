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

public class LifecycleQueryInstalledChaincodeBuilder extends LifecycleProposalBuilder {

    private String packageId;

    private LifecycleQueryInstalledChaincodeBuilder() {
        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("QueryInstalledChaincode"));

        args(argList);
    }

    @Override
    public LifecycleQueryInstalledChaincodeBuilder context(TransactionContext context) {
        super.context(context);
        return this;
    }

    public static LifecycleQueryInstalledChaincodeBuilder newBuilder() {
        return new LifecycleQueryInstalledChaincodeBuilder();
    }

    public LifecycleQueryInstalledChaincodeBuilder setPackageId(String packageId) {

        this.packageId = packageId;
        return this;
    }

    @Override
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {
        argList.add(Lifecycle.QueryInstalledChaincodeArgs.newBuilder().setPackageId(packageId).build().toByteString());
        return super.build();
    }
}
