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
import org.hyperledger.fabric.protos.common.Collection;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;

public class LifecycleSimulateCommitChaincodeDefinitionBuilder extends LifecycleProposalBuilder {
    static Config config = Config.getConfig();

    static Boolean lifecycleInitRequiredDefault = null;

    static {
        lifecycleInitRequiredDefault = config.getLifecycleInitRequiredDefault();
    }

    private final Lifecycle.SimulateCommitChaincodeDefinitionArgs.Builder builder = Lifecycle.SimulateCommitChaincodeDefinitionArgs.newBuilder();

    private LifecycleSimulateCommitChaincodeDefinitionBuilder() {

        if (null != lifecycleInitRequiredDefault) {
            builder.setInitRequired(lifecycleInitRequiredDefault);
        }
    }

    @Override
    public LifecycleSimulateCommitChaincodeDefinitionBuilder context(TransactionContext context) {
        super.context(context);
        if (!Utils.isNullOrEmpty(config.getDefaultChaincodeEndorsementPlugin())) {

            builder.setEndorsementPlugin(config.getDefaultChaincodeEndorsementPlugin());
        }

        if (!Utils.isNullOrEmpty(config.getDefaultChaincodeValidationPlugin())) {

            builder.setValidationPlugin(config.getDefaultChaincodeValidationPlugin());
        }

        if (lifecycleInitRequiredDefault != null) {

            builder.setInitRequired(lifecycleInitRequiredDefault);
        }
        return this;
    }

    public static LifecycleSimulateCommitChaincodeDefinitionBuilder newBuilder() {
        return new LifecycleSimulateCommitChaincodeDefinitionBuilder();
    }

    public void setSequence(long sequence) {
        builder.setSequence(sequence);
    }

    public void setName(String name) {
        builder.setName(name);
    }

    public void setVersion(String version) {
        builder.setVersion(version);
    }

    public void setEndorsementPlugin(String endorsementPlugin) {
        builder.setEndorsementPlugin(endorsementPlugin);
    }

    public void setValidationPlugin(String validationPlugin) {
        builder.setValidationPlugin(validationPlugin);
    }

    public void setValidationParameter(ByteString validationParameter) {
        builder.setValidationParameter(validationParameter);
    }

    public void setCollections(Collection.CollectionConfigPackage collectionConfigPackage) {
        builder.setCollections(collectionConfigPackage);
    }

    public void setInitRequired(boolean initRequired) {
        builder.setInitRequired(initRequired);
    }

    @Override
    public FabricProposal.Proposal build() throws ProposalException, InvalidArgumentException {

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("SimulateCommitChaincodeDefinition"));
        argList.add(builder.build().toByteString());
        args(argList);
        return super.build();
    }
}
