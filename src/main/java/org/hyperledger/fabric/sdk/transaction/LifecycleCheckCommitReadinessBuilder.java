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
import org.hyperledger.fabric.protos.peer.Collection;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;

public final class LifecycleCheckCommitReadinessBuilder extends LifecycleProposalBuilder {
    private static final Config config = Config.getConfig();
    private static final Boolean lifecycleInitRequiredDefault = config.getLifecycleInitRequiredDefault();

    private final Lifecycle.CheckCommitReadinessArgs.Builder builder = Lifecycle.CheckCommitReadinessArgs.newBuilder();

    private LifecycleCheckCommitReadinessBuilder() {
        if (null != lifecycleInitRequiredDefault) {
            builder.setInitRequired(lifecycleInitRequiredDefault);
        }
    }

    @Override
    public LifecycleCheckCommitReadinessBuilder context(TransactionContext context) {
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

    public static LifecycleCheckCommitReadinessBuilder newBuilder() {
        return new LifecycleCheckCommitReadinessBuilder();
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
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {
        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("CheckCommitReadiness"));
        argList.add(builder.build().toByteString());
        args(argList);
        return super.build();
    }
}
