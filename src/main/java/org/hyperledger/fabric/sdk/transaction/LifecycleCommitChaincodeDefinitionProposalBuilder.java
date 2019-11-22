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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Collection;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.helper.Utils;

public class LifecycleCommitChaincodeDefinitionProposalBuilder extends LifecycleProposalBuilder {

    private static final Log logger = LogFactory.getLog(LifecycleCommitChaincodeDefinitionProposalBuilder.class);
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final Config config = Config.getConfig();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;
    private Lifecycle.CommitChaincodeDefinitionArgs.Builder builder = Lifecycle.CommitChaincodeDefinitionArgs.newBuilder();

    static Boolean lifecycleInitRequiredDefault = null;

    static {
        lifecycleInitRequiredDefault = config.getLifecycleInitRequiredDefault();
    }

    protected LifecycleCommitChaincodeDefinitionProposalBuilder() {
        super();
        if (!Utils.isNullOrEmpty(config.getDefaultChaincodeEndorsementPlugin())) {
            builder.setEndorsementPlugin(config.getDefaultChaincodeEndorsementPlugin());
        }

        if (!Utils.isNullOrEmpty(config.getDefaultChaincodeValidationPlugin())) {
            builder.setValidationPlugin(config.getDefaultChaincodeValidationPlugin());
        }

        if (lifecycleInitRequiredDefault != null) {
            builder.setInitRequired(lifecycleInitRequiredDefault);
        }
    }

    public static LifecycleCommitChaincodeDefinitionProposalBuilder newBuilder() {
        return new LifecycleCommitChaincodeDefinitionProposalBuilder();
    }

    @Override
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {
        constructProposal();
        return super.build();
    }

    public void chaincodeName(String name) {
        builder.setName(name);
    }

    public void initRequired(boolean initRequired) {
        builder.setInitRequired(initRequired);
    }

    public void version(String version) {
        builder.setVersion(version);
    }

    public void sequence(long sequence) {
        builder.setSequence(sequence);
    }

    public void setValidationParamter(ByteString validationParamter) {
        builder.setValidationParameter(validationParamter);
    }

    //Optional
    public void collectionsConfig(Collection.CollectionConfigPackage collectionsConfig) {
        builder.setCollections(collectionsConfig);
    }

    void endorsementPolicy(byte[] endorsmentPolicyBytes) {
        builder.setValidationParameter(ByteString.copyFrom(endorsmentPolicyBytes));
    }

    private void constructProposal() {
        // set args
        final List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("CommitChaincodeDefinition"));
        argList.add(builder.build().toByteString());
        args(argList);
    }

    public void chaincodeCollectionConfiguration(Collection.CollectionConfigPackage collectionConfigPackage) {
        builder.setCollections(collectionConfigPackage);
    }

    public void chaincodeCodeEndorsementPlugin(String chaincodeEndorsementPlugin) {
        if (!Utils.isNullOrEmpty(chaincodeEndorsementPlugin)) {
            builder.setEndorsementPlugin(chaincodeEndorsementPlugin);
        }
    }

    public void chaincodeCodeValidationPlugin(String chaincodeValidationPlugin) {
        if (!Utils.isNullOrEmpty(chaincodeValidationPlugin)) {
            builder.setValidationPlugin(chaincodeValidationPlugin);
        }
    }
}