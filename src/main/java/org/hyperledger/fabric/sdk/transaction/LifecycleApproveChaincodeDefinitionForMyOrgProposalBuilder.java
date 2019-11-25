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
import org.hyperledger.fabric.protos.peer.Collection.CollectionConfigPackage;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.helper.Utils;

public class LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder extends LifecycleProposalBuilder {

    private static final Log logger = LogFactory.getLog(LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder.class);
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final Config config = Config.getConfig();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;
    private Lifecycle.ApproveChaincodeDefinitionForMyOrgArgs.Builder builder = Lifecycle.ApproveChaincodeDefinitionForMyOrgArgs.newBuilder();

    static Boolean lifecycleInitRequiredDefault = null;

    static {
        lifecycleInitRequiredDefault = config.getLifecycleInitRequiredDefault();
    }

    protected LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder() {
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

        builder.setSource(Lifecycle.ChaincodeSource.newBuilder()
                .setUnavailable(Lifecycle.ChaincodeSource.Unavailable.newBuilder().build()).build());

    }

    public static LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder newBuilder() {
        return new LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder();

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

    public void setPackageId(String packageId) {

        builder.setSource(Lifecycle.ChaincodeSource.newBuilder()
                .setLocalPackage(Lifecycle.ChaincodeSource.Local.newBuilder().setPackageId(packageId).build()));
    }

    public void sequence(long sequence) {
        builder.setSequence(sequence);
    }

    public void setValidationParamter(ByteString validationParamter) {
        builder.setValidationParameter(validationParamter);
    }

    //Optional
    public void collectionsConfig(CollectionConfigPackage collectionsConfig) {
        builder.setCollections(collectionsConfig);

    }

    void endorsementPolicy(byte[] endorsmentPolicyBytes) {
        builder.setValidationParameter(ByteString.copyFrom(endorsmentPolicyBytes));
    }

    private void constructProposal() {

        // set args
        final List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFromUtf8("ApproveChaincodeDefinitionForMyOrg"));
        argList.add(builder.build().toByteString());
        args(argList);

    }

    public void chaincodeCollectionConfiguration(CollectionConfigPackage collectionConfigPackage) {

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