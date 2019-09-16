/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.util.Collection;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;

/**
 * LifecycleApproveChaincodeDefinitionForMyOrgRequest parameters for approving chaincode with lifecycle.
 * Send to peers with {@link Channel#sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(LifecycleApproveChaincodeDefinitionForMyOrgRequest, Collection)}
 */
public class LifecycleApproveChaincodeDefinitionForMyOrgRequest extends LifecycleRequest {
    private static final Config config = Config.getConfig();
    protected String chaincodeName;
    // The version of the chaincode
    protected String chaincodeVersion;

    private String packageId;
    private boolean sourceUnavailable = false; // there is no packageId source
    private long sequence;
    private ChaincodeCollectionConfiguration chaincodeCollectionConfiguration;
    private String chaincodeEndorsementPlugin = null;
    private Boolean initRequired = null;
    private String chaincodeValidationPlugin = null;
    private ByteString validationParameter = null;

    LifecycleApproveChaincodeDefinitionForMyOrgRequest(User userContext) {
        super(userContext);
    }

    boolean isSourceUnavailable() {
        return sourceUnavailable;
    }

    /**
     * There is no specific packageId for this approval.
     *
     * @param sourceUnavailable
     * @throws InvalidArgumentException
     */
    public void setSourceUnavailable(boolean sourceUnavailable) throws InvalidArgumentException {
        if (packageId != null) {
            throw new InvalidArgumentException("Source none can not be set to true if packageId has been provided already");
        }
        this.sourceUnavailable = sourceUnavailable;
    }

    /**
     * The chaincode validation parameter. Only this or chaincode endorsement policy {@link #setChaincodeEndorsementPolicy(LifecycleChaincodeEndorsementPolicy)} may be set at any one time.
     *
     * @param validationParameter
     * @throws InvalidArgumentException
     */
    public void setValidationParameter(byte[] validationParameter) throws InvalidArgumentException {
        if (null == validationParameter) {
            throw new InvalidArgumentException("The valdiationParameter parameter can not be null.");
        }
        this.validationParameter = ByteString.copyFrom(validationParameter);

    }

    /**
     * The chaincode endorsement policy. Only this or setValdationParamter {@link #setValidationParameter(byte[])} maybe set at any one time.
     *
     * @param lifecycleChaincodeEndorsementPolicy
     * @throws InvalidArgumentException
     */

    public void setChaincodeEndorsementPolicy(LifecycleChaincodeEndorsementPolicy lifecycleChaincodeEndorsementPolicy) throws InvalidArgumentException {
        if (null == lifecycleChaincodeEndorsementPolicy) {
            throw new InvalidArgumentException("The lifecycleChaincodeEndorsementPolicy parameter can not be null.");
        }
        this.validationParameter = lifecycleChaincodeEndorsementPolicy.getByteString();
    }

    Boolean isInitRequired() {
        return initRequired;
    }

    /**
     * If set the chaincode will need to have an explicit initializer. See {@link TransactionProposalRequest#setInit(boolean)} must be true, for first invoke.
     * Optional and if not set the chaincode will default to false with the chaincode not needing an initializer.
     *
     * @param initRequired set to true in chaincode will need initialization.
     */
    public void setInitRequired(boolean initRequired) {
        this.initRequired = initRequired;
    }

    String getChaincodeName() {
        return chaincodeName;
    }

    /**
     * The name of the chaincode to approve.
     *
     * @param chaincodeName
     */
    public void setChaincodeName(String chaincodeName) throws InvalidArgumentException {
        if (Utils.isNullOrEmpty(chaincodeName)) {
            throw new InvalidArgumentException("The chaincodeName parameter can not be null or empty.");
        }
        this.chaincodeName = chaincodeName;
    }

    String getChaincodeVersion() {

        return chaincodeVersion;
    }

    /**
     * The version of the chaincode to approve.
     *
     * @param chaincodeVersion the version.
     */

    public void setChaincodeVersion(String chaincodeVersion) throws InvalidArgumentException {
        if (Utils.isNullOrEmpty(chaincodeVersion)) {
            throw new InvalidArgumentException("The chaincodeVersion parameter can not be null or empty.");
        }
        this.chaincodeVersion = chaincodeVersion;

    }

    long getSequence() {
        return sequence;
    }

    /**
     * The sequence of this change. Latest sequence can be determined from {@link QueryLifecycleQueryChaincodeDefinitionRequest}
     *
     * @param sequence
     */
    public void setSequence(long sequence) {
        this.sequence = sequence;
    }

    String getPackageId() {

        return packageId;
    }

    /**
     * The packageId being approved. This is the package id gotten from {@link LifecycleInstallChaincodeProposalResponse#getPackageId()}
     * or from {@link LifecycleQueryInstalledChaincodesProposalResponse}, {@link LifecycleQueryInstalledChaincodeProposalResponse}
     * <p>
     * Only packageID or the sourceUnavailable to true may be set any time.
     *
     * @param packageId the package ID
     * @throws InvalidArgumentException
     */

    public void setPackageId(String packageId) throws InvalidArgumentException {
        if (sourceUnavailable) {
            throw new InvalidArgumentException("The source none has be set to true already. Can not have packageId set when source none set to true.");
        }
        if (Utils.isNullOrEmpty(packageId)) {
            throw new InvalidArgumentException("The packageId parameter can not be null or empty.");
        }

        this.packageId = packageId;

    }

    ChaincodeCollectionConfiguration getChaincodeCollectionConfiguration() {
        return this.chaincodeCollectionConfiguration;
    }

    /**
     * The collections configuration for this chaincode;
     *
     * @param chaincodeCollectionConfiguration the collection configurtation {@link ChaincodeCollectionConfiguration}
     * @throws InvalidArgumentException
     */
    public void setChaincodeCollectionConfiguration(ChaincodeCollectionConfiguration chaincodeCollectionConfiguration) throws InvalidArgumentException {
        if (null == chaincodeCollectionConfiguration) {
            throw new InvalidArgumentException("The chaincodeCollectionConfiguration may not be null");
        }
        this.chaincodeCollectionConfiguration = chaincodeCollectionConfiguration;
    }

    String getChaincodeEndorsementPlugin() {
        return chaincodeEndorsementPlugin;
    }

    String getChaincodeValidationPlugin() {

        return chaincodeValidationPlugin;
    }

    /**
     * This is the chaincode endorsement plugin. Should default, not needing set. ONLY set if there is a specific endorsement is set for your organization
     *
     * @param chaincodeEndorsementPlugin
     * @throws InvalidArgumentException
     */
    public void setChaincodeEndorsementPlugin(String chaincodeEndorsementPlugin) throws InvalidArgumentException {
        if (Utils.isNullOrEmpty(chaincodeEndorsementPlugin)) {
            throw new InvalidArgumentException("The getChaincodeEndorsementPlugin parameter can not be null or empty.");
        }
        this.chaincodeEndorsementPlugin = chaincodeEndorsementPlugin;
    }

    /**
     * This is the chaincode validation plugin. Should default, not needing set. ONLY set if there is a specific validation is set for your organization
     *
     * @param chaincodeValidationPlugin
     * @throws InvalidArgumentException
     */
    public void setChaincodeValidationPlugin(String chaincodeValidationPlugin) throws InvalidArgumentException {
        if (Utils.isNullOrEmpty(chaincodeValidationPlugin)) {
            throw new InvalidArgumentException("The getChaincodeValidationPlugin parameter can not be null or empty.");
        }
        this.chaincodeValidationPlugin = chaincodeValidationPlugin;
    }

    ByteString getValidationParameter() {
        return validationParameter;
    }
}
