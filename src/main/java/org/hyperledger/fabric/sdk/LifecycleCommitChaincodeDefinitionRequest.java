/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;

import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;

/**
 * LifecycleCommitChaincodeDefinitionRequest parameters for defining chaincode with lifecycle
 */
public class LifecycleCommitChaincodeDefinitionRequest extends LifecycleRequest {
    private static final Config config = Config.getConfig();
    protected String chaincodeName;
    // The version of the chaincode
    protected String chaincodeVersion;

    private long sequence;
    private ChaincodeCollectionConfiguration chaincodeCollectionConfiguration;

    private String chaincodeEndorsementPlugin = null;
    private Boolean initRequired = null;

    private ByteString validationParameter = null;
    private String chaincodeValidationPlugin;

    LifecycleCommitChaincodeDefinitionRequest(User userContext) {
        super(userContext);
    }

    Boolean isInitRequired() {
        return initRequired;
    }

    /**
     * Optional. The default is that chaincode init is not required.
     * If set to true requires chaincode to have an init method and be called before any invoke methods.
     *
     * @param initRequired
     */
    public void setInitRequired(boolean initRequired) {
        this.initRequired = initRequired;
    }

    String getChaincodeName() {
        return chaincodeName;
    }

    /**
     * The chain code name that's being defined.
     *
     * @param chaincodeName the name.
     */
    public void setChaincodeName(String chaincodeName) throws InvalidArgumentException {

        if (isNullOrEmpty(chaincodeName)) {
            throw new InvalidArgumentException("The chaincodeName parameter can not be null or empty.");
        }

        this.chaincodeName = chaincodeName;
    }

    String getChaincodeVersion() {
        return chaincodeVersion;
    }

    /**
     * The chaincode version. This can be anything you like. Fabric does not parse or validate it's content.
     *
     * @param chaincodeVersion
     */

    public void setChaincodeVersion(String chaincodeVersion) throws InvalidArgumentException {

        if (isNullOrEmpty(chaincodeVersion)) {
            throw new InvalidArgumentException("The chaincodeVersion parameter can not be null or empty.");
        }

        this.chaincodeVersion = chaincodeVersion;

    }

    long getSequence() {
        return sequence;
    }

    /**
     * The sequence that this defintion is being used.
     *
     * @param sequence
     */
    public void setSequence(long sequence) {
        this.sequence = sequence;
    }

    ChaincodeCollectionConfiguration getChaincodeCollectionConfiguration() {
        return this.chaincodeCollectionConfiguration;
    }

    /**
     * The Collections this chaincode will use.
     *
     * @param chaincodeCollectionConfiguration
     * @throws InvalidArgumentException
     */
    public void setChaincodeCollectionConfiguration(ChaincodeCollectionConfiguration chaincodeCollectionConfiguration) throws InvalidArgumentException {
        if (null == chaincodeCollectionConfiguration) {
            throw new InvalidArgumentException(" The parameter chaincodeCollectionConfiguration may not be null.");
        }
        this.chaincodeCollectionConfiguration = chaincodeCollectionConfiguration;
    }

    /**
     * The endorsement policy used by this chaincode. Only this or {@link #setValidationParameter(byte[])} maybe used in one request.
     *
     * @param chaincodeEndorsementPolicy
     * @throws InvalidArgumentException
     */
    public void setChaincodeEndorsementPolicy(LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy) throws InvalidArgumentException {
        if (null == chaincodeEndorsementPolicy) {
            throw new InvalidArgumentException(" The parameter chaincodeEndorsementPolicy may not be null.");
        }
        validationParameter = chaincodeEndorsementPolicy.getByteString();
    }

    String getChaincodeEndorsementPlugin() {
        return chaincodeEndorsementPlugin;
    }

    /**
     * The endosment plugin name for this chaincode. Optional and should probably not be set.
     *
     * @param chaincodeEndorsementPlugin
     * @throws InvalidArgumentException
     */
    public void setChaincodeEndorsementPlugin(String chaincodeEndorsementPlugin) throws InvalidArgumentException {
        if (isNullOrEmpty(chaincodeEndorsementPlugin)) {
            throw new InvalidArgumentException("The chaincodeEndorsementPlugin parameter can not be null or empty.");
        }

        this.chaincodeEndorsementPlugin = chaincodeEndorsementPlugin;
    }

    String getChaincodeValidationPlugin() {

        return chaincodeValidationPlugin;
    }

    /**
     * The chaincode validation parameter to be used with this chaincode. Optional and should probably not be set.
     *
     * @param chaincodeValidationPlugin
     * @throws InvalidArgumentException
     */
    public void setChaincodeValidationPlugin(String chaincodeValidationPlugin) throws InvalidArgumentException {
        if (isNullOrEmpty(chaincodeValidationPlugin)) {
            throw new InvalidArgumentException("The chaincodeValidationPlugin parameter can not be null or empty.");
        }
        this.chaincodeValidationPlugin = chaincodeValidationPlugin;
    }

    ByteString getValidationParameter() {
        return validationParameter;
    }

    /**
     * The validation parameter to be used with this chaincode. Only this or {@link #setChaincodeEndorsementPolicy(LifecycleChaincodeEndorsementPolicy)} maybe set in a single request.
     *
     * @param validationParameter
     * @throws InvalidArgumentException
     */
    public void setValidationParameter(byte[] validationParameter) throws InvalidArgumentException {
        if (null == validationParameter) {
            throw new InvalidArgumentException(" The parameter validationParameter may not be null.");
        }

        this.validationParameter = ByteString.copyFrom(validationParameter);
    }
}
