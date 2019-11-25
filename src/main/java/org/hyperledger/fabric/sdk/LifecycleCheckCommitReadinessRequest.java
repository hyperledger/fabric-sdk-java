/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.Collection;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;

import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;

/**
 * Queries the approval status of organizations for chaincode sequence.
 */
public class LifecycleCheckCommitReadinessRequest extends LifecycleRequest {
    private static final Config config = Config.getConfig();
    private static final Boolean lifecycleInitRequiredDefault = config.getLifecycleInitRequiredDefault();

    private long sequence;
    private String chaincodeName;
    private String chaincodeVersion;
    private String chaincodeEndorsementPlugin;
    private String chaincodeValidationPlugin;
    private Collection.CollectionConfigPackage collectionConfigPackage;
    private Boolean initRequired;
    private ByteString validationParameter;

    LifecycleCheckCommitReadinessRequest(User userContext) {
        super(userContext);
        if (!isNullOrEmpty(config.getDefaultChaincodeEndorsementPlugin())) {
            chaincodeEndorsementPlugin = config.getDefaultChaincodeEndorsementPlugin();
        }

        if (!isNullOrEmpty(config.getDefaultChaincodeValidationPlugin())) {
            chaincodeValidationPlugin = config.getDefaultChaincodeValidationPlugin();
        }

        initRequired = lifecycleInitRequiredDefault;
    }

    ByteString getValidationParameter() {
        return validationParameter;
    }

    /**
     * The validation parameter. Only this or {link {@link #setChaincodeEndorsementPolicy(LifecycleChaincodeEndorsementPolicy)}}
     * may be used at one time.
     *
     * @param validationParameter
     * @throws InvalidArgumentException
     */
    public void setValidationParameter(byte[] validationParameter) throws InvalidArgumentException {
        if (null == validationParameter) {
            throw new InvalidArgumentException("The parameter validationParameter may not be null.");
        }
        this.validationParameter = ByteString.copyFrom(validationParameter);
    }

    long getSequence() {
        return sequence;
    }

    /**
     * The sequence for the approval being queried for.
     *
     * @param sequence
     */
    public void setSequence(long sequence) {
        this.sequence = sequence;
    }

    String getChaincodeName() {
        return chaincodeName;
    }

    /**
     * The chaincode name for the approval being queried for.
     *
     * @param chaincodeName
     * @throws InvalidArgumentException
     */
    public void setChaincodeName(String chaincodeName) throws InvalidArgumentException {
        if (isNullOrEmpty(chaincodeName)) {
            throw new InvalidArgumentException("The name parameter can not be null or empty.");
        }
        this.chaincodeName = chaincodeName;
    }

    String getChaincodeVersion() {
        return chaincodeVersion;
    }

    /**
     * The chaincode version for the approval being queried for.
     *
     * @param chaincodeVersion
     * @throws InvalidArgumentException
     */
    public void setChaincodeVersion(String chaincodeVersion) throws InvalidArgumentException {
        if (isNullOrEmpty(chaincodeVersion)) {
            throw new InvalidArgumentException("The version parameter can not be null or empty.");
        }
        this.chaincodeVersion = chaincodeVersion;
    }

    String getChaincodeEndorsementPlugin() {
        return chaincodeEndorsementPlugin;
    }

    /**
     * The chaincode endorsement plugin for the approval being queried for.
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
     * The chaincode validation plugin for the approval being queried for.
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

    /**
     * The chaincode endorsment policy for the approval being queried for. Only this or {link {@link #setValidationParameter(byte[])}}
     * may be used in a request.
     *
     * @param lifecycleChaincodeEndorsementPolicy
     * @throws InvalidArgumentException
     */
    public void setChaincodeEndorsementPolicy(LifecycleChaincodeEndorsementPolicy lifecycleChaincodeEndorsementPolicy) throws InvalidArgumentException {
        if (null == lifecycleChaincodeEndorsementPolicy) {
            throw new InvalidArgumentException("The parameter lifecycleChaincodeEndorsementPolicy may not be null.");
        }
        this.validationParameter = lifecycleChaincodeEndorsementPolicy.getByteString();
    }

    Collection.CollectionConfigPackage getCollectionConfigPackage() {
        return collectionConfigPackage;
    }

    Boolean isInitRequired() {
        return initRequired;
    }

    /**
     * The init required for the approval being queried for.
     *
     * @param initRequired
     */
    public void setInitRequired(boolean initRequired) {
        this.initRequired = initRequired;
    }

    /**
     * The collection configuration for the approval being queried for.
     *
     * @param collectionConfigPackage
     * @throws InvalidArgumentException
     */
    public void setChaincodeCollectionConfiguration(ChaincodeCollectionConfiguration collectionConfigPackage) throws InvalidArgumentException {
        if (null == collectionConfigPackage) {
            throw new InvalidArgumentException("The parameter collectionConfigPackage may not be null.");
        }

        this.collectionConfigPackage = collectionConfigPackage.getCollectionConfigPackage();
    }

}
