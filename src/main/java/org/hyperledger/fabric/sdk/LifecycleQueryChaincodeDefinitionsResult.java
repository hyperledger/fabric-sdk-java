/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.sdk;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.Collection;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;

/**
 * Definition of a chaincode.
 */
public final class LifecycleQueryChaincodeDefinitionsResult {
    private final Lifecycle.QueryChaincodeDefinitionsResult.ChaincodeDefinition chaincodeDefinition;

    LifecycleQueryChaincodeDefinitionsResult(Lifecycle.QueryChaincodeDefinitionsResult.ChaincodeDefinition chaincodeDefinition) {
        this.chaincodeDefinition = chaincodeDefinition;
    }

    /**
     * The chaincode name.
     * @return A name.
     */
    public String getName() {
        return chaincodeDefinition.getName();
    }

    /**
     * The sequence of change for this chaincode.
     * @return the sequence.
     */
    public long getSequence() {
        return chaincodeDefinition.getSequence();
    }

    /**
     * The chaincode version.
     * @return a version.
     */
    public String getVersion() {
        return chaincodeDefinition.getVersion();
    }

    /**
     * The endorsement plugin defined for this chaincode.
     * @return An endorsement plugin.
     */
    public String getEndorsementPlugin() {
        return chaincodeDefinition.getEndorsementPlugin();
    }

    /**
     * The validation plugin defined for this chaincode.
     * @return A validation plugin.
     */
    public String getValidationPlugin() {
        return chaincodeDefinition.getValidationPlugin();
    }

    /**
     * The validation parameter bytes that were set when the chaincode was defined.
     * @return A validation parameter.
     */
    public byte[] getValidationParameter() {
        final ByteString payloadBytes = chaincodeDefinition.getValidationParameter();
        return payloadBytes == null ? null : payloadBytes.toByteArray();
    }

    /**
     * Collection configurations defined for this chaincode.
     * @return Collection configurations.
     * @throws ProposalException if the proposal response content is invalid.
     */
    public ChaincodeCollectionConfiguration getChaincodeCollectionConfiguration() throws ProposalException {
        final Collection.CollectionConfigPackage collections = chaincodeDefinition.getCollections();
        try {
            return collections == null ? null : ChaincodeCollectionConfiguration.fromCollectionConfigPackage(collections);
        } catch (InvalidArgumentException e) {
            throw new ProposalException(e);
        }
    }

    /**
     * Whether initialization is required for this chaincode.
     * @return true if initialization is required; otherwise false.
     */
    public boolean getInitRequired() {
        return chaincodeDefinition.getInitRequired();
    }
}
