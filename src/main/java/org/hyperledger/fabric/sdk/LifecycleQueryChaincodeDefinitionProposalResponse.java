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
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

/**
 * LifecycleQueryChaincodeDefinitionProposalResponse is response to a LifecycleQueryChaincodeDefinition
 * Returns the chaoncode's sequence, version, endorsement plugin, validation plugin, validation parameter, collections and init is required.
 */
public class LifecycleQueryChaincodeDefinitionProposalResponse extends ProposalResponse {
    private Lifecycle.QueryChaincodeDefinitionResult queryChaincodeDefinitionResult = null;

    LifecycleQueryChaincodeDefinitionProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }

    private Lifecycle.QueryChaincodeDefinitionResult parsePayload() throws ProposalException {
        if (null == queryChaincodeDefinitionResult) {
            if (getStatus() != Status.SUCCESS) {
                throw new ProposalException(format("Fabric response failed on peer %s  %s", getPeer(), getMessage()));
            }

            ProposalResponsePackage.ProposalResponse fabricResponse = getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException("Proposal has no Fabric response.");
            }

            ByteString payload = fabricResponse.getPayload();
            if (payload == null) {
                throw new ProposalException("Fabric response has no payload");
            }

            try {
                byte[] chaincodeActionResponsePayload = getChaincodeActionResponsePayload();
                if (null == chaincodeActionResponsePayload) {
                    throw new ProposalException("Fabric chaincode action response payload is null.");
                }
                queryChaincodeDefinitionResult = Lifecycle.QueryChaincodeDefinitionResult.parseFrom(getChaincodeActionResponsePayload());
            } catch (Exception e) {
                throw new ProposalException(format("Failure on peer %s %s", getPeer(), e.getMessage()), e);
            }
        }

        return queryChaincodeDefinitionResult;
    }

    /**
     * The validation parameter bytes that were set when the chaincode was defined.
     *
     * @return validation parameter.
     * @throws ProposalException
     */
    public byte[] getValidationParameter() throws ProposalException {
        ByteString payloadBytes = parsePayload().getValidationParameter();
        if (null == payloadBytes) {
            return null;
        }
        return payloadBytes.toByteArray();
    }

    /**
     * The chaincodes version
     *
     * @return the verison.
     * @throws ProposalException
     */
    public String getVersion() throws ProposalException {
        return parsePayload().getVersion();
    }

    /**
     * Is init required for the chaincode. The chaincode must have an Init method that is called first.
     *
     * @return init required.
     * @throws ProposalException
     */
    public boolean getInitRequired() throws ProposalException {
        return parsePayload().getInitRequired();
    }

    /**
     * The sequence of change for this chaincode.
     *
     * @return the sequence.
     * @throws ProposalException
     */
    public long getSequence() throws ProposalException {
        return parsePayload().getSequence();
    }

    /**
     * The collection configuration this chaincode was defined.
     *
     * @return chaincode collection
     * @throws ProposalException
     */
    public ChaincodeCollectionConfiguration getChaincodeCollectionConfiguration() throws ProposalException {
        Collection.CollectionConfigPackage collections = parsePayload().getCollections();

        if (null == collections || !parsePayload().hasCollections()) {
            return null;
        }
        try {
            return ChaincodeCollectionConfiguration.fromCollectionConfigPackage(collections);
        } catch (InvalidArgumentException e) {
            throw new ProposalException(e);
        }
    }

    /**
     * The endorsement plugin for this chaincode.
     *
     * @return the endorsement plugin.
     * @throws ProposalException
     */
    public String getEndorsementPlugin() throws ProposalException {
        return parsePayload().getEndorsementPlugin();
    }

    /**
     * The valadiation plugin defined for this chaincode.
     *
     * @return validation plugin.
     * @throws ProposalException
     */
    public String getValidationPlugin() throws ProposalException {
        return parsePayload().getValidationPlugin();
    }
}
