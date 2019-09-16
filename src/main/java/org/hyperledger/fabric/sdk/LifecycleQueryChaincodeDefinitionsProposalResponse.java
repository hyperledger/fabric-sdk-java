/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

public final class LifecycleQueryChaincodeDefinitionsProposalResponse extends ProposalResponse {
    LifecycleQueryChaincodeDefinitionsProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }

    private Lifecycle.QueryChaincodeDefinitionsResult queryChaincodeDefinitionsResult;

    private Lifecycle.QueryChaincodeDefinitionsResult getPayload() throws ProposalException {
        if (null == queryChaincodeDefinitionsResult) {
            if (getStatus() != Status.SUCCESS) {
                throw new ProposalException(format("Fabric response failed on peer %s  %s", getPeer(), getMessage()));
            }

            ProposalResponsePackage.ProposalResponse fabricResponse = getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Proposal has no Fabric response. %s", getPeer()));
            }

            ByteString responsePayload = fabricResponse.getResponse().getPayload();
            if (responsePayload == null) {
                throw new ProposalException(format("Fabric response has no payload  %s", getPeer()));
            }

            try {
                queryChaincodeDefinitionsResult = Lifecycle.QueryChaincodeDefinitionsResult.parseFrom(responsePayload);
            } catch (Exception e) {
                throw new ProposalException(format("Failure on peer %s %s", getPeer(), e.getMessage()), e);
            }
        }

        return queryChaincodeDefinitionsResult;
    }

    /**
     * The definitions of chaincode that have been committed.
     * @return Chaincode definitions.
     * @throws ProposalException if the proposal response is invalid.
     */
    public Collection<LifecycleQueryChaincodeDefinitionsResult> getLifecycleQueryChaincodeDefinitionsResult() throws ProposalException {
        final Lifecycle.QueryChaincodeDefinitionsResult payload = getPayload();
        if (payload == null) {
            return Collections.emptyList();
        }

        final List<Lifecycle.QueryChaincodeDefinitionsResult.ChaincodeDefinition> chaincodeDefinitions = payload.getChaincodeDefinitionsList();
        if (chaincodeDefinitions == null) {
            return Collections.emptyList();
        }

        return chaincodeDefinitions.stream()
                .map(LifecycleQueryChaincodeDefinitionsResult::new)
                .collect(Collectors.toList());
    }
}
