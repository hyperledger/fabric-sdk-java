/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

/**
 * Returns the response for a LifecycleCheckCommitReadinessStatus showing what organizations have or have not approved yet.
 */
public final class LifecycleCheckCommitReadinessProposalResponse extends ProposalResponse {
    private Lifecycle.CheckCommitReadinessResult checkCommitReadinessResult;

    LifecycleCheckCommitReadinessProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }

    public Lifecycle.CheckCommitReadinessResult getApprovalStatusResults() throws ProposalException {
        if (null == checkCommitReadinessResult) {
            if (getStatus() != Status.SUCCESS) {
                throw new ProposalException(format("Fabric response failed on peer %s  %s", getPeer(), getMessage()));
            }

            ProposalResponsePackage.ProposalResponse fabricResponse = getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Proposal has no Fabric response. %s", getPeer()));
            }

            ByteString payload = fabricResponse.getResponse().getPayload();
            if (payload == null) {
                throw new ProposalException(format("Fabric response has no payload  %s", getPeer()));
            }

            try {
                checkCommitReadinessResult = Lifecycle.CheckCommitReadinessResult.parseFrom(payload);
            } catch (Exception e) {
                throw new ProposalException(format("Failure on peer %s %s", getPeer(), e.getMessage()), e);
            }
        }

        return checkCommitReadinessResult;
    }

    /**
     * The set of organizations that hav approved this chaincode definition.
     *
     * @return
     * @throws ProposalException
     */
    public Set<String> getApprovedOrgs() throws ProposalException {
        return getApprovalsMap().entrySet().stream()
                .filter(Map.Entry::getValue)
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    /**
     * The set of organizations that have not approved this chaincode definition.
     *
     * @return
     * @throws ProposalException
     */
    public Set<String> getUnApprovedOrgs() throws ProposalException {
        return getApprovalsMap().entrySet().stream()
                .filter(entry -> !entry.getValue())
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    /**
     * A map of approved and not approved. The key contains name of org the value a Boolean if approved.
     *
     * @return
     * @throws ProposalException
     */
    public Map<String, Boolean> getApprovalsMap() throws ProposalException {
        final Lifecycle.CheckCommitReadinessResult approvalStatusResults = getApprovalStatusResults();
        return approvalStatusResults == null ? Collections.emptyMap() : approvalStatusResults.getApprovalsMap();
    }
}
