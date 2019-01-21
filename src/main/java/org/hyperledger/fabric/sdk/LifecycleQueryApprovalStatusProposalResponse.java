/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

/**
 * Returns the response for a LifecycleQueryApprovalStatus showing what organizations have or have not approved yet.
 */
public class LifecycleQueryApprovalStatusProposalResponse extends ProposalResponse {
    LifecycleQueryApprovalStatusProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }

    Lifecycle.QueryApprovalStatusResults queryApprovalStatusResults;

    private Lifecycle.QueryApprovalStatusResults parsePayload() throws ProposalException {

        if (null == queryApprovalStatusResults) {

            if (getStatus() != Status.SUCCESS) {
                throw new ProposalException(format("Fabric response failed on peer %s  %s", getPeer(), getMessage()));
            }

            FabricProposalResponse.ProposalResponse fabricResponse = getProposalResponse();

            if (null == fabricResponse) {
                throw new ProposalException(format("Proposal has no Fabric response. %s", getPeer()));
            }

            ByteString payload = fabricResponse.getResponse().getPayload();

            if (payload == null) {
                throw new ProposalException(format("Fabric response has no payload  %s", getPeer()));
            }

            try {
                queryApprovalStatusResults = Lifecycle.QueryApprovalStatusResults.parseFrom(payload);
            } catch (Exception e) {
                throw new ProposalException(format("Failure on peer %s %s", getPeer(), e.getMessage()), e);
            }
        }

        return queryApprovalStatusResults;
    }

    public Lifecycle.QueryApprovalStatusResults getApprovalStatusResults() throws ProposalException {

        return parsePayload();

    }

    private Set<String> approved = null;
    private Set<String> unApproved = null;

    /**
     * The set of organizations that hav approved this chaincode definition.
     *
     * @return
     * @throws ProposalException
     */
    public Set<String> getApprovedOrgs() throws ProposalException {
        sort();
        return new HashSet<>(approved);
    }

    /**
     * The set of organizations that have not approved this chaincode definition.
     *
     * @return
     * @throws ProposalException
     */
    public Set<String> getUnApprovedOrgs() throws ProposalException {
        sort();
        return new HashSet<>(unApproved);
    }

    /**
     * A map of approved and not approved. The key contains name of org the value a Boolean if approved.
     *
     * @return
     * @throws ProposalException
     */
    public Map<String, Boolean> getApprovalMap() throws ProposalException {

        Lifecycle.QueryApprovalStatusResults rs = getApprovalStatusResults();
        if (rs == null) {
            return Collections.emptyMap();
        }
        return rs.getApprovedMap();
    }

    private void sort() throws ProposalException {

        Lifecycle.QueryApprovalStatusResults rs = getApprovalStatusResults();
        if (null != rs) {
            if (null != approved) {
                return;
            }
            approved = new HashSet<>();
            unApproved = new HashSet<>();

            rs.getApprovedMap().forEach((key, value) -> {
                if (value) {
                    approved.add(key);

                } else {

                    unApproved.add(key);

                }

            });

        }

    }

}
