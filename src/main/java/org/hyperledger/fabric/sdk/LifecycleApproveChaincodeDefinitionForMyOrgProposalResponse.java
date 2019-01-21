/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.util.Collection;

import org.hyperledger.fabric.sdk.transaction.TransactionContext;

/**
 * Result of sending a {@link LifecycleApproveChaincodeDefinitionForMyOrgRequest}.
 * Also see {@link Channel#sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(LifecycleApproveChaincodeDefinitionForMyOrgRequest, Collection)}
 * <p>
 * Does not return any request specific results.
 */
public class LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse extends ProposalResponse {
    LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }
}
