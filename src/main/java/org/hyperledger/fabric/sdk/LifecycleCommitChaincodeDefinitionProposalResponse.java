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
 * Response to a {@link LifecycleCommitChaincodeDefinitionRequest}
 * Also see {@link Channel#sendLifecycleCommitChaincodeDefinitionProposal(LifecycleCommitChaincodeDefinitionRequest, Collection)}}
 * <p>
 * Response does not return any request specific parameters.
 */
public class LifecycleCommitChaincodeDefinitionProposalResponse extends ProposalResponse {
    LifecycleCommitChaincodeDefinitionProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }
}
