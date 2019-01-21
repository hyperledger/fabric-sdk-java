/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

/**
 * Request to return all installed chaincode on a peer. See results in {@link LifecycleQueryInstalledChaincodesProposalResponse}
 */
public class LifecycleQueryInstalledChaincodesRequest extends LifecycleRequest {

    LifecycleQueryInstalledChaincodesRequest(User userContext) {
        super(userContext, false);
    }
}
