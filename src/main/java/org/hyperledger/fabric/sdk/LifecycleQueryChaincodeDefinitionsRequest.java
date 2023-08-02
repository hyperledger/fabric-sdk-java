/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

/**
 * Request for definitions of commited chaincode.
 * See also {@link Channel#lifecycleQueryChaincodeDefinitions(LifecycleQueryChaincodeDefinitionsRequest, java.util.Collection)}
 */
public final class LifecycleQueryChaincodeDefinitionsRequest extends LifecycleRequest {
    LifecycleQueryChaincodeDefinitionsRequest(User userContext) {
        super(userContext, false);
    }
}
