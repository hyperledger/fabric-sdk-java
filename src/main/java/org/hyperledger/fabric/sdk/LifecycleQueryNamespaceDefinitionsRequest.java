/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.util.Collection;

/**
 * LifecycleQueryNamespaceDefinitionsRequest Request for namespaces of committed types.
 * See also {@link Channel#lifecycleQueryNamespaceDefinitions(LifecycleQueryNamespaceDefinitionsRequest, Collection)}
 */
public class LifecycleQueryNamespaceDefinitionsRequest extends LifecycleRequest {

    private LifecycleChaincodePackage lifecycleChaincodePackage;

    LifecycleQueryNamespaceDefinitionsRequest(User userContext) {
        super(userContext, false);
    }
}
