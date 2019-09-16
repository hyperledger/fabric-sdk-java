/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Utils;

/**
 * Request to get a {@link LifecycleQueryInstalledChaincodeProposalResponse} for a specific packageId
 */
public class LifecycleQueryInstalledChaincodeRequest extends LifecycleRequest {
    private String packageId;

    LifecycleQueryInstalledChaincodeRequest(User userContext) {
        super(userContext, false);
    }

    String getPackageId() {
        return packageId;
    }

    /**
     * The packageId of the chaincode to query. Sent to peer to get a {@link LifecycleQueryInstalledChaincodeProposalResponse}
     *
     * @param packageId
     * @throws InvalidArgumentException
     */
    public void setPackageID(String packageId) throws InvalidArgumentException {

        if (Utils.isNullOrEmpty(packageId)) {
            throw new InvalidArgumentException("The packageId parameter can not be null or empty.");
        }
        this.packageId = packageId;
    }
}
