/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.util.Collection;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

/**
 * LifecycleInstallChaincodeRequest parameters for installing chaincode with lifecycle
 * see also {@link HFClient#sendLifecycleInstallChaincodeRequest(LifecycleInstallChaincodeRequest, Collection)}
 */
public class LifecycleInstallChaincodeRequest extends LifecycleRequest {

    private LifecycleChaincodePackage lifecycleChaincodePackage;

    LifecycleInstallChaincodeRequest(User userContext) {
        super(userContext, false);
    }

    LifecycleChaincodePackage getLifecycleChaincodePackage() {
        return lifecycleChaincodePackage;
    }

    /**
     * Set the chaincode package that needs to be installed.
     *
     * @param lifecycleChaincodePackage The chaincode to install see {@link LifecycleChaincodePackage}
     * @throws InvalidArgumentException
     */
    public void setLifecycleChaincodePackage(LifecycleChaincodePackage lifecycleChaincodePackage) throws InvalidArgumentException {

        if (null == lifecycleChaincodePackage) {
            throw new InvalidArgumentException("The parameter lifecycleChaincodePackage can not be null.");

        }
        this.lifecycleChaincodePackage = lifecycleChaincodePackage;
    }
}
