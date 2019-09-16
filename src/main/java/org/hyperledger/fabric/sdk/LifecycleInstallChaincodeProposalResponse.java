/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

/**
 * The response to {@link LifecycleInstallChaincodeRequest}
 */
public class LifecycleInstallChaincodeProposalResponse extends ProposalResponse {
    LifecycleInstallChaincodeProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }

    /**
     * The packageId the identifies this chaincode change.
     *
     * @return the package id.
     * @throws ProposalException
     */

    public String getPackageId() throws ProposalException {
        if (Status.SUCCESS != getStatus()) {
            throw new ProposalException(format("Status of install proposal did not ret ok for %s, %s ", getPeer(), getStatus()));
        }
        ByteString payload = getProposalResponse().getResponse().getPayload();
        Lifecycle.InstallChaincodeResult installChaincodeResult = null;
        try {
            installChaincodeResult = Lifecycle.InstallChaincodeResult.parseFrom(payload);
        } catch (InvalidProtocolBufferException e) {
            throw new ProposalException(format("Bad protobuf received for install proposal %s", getPeer()));
        }
        return installChaincodeResult.getPackageId();
    }
}
