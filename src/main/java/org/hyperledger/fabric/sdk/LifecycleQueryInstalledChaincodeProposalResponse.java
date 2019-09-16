/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.nio.file.Path;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

/**
 * QueryInstalledChaincode proposal returned by sending the {@link LifecycleQueryInstalledChaincodeRequest} to a peer.
 */
public class LifecycleQueryInstalledChaincodeProposalResponse extends ProposalResponse {
    LifecycleQueryInstalledChaincodeProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }

    Lifecycle.QueryInstalledChaincodeResult queryChaincodeDefinitionResult;

    private Lifecycle.QueryInstalledChaincodeResult parsePayload() throws ProposalException {
        if (null == queryChaincodeDefinitionResult) {
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
                queryChaincodeDefinitionResult = Lifecycle.QueryInstalledChaincodeResult.parseFrom(payload);
            } catch (Exception e) {
                throw new ProposalException(format("Failure on peer %s %s", getPeer(), e.getMessage()), e);
            }
        }

        return queryChaincodeDefinitionResult;
    }

    /**
     * The packageId for this chaincode.
     *
     * @return the packageId
     * @throws ProposalException
     */
    public String getPackageId() throws ProposalException {
        Lifecycle.QueryInstalledChaincodeResult queryInstalledChaincodeResult = parsePayload();

        if (queryInstalledChaincodeResult == null) {
            return null;
        }
        return queryInstalledChaincodeResult.getPackageId();
    }

    /**
     * The lable used by this chaincode. This is defined by the installed chaincode. See label parameter in {@link LifecycleChaincodePackage#fromSource(String, Path, TransactionRequest.Type, String, Path)}
     * @return the label
     * @throws ProposalException
     */
    public String getLabel() throws ProposalException {
        Lifecycle.QueryInstalledChaincodeResult queryInstalledChaincodeResult = parsePayload();

        if (queryInstalledChaincodeResult == null) {
            return null;
        }
        return queryInstalledChaincodeResult.getLabel();
    }
}
