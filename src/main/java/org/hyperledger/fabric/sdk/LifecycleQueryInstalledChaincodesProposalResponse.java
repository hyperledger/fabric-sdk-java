/*
 *
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 */

package org.hyperledger.fabric.sdk;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

/**
 * Result of querying all chaincodes on a peer. See {@link LifecycleQueryInstalledChaincodesRequest} and {@link HFClient#sendLifecycleQueryInstalledChaincodes(LifecycleQueryInstalledChaincodesRequest, Collection)}
 */
public class LifecycleQueryInstalledChaincodesProposalResponse extends ProposalResponse {
    LifecycleQueryInstalledChaincodesProposalResponse(TransactionContext transactionContext, int status, String message) {
        super(transactionContext, status, message);
    }

    Lifecycle.QueryInstalledChaincodesResult queryChaincodeDefinitionResult;

    private Lifecycle.QueryInstalledChaincodesResult parsePayload() throws ProposalException {
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
                queryChaincodeDefinitionResult = Lifecycle.QueryInstalledChaincodesResult.parseFrom(payload);
            } catch (Exception e) {
                throw new ProposalException(format("Failure on peer %s %s", getPeer(), e.getMessage()), e);
            }
        }

        return queryChaincodeDefinitionResult;
    }

    public Collection<LifecycleQueryInstalledChaincodesResult> getLifecycleQueryInstalledChaincodesResult() throws ProposalException {
        Lifecycle.QueryInstalledChaincodesResult queryInstalledChaincodesResult = parsePayload();

        Collection<LifecycleQueryInstalledChaincodesResult> ret = new ArrayList<>(queryInstalledChaincodesResult.getInstalledChaincodesCount());
        for (Lifecycle.QueryInstalledChaincodesResult.InstalledChaincode qr : queryInstalledChaincodesResult.getInstalledChaincodesList()) {

            ret.add(new LifecycleQueryInstalledChaincodesResult(qr));
        }
        return ret;
    }

    public class LifecycleQueryInstalledChaincodesResult {
        LifecycleQueryInstalledChaincodesResult(Lifecycle.QueryInstalledChaincodesResult.InstalledChaincode installedChaincode) {
            this.installedChaincode = installedChaincode;
        }

        /**
         * The label used by this chaincode. This is defined by the installed chaincode. See label parameter in {@link LifecycleChaincodePackage#fromSource(String, Path, TransactionRequest.Type, String, Path)}
         *
         * @return Label
         */
        public String getLabel() {
            return installedChaincode.getLabel();
        }

        /**
         * The packageId that identifies this chaincode.
         *
         * @return the packageId
         */
        public String getPackageId() {
            return installedChaincode.getPackageId();
        }

        private final Lifecycle.QueryInstalledChaincodesResult.InstalledChaincode installedChaincode;
    }
}
