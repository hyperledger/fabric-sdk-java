/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.util.concurrent.TimeUnit;

import com.google.common.util.concurrent.ListenableFuture;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.EndorserGrpc;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.exception.PeerException;

/**
 * Sample client code that makes gRPC calls to the server.
 */
class EndorserClient {
    private static final Log logger = LogFactory.getLog(EndorserClient.class);

    private ManagedChannel managedChannel;
    private EndorserGrpc.EndorserBlockingStub blockingStub;
    private EndorserGrpc.EndorserFutureStub futureStub;
    private boolean shutdown = false;

    /**
     * Construct client for accessing Peer server using the existing channel.
     *
     * @param channelBuilder The ChannelBuilder to build the endorser client
     */
    EndorserClient(ManagedChannelBuilder<?> channelBuilder) {
        managedChannel = channelBuilder.build();
        blockingStub = EndorserGrpc.newBlockingStub(managedChannel);
        futureStub = EndorserGrpc.newFutureStub(managedChannel);
    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        shutdown = true;
        ManagedChannel lchannel = managedChannel;
        // let all referenced resource finalize
        managedChannel = null;
        blockingStub = null;
        futureStub = null;

        if (lchannel == null) {
            return;
        }
        if (force) {
            lchannel.shutdownNow();
        } else {
            boolean isTerminated = false;

            try {
                isTerminated = lchannel.shutdown().awaitTermination(3, TimeUnit.SECONDS);
            } catch (Exception e) {
                logger.debug(e); //best effort
            }
            if (!isTerminated) {
                lchannel.shutdownNow();
            }
        }
    }

    public ListenableFuture<FabricProposalResponse.ProposalResponse> sendProposalAsync(FabricProposal.SignedProposal proposal) throws PeerException {
        if (shutdown) {
            throw new PeerException("Shutdown");
        }
        return futureStub.processProposal(proposal);
    }

    public FabricProposalResponse.ProposalResponse sendProposal(FabricProposal.SignedProposal proposal) throws PeerException {

        if (shutdown) {
            throw new PeerException("Shutdown");
        }

        try {
            return blockingStub.processProposal(proposal);

        } catch (StatusRuntimeException e) {
            logger.warn(String.format("RPC failed: %s", e.getStatus()));
            throw new PeerException("Sending transaction to peer failed", e);
        }
    }

    boolean isChannelActive() {
        ManagedChannel lchannel = managedChannel;
        return lchannel != null && !lchannel.isShutdown() && !lchannel.isTerminated();
    }

    @Override
    public void finalize() {
        shutdown(true);
    }
}
