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

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import com.spotify.futures.ListenableFuturesExtra;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.discovery.DiscoveryGrpc;
import org.hyperledger.fabric.protos.discovery.Protocol;
import org.hyperledger.fabric.protos.peer.EndorserGrpc;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.hyperledger.fabric.sdk.helper.Config;

import static java.lang.String.format;

/**
 * Sample client code that makes gRPC calls to the server.
 */
class EndorserClient {
    private static final Config config = Config.getConfig();
    private static final Log logger = LogFactory.getLog(EndorserClient.class);
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    //    private final String channelName;
//    private final String name;
//    private final String url;
    private ManagedChannel managedChannel;
    private EndorserGrpc.EndorserFutureStub futureStub;
    private DiscoveryGrpc.DiscoveryFutureStub discoveryFutureStub;
    private boolean shutdown = false;
    private final String toString;

    /**
     * Construct client for accessing Peer server using the existing channel.
     *
     * @param channelBuilder The ChannelBuilder to build the endorser client
     */
    EndorserClient(String channelName, String name, String url, ManagedChannelBuilder<?> channelBuilder) {
        managedChannel = channelBuilder.build();
        futureStub = EndorserGrpc.newFutureStub(managedChannel);
        discoveryFutureStub = DiscoveryGrpc.newFutureStub(managedChannel);
        toString = "EndorserClient{" + "id: " + config.getNextID() + ", channel: " + channelName + ", name:" + name + ", url: " + url + "}";
        logger.trace("Created " + toString());

    }

    @Override
    public String toString() {
        return toString;
    }

    synchronized void shutdown(boolean force) {
        if (IS_TRACE_LEVEL) {
            logger.trace(format("%s shutdown called force: %b, shutdown: %b, managedChannel: %s", toString(), force, shutdown, "" + managedChannel));
        }
        if (shutdown) {
            return;
        }
        shutdown = true;
        ManagedChannel lchannel = managedChannel;
        // let all referenced resource finalize
        managedChannel = null;
        discoveryFutureStub = null;
        futureStub = null;

        if (lchannel == null) {
            return;
        }
        if (force) {

            try {
                lchannel.shutdownNow();
            } catch (Exception e) {
                logger.warn(e);
            }

        } else {
            boolean isTerminated = false;

            try {
                isTerminated = lchannel.shutdown().awaitTermination(3, TimeUnit.SECONDS);
            } catch (Exception e) {
                logger.debug(toString(), e); //best effort
            }
            if (!isTerminated) {
                try {
                    lchannel.shutdownNow();
                } catch (Exception e) {
                    logger.warn(toString(), e);
                }
            }
        }
    }

    public CompletableFuture<ProposalResponsePackage.ProposalResponse> sendProposalAsync(ProposalPackage.SignedProposal proposal) {
        if (shutdown) {
            CompletableFuture<ProposalResponsePackage.ProposalResponse> ret = new CompletableFuture<>();
            ret.completeExceptionally(new PeerException("Shutdown " + toString()));
            return ret;
        }

        CompletableFuture<ProposalResponsePackage.ProposalResponse> future = ListenableFuturesExtra.toCompletableFuture(futureStub.processProposal(proposal));

        return future.exceptionally(throwable -> {
            throw new CompletionException(format("%s %s", toString, throwable.getMessage()), throwable);
        });

        //  return CompletableFuturesExtra.toCompletableFuture(futureStub.processProposal(proposal));
        //  return futureStub.processProposal(proposal);
    }

    public CompletableFuture<Protocol.Response> sendDiscoveryRequestAsync(Protocol.SignedRequest signedRequest) {
        if (shutdown) {
            CompletableFuture<Protocol.Response> ret = new CompletableFuture<>();
            ret.completeExceptionally(new PeerException("Shutdown " + toString()));
            return ret;
        }

        CompletableFuture<Protocol.Response> future = ListenableFuturesExtra.toCompletableFuture(discoveryFutureStub.discover(signedRequest));
        return future.exceptionally(throwable -> {
            throw new CompletionException(format("%s %s", toString, throwable.getMessage()), throwable);
        });

    }

    boolean isChannelActive() {
        ManagedChannel lchannel = managedChannel;
        if (null == lchannel) {

            logger.trace(toString() + "Grpc channel needs creation.");

            return false;
        }

        final boolean isTerminated = lchannel.isTerminated();
        final boolean isShutdown = lchannel.isShutdown();
        final boolean ret = !lchannel.isShutdown() && !isTerminated; // && ConnectivityState.READY.equals(lchannel.getState(true));
        if (IS_TRACE_LEVEL) {
            logger.trace(format("%s grpc channel isActive: %b, isShutdown: %b, isTerminated: %b, state: %s ", toString(), ret, isShutdown, isTerminated, "" + lchannel.getState(false)));
        }

        return ret;
    }

    @Override
    public void finalize() throws Throwable {
        try {
            if (!shutdown) {
                logger.warn(toString() + " finalized not shutdown is Active" + isChannelActive());
            }

            shutdown(true);
        } finally {
            super.finalize();
        }
    }
}
