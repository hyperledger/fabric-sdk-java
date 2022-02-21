/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.SeekInfo;
import org.hyperledger.fabric.protos.peer.DeliverGrpc;
import org.hyperledger.fabric.protos.peer.EventsPackage;
import org.hyperledger.fabric.sdk.Channel.PeerOptions;
import org.hyperledger.fabric.sdk.exception.PeerEventingServiceException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.transaction.ProtoUtils;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

/**
 * Sample client code that makes gRPC calls to the server.
 */
class PeerEventServiceClient {
    private static final Config config = Config.getConfig();
    private static final long PEER_EVENT_REGISTRATION_WAIT_TIME = config.getPeerEventRegistrationWaitTime();
    private static final long PEER_EVENT_RECONNECTION_WARNING_RATE = config.getPeerEventReconnectionWarningRate();
    private static final Log logger = LogFactory.getLog(PeerEventServiceClient.class);
    private String channelName = null;
    private final ManagedChannelBuilder channelBuilder;
    private final String name;
    private final String url;
    private long peerEventRegistrationWaitTimeMilliSecs = PEER_EVENT_REGISTRATION_WAIT_TIME;

    private final PeerOptions peerOptions;
    private final BlockInfo.Type eventType;
    private byte[] clientTLSCertificateDigest;
    StreamObserver<Envelope> nso = null;
    StreamObserver<EventsPackage.DeliverResponse> so = null;
    private Channel.ChannelEventQue channelEventQue;
    private volatile boolean shutdown = false;
    private ManagedChannel managedChannel = null;
    private Peer peer;
    private final String toString;

    /**
     * Construct client for accessing Peer eventing service using the existing managedChannel.
     */
    PeerEventServiceClient(Peer peer, Endpoint endpoint, Properties properties, PeerOptions peerOptions) {
        this.channelBuilder = endpoint.getChannelBuilder();
        this.eventType = peerOptions.getEventType();
        this.peer = peer;
        this.peerOptions = peerOptions;
        name = peer.getName();
        url = peer.getUrl();

        if (peer.isShutdown()) {
            logger.debug("PeerEventServiceClient not starting peer has shutdown.");
            shutdown = true;
            toString = "PeerEventServiceClient{" + "id: " + config.getNextID() + ", channel: null" + ", peerName: " + name + ", url: " + url + "}";
            return;
        }
        final Channel channel = peer.getChannel();
        if (channel == null) {
            logger.debug("Peer no longer associated with a channel not connecting.");
            shutdown = true;
            toString = "PeerEventServiceClient{" + "id: " + config.getNextID() + ", channel: null" + ", peerName: " + name + ", url: " + url + "}";
            return;
        }

        channelName = channel.getName();
        toString = "PeerEventServiceClient{" + "id: " + config.getNextID() + ", channel: " + channelName + ", peerName: " + name + ", url: " + url + "}";

        clientTLSCertificateDigest = endpoint.getClientTLSCertificateDigest();

        this.channelEventQue = channel.getChannelEventQue();

        if (null == properties) {
            peerEventRegistrationWaitTimeMilliSecs = PEER_EVENT_REGISTRATION_WAIT_TIME;
        } else {
            String peerEventRegistrationWaitTime = properties.getProperty("peerEventRegistrationWaitTime", Long.toString(PEER_EVENT_REGISTRATION_WAIT_TIME));
            long tempPeerWaitTimeMilliSecs = PEER_EVENT_REGISTRATION_WAIT_TIME;

            try {
                tempPeerWaitTimeMilliSecs = Long.parseLong(peerEventRegistrationWaitTime);
            } catch (NumberFormatException e) {
                logger.warn(format("Peer event service registration %s wait time %s not parsable.", toString, peerEventRegistrationWaitTime), e);
            }

            peerEventRegistrationWaitTimeMilliSecs = tempPeerWaitTimeMilliSecs;
        }
    }

    PeerOptions getPeerOptions() {
        return peerOptions.clone();
    }

    @Override
    public String toString() {
        return toString;
    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        final String me = toString();
        logger.debug(me + " is shutting down.");
        shutdown = true;
        StreamObserver<EventsPackage.DeliverResponse> lsno = so;
        nso = null;
        so = null;
        if (null != lsno) {
            try {
                lsno.onCompleted();
            } catch (Exception e) {
                logger.error(toString() + " error message: " + e.getMessage(), e);
            }
        }

        ManagedChannel lchannel = managedChannel;
        managedChannel = null;
        if (lchannel != null) {
            if (force) {
                lchannel.shutdownNow();
            } else {
                boolean isTerminated = false;

                try {
                    isTerminated = lchannel.shutdown().awaitTermination(3, TimeUnit.SECONDS);
                } catch (Exception e) {
                    logger.debug(me + " error message: " + e.getMessage(), e); //best effort
                }
                if (!isTerminated) {
                    lchannel.shutdownNow();
                }
            }
        }

        channelEventQue = null;
        logger.debug(me + " is down.");
    }

    @Override
    public void finalize() throws Throwable {
        try {
            shutdown(true);
        } finally {
            super.finalize();
        }
    }

    /**
     * Get the last block received by this peer.
     */
    void connectEnvelope(Envelope envelope) {
        if (shutdown) {
            logger.warn(format("%s not connecting is shutdown.", toString()));
            return;
        }

        final AtomicBoolean retry = new AtomicBoolean(true); // make sure we only retry connection once for each connection attempt.

        ManagedChannel lmanagedChannel = managedChannel;

        if (lmanagedChannel == null || lmanagedChannel.isTerminated() || lmanagedChannel.isShutdown()) {
            lmanagedChannel = channelBuilder.build();
            managedChannel = lmanagedChannel;
        }

        try {
            DeliverGrpc.DeliverStub broadcast = DeliverGrpc.newStub(lmanagedChannel);

            // final DeliverResponse[] ret = new DeliverResponse[1];
            //   final List<DeliverResponse> retList = new ArrayList<>();
            final List<Throwable> throwableList = new ArrayList<>();
            final CountDownLatch finishLatch = new CountDownLatch(1);

            so = new StreamObserver<EventsPackage.DeliverResponse>() {
                @Override
                public void onNext(EventsPackage.DeliverResponse resp) {
                    // logger.info("Got Broadcast response: " + resp);
                    logger.trace(format("DeliverResponse %s resp status value:%d  status %s, typecase %s ",
                            PeerEventServiceClient.this.toString(), resp.getStatusValue(), resp.getStatus(), resp.getTypeCase()));

                    final EventsPackage.DeliverResponse.TypeCase typeCase = resp.getTypeCase();

                    if (typeCase == EventsPackage.DeliverResponse.TypeCase.STATUS) {
                        logger.debug(format("DeliverResponse  %s setting done.",
                                PeerEventServiceClient.this.toString()));

                        if (resp.getStatus() == Common.Status.SUCCESS) { // unlike you may think this only happens when all blocks are fetched.
                            peer.setLastConnectTime(System.currentTimeMillis());
                            peer.resetReconnectCount();
                        } else {
                            final long rec = peer.getReconnectCount();

                            PeerEventingServiceException peerEventingServiceException = new PeerEventingServiceException(format("%s attempts %s Status returned failure code %d (%s) during peer service event registration",
                                    PeerEventServiceClient.this.toString(), rec, resp.getStatusValue(), resp.getStatus().name()));
                            peerEventingServiceException.setResponse(resp);
                            if (rec % 10 == 0) {
                                logger.warn(PeerEventServiceClient.this.toString() + " " + peerEventingServiceException.getMessage());
                            }

                            throwableList.add(peerEventingServiceException);
                        }
                    } else if (typeCase == EventsPackage.DeliverResponse.TypeCase.FILTERED_BLOCK ||
                            typeCase == EventsPackage.DeliverResponse.TypeCase.BLOCK ||
                            typeCase == EventsPackage.DeliverResponse.TypeCase.BLOCK_AND_PRIVATE_DATA) {
                        if (typeCase == EventsPackage.DeliverResponse.TypeCase.BLOCK) {
                            logger.trace(format("%s got event block hex hashcode: %016x, block number: %d",
                                    PeerEventServiceClient.this.toString(), resp.getBlock().hashCode(), resp.getBlock().getHeader().getNumber()));
                        } else if (typeCase == EventsPackage.DeliverResponse.TypeCase.FILTERED_BLOCK) {
                            logger.trace(format("%s got event block hex hashcode: %016x, block number: %d",
                                    PeerEventServiceClient.this.toString(), resp.getFilteredBlock().hashCode(), resp.getFilteredBlock().getNumber()));
                        } else {
                            logger.trace(format("%s got event block hex hashcode: %016x, block number: %d",
                                    PeerEventServiceClient.this.toString(), resp.getBlockAndPrivateData().getBlock().hashCode(), resp.getBlockAndPrivateData().getBlock().getHeader().getNumber()));
                        }

                        peer.setLastConnectTime(System.currentTimeMillis());
                        long reconnectCount = peer.getReconnectCount();
                        if (reconnectCount > 1) {
                            logger.info(format("%s reconnected after %d attempts on channel %s, peer %s, url %s",
                                    PeerEventServiceClient.this.toString(), reconnectCount, channelName, name, url));
                        }
                        peer.resetReconnectCount();

                        BlockEvent blockEvent = new BlockEvent(peer, resp);
                        peer.setLastBlockSeen(blockEvent);

                        channelEventQue.addBEvent(blockEvent);
                    } else {
                        logger.error(format("%s got event block with unknown type: %s, %d",
                                PeerEventServiceClient.this.toString(), typeCase.name(), typeCase.getNumber()));

                        PeerEventingServiceException peerEventingServiceException = new PeerEventingServiceException(format("%s got event block with unknown type: %s, %d",
                                PeerEventServiceClient.this.toString(), typeCase.name(), typeCase.getNumber()));
                        peerEventingServiceException.setResponse(resp);

                        throwableList.add(peerEventingServiceException);
                    }
                    finishLatch.countDown();
                }

                @Override
                public void onError(Throwable t) {
                    ManagedChannel llmanagedChannel = managedChannel;
                    if (llmanagedChannel != null) {
                        try {
                            llmanagedChannel.shutdownNow();
                        } catch (Exception e) {
                            logger.warn(format("Received error on %s, attempts %d. %s shut down of grpc channel.",
                                    PeerEventServiceClient.this.toString(), peer == null ? -1 : peer.getReconnectCount(), e.getMessage()), e);
                        }
                        managedChannel = null;
                    }
                    if (!shutdown) {
                        final long reconnectCount = peer.getReconnectCount();
                        if (PEER_EVENT_RECONNECTION_WARNING_RATE > 1 && reconnectCount % PEER_EVENT_RECONNECTION_WARNING_RATE == 1) {
                            logger.warn(format("Received error on  %s, attempts %d. %s",
                                    PeerEventServiceClient.this.toString(), reconnectCount, t.getMessage()));
                        } else {
                            logger.trace(format("Received error on %s, attempts %d. %s",
                                    PeerEventServiceClient.this.toString(), reconnectCount, t.getMessage()));
                        }

                        if (retry.getAndSet(false)) {
                            peer.reconnectPeerEventServiceClient(PeerEventServiceClient.this, t);
                        }
                    }
                    finishLatch.countDown();
                }

                @Override
                public void onCompleted() {
                    logger.debug(format("DeliverResponse onCompleted %s setting done.",
                            PeerEventServiceClient.this.toString()));
                    //            done = true;
                    //There should have been a done before this...
                    finishLatch.countDown();
                }
            };

            switch (this.eventType) {
                case FILTERED_BLOCK:
                    nso = broadcast.deliverFiltered(so);
                    break;
                case BLOCK_WITH_PRIVATE_DATA:
                    nso = broadcast.deliverWithPrivateData(so);
                    break;
                default:
                    nso = broadcast.deliver(so);
            }

            nso.onNext(envelope);

            // try {
            if (!finishLatch.await(peerEventRegistrationWaitTimeMilliSecs, TimeUnit.MILLISECONDS)) {
                PeerEventingServiceException ex = new PeerEventingServiceException(format(
                        "Channel %s connect time exceeded for peer eventing service %s, timed out at %d ms.", channelName, name, peerEventRegistrationWaitTimeMilliSecs));
                ex.setTimedOut(peerEventRegistrationWaitTimeMilliSecs);
                logger.warn(toString() + " " + ex.getMessage());
                throwableList.add(0, ex);
            }
            logger.trace(toString() + " done waiting for reply!");

            if (!throwableList.isEmpty()) {
                ManagedChannel llmanagedChannel = managedChannel;
                if (llmanagedChannel != null) {
                    llmanagedChannel.shutdownNow();
                    managedChannel = null;
                }
                Throwable throwable = throwableList.get(0);
                if (retry.getAndSet(false)) {
                    peer.reconnectPeerEventServiceClient(this, throwable);
                }
            }
        } catch (InterruptedException e) {
            ManagedChannel llmanagedChannel = managedChannel;
            if (llmanagedChannel != null) {
                llmanagedChannel.shutdownNow();
                managedChannel = null;
            }
            logger.error(toString() + " error message: " + e.getMessage(), e); // not likely

            if (retry.getAndSet(false)) {
                peer.reconnectPeerEventServiceClient(this, e);
            }
        } finally {
            if (null != nso) {
                try {
                    nso.onCompleted();
                } catch (Exception e) {  //Best effort only report on debug
                    logger.debug(format("Exception completing connect with %s %s",
                            toString(), e.getMessage()), e);
                }
            }
        }
    }

    boolean isChannelActive() {
        ManagedChannel lchannel = managedChannel;
        return lchannel != null && !lchannel.isShutdown() && !lchannel.isTerminated();
    }

    void connect(TransactionContext transactionContext) throws TransactionException {
        if (shutdown) {
            return;
        }
        peerVent(transactionContext);
    }

    //=========================================================
    // Peer eventing
    private void peerVent(TransactionContext transactionContext) throws TransactionException {
        logger.trace(toString() + "peerVent  transaction: " + transactionContext);
        if (shutdown) { // check aagin
            logger.debug("peerVent not starting, shutting down.");
            return;
        }

        final Envelope envelope;
        try {
            Ab.SeekPosition.Builder start = Ab.SeekPosition.newBuilder();
            if (null != peerOptions.getNewest()) {
                start.setNewest(Ab.SeekNewest.getDefaultInstance());
            } else if (peerOptions.getStartEvents() != null) {
                start.setSpecified(Ab.SeekSpecified.newBuilder().setNumber(peerOptions.getStartEvents()));
            } else {
                start.setNewest(Ab.SeekNewest.getDefaultInstance());
            }

            envelope = ProtoUtils.createSeekInfoEnvelope(transactionContext,
                    start.build(),
                    Ab.SeekPosition.newBuilder()
                            .setSpecified(Ab.SeekSpecified.newBuilder().setNumber(peerOptions.getStopEvents()).build())
                            .build(),
                    SeekInfo.SeekBehavior.BLOCK_UNTIL_READY,

                    clientTLSCertificateDigest);
            connectEnvelope(envelope);
        } catch (Exception e) {
            throw new TransactionException(toString() + " error message: " + e.getMessage(), e);
        }
    }

    String getStatus() {
        ManagedChannel lmanagedChannel = managedChannel;
        if (lmanagedChannel == null) {
            return "No grpc managed channel active. peer eventing client service is shutdown: " + shutdown;
        } else {
            return "peer eventing client service is shutdown: " + shutdown +
                    ", grpc isShutdown: " + lmanagedChannel.isShutdown() +
                    ", grpc isTerminated: " + lmanagedChannel.isTerminated() +
                    ", grpc state: " + lmanagedChannel.getState(false);
        }
    }
}
