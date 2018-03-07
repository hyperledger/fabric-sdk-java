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
import org.hyperledger.fabric.protos.peer.PeerEvents.DeliverResponse;
import org.hyperledger.fabric.sdk.Channel.PeerOptions;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;
import static org.hyperledger.fabric.protos.peer.PeerEvents.DeliverResponse.TypeCase.BLOCK;
import static org.hyperledger.fabric.protos.peer.PeerEvents.DeliverResponse.TypeCase.FILTERED_BLOCK;
import static org.hyperledger.fabric.protos.peer.PeerEvents.DeliverResponse.TypeCase.STATUS;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createSeekInfoEnvelope;

/**
 * Sample client code that makes gRPC calls to the server.
 */
class PeerEventServiceClient {
    private static final Config config = Config.getConfig();
    private static final long PEER_EVENT_REGISTRATION_WAIT_TIME = config.getPeerEventRegistrationWaitTime();
    private static final Log logger = LogFactory.getLog(PeerEventServiceClient.class);
    private final String channelName;
    private final ManagedChannelBuilder channelBuilder;
    private final String name;
    private final String url;
    private final long peerEventRegistrationWaitTimeMilliSecs;

    private final PeerOptions peerOptions;
    private final boolean filterBlock;
    private byte[] clientTLSCertificateDigest;
    Properties properties = new Properties();
    StreamObserver<Envelope> nso = null;
    StreamObserver<DeliverResponse> so = null;
    private Channel.ChannelEventQue channelEventQue;
    private boolean shutdown = false;
    private transient ManagedChannel managedChannel = null;
    private transient TransactionContext transactionContext;
    private transient Peer peer;

    /**
     * Construct client for accessing Peer eventing service using the existing managedChannel.
     */
    PeerEventServiceClient(Peer peer, Endpoint endpoint, Properties properties, PeerOptions peerOptions) {

        this.channelBuilder = endpoint.getChannelBuilder();
        this.filterBlock = peerOptions.isRegisterEventsForFilteredBlocks();
        this.peer = peer;
        name = peer.getName();
        url = peer.getUrl();
        channelName = peer.getChannel().getName();
        this.peerOptions = peerOptions;
        clientTLSCertificateDigest = endpoint.getClientTLSCertificateDigest();

        this.channelEventQue = peer.getChannel().getChannelEventQue();

        if (null == properties) {

            peerEventRegistrationWaitTimeMilliSecs = PEER_EVENT_REGISTRATION_WAIT_TIME;

        } else {
            this.properties = properties;

            String peerEventRegistrationWaitTime = properties.getProperty("peerEventRegistrationWaitTime", Long.toString(PEER_EVENT_REGISTRATION_WAIT_TIME));

            long tempPeerWaitTimeMilliSecs = PEER_EVENT_REGISTRATION_WAIT_TIME;

            try {
                tempPeerWaitTimeMilliSecs = Long.parseLong(peerEventRegistrationWaitTime);
            } catch (NumberFormatException e) {
                logger.warn(format("Peer event service registration %s wait time %s not parsable.", name, peerEventRegistrationWaitTime), e);
            }

            peerEventRegistrationWaitTimeMilliSecs = tempPeerWaitTimeMilliSecs;
        }

    }

    PeerOptions getPeerOptions() {
        return peerOptions.clone();
    }

    synchronized void shutdown(boolean force) {

        if (shutdown) {
            return;
        }
        shutdown = true;
        StreamObserver<DeliverResponse> lsno = so;
        nso = null;
        so = null;
        if (null != lsno) {
            try {
                lsno.onCompleted();
            } catch (Exception e) {
                logger.error(e);
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
                    logger.debug(e); //best effort
                }
                if (!isTerminated) {
                    lchannel.shutdownNow();
                }
            }
        }
        peer = null;
        channelEventQue = null;

    }

    @Override
    public void finalize() {
        shutdown(true);
    }

    /**
     * Get the last block received by this peer.
     *
     * @return The last block received by this peer. May return null if no block has been received since first reactivated.
     */

    void connectEnvelope(Envelope envelope) throws TransactionException {

        if (shutdown) {
            throw new TransactionException("Peer eventing client is shutdown");
        }

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

            so = new StreamObserver<DeliverResponse>() {

                @Override
                public void onNext(DeliverResponse resp) {

                    // logger.info("Got Broadcast response: " + resp);
                    logger.trace(format("DeliverResponse channel %s peer %s resp status value:%d  status %s, typecase %s ",
                            channelName, peer.getName(), resp.getStatusValue(), resp.getStatus(), resp.getTypeCase()));

                    final DeliverResponse.TypeCase typeCase = resp.getTypeCase();

                    if (typeCase == STATUS) {

                        logger.debug(format("DeliverResponse channel %s peer %s setting done.",
                                channelName, peer.getName()));

                        if (resp.getStatus() == Common.Status.SUCCESS) { // unlike you may think this only happens when all blocks are fetched.
                            peer.setLastConnectTime(System.currentTimeMillis());
                            peer.resetReconnectCount();
                        } else {

                            throwableList.add(new TransactionException(format("Channel %s peer %s Status returned failure code %d (%s) during peer service event registration",
                                    channelName, peer.getName(), resp.getStatusValue(), resp.getStatus().name())));
                        }

                    } else if (typeCase == FILTERED_BLOCK || typeCase == BLOCK) {
                        if (typeCase == BLOCK) {
                            logger.trace(format("Channel %s peer %s got event block hex hashcode: %016x, block number: %d",
                                    channelName, peer.getName(), resp.getBlock().hashCode(), resp.getBlock().getHeader().getNumber()));
                        } else {
                            logger.trace(format("Channel %s peer %s got event block hex hashcode: %016x, block number: %d",
                                    channelName, peer.getName(), resp.getFilteredBlock().hashCode(), resp.getFilteredBlock().getNumber()));
                        }

                        peer.setLastConnectTime(System.currentTimeMillis());
                        long reconnectCount = peer.getReconnectCount();
                        if (reconnectCount > 1) {

                            logger.info(format("Peer eventing service reconnected after %d attempts on channel %s, peer %s, url %s",
                                    reconnectCount, channelName, name, url));

                        }
                        peer.resetReconnectCount();

                        BlockEvent blockEvent = new BlockEvent(peer, resp);
                        peer.setLastBlockSeen(blockEvent);

                        channelEventQue.addBEvent(blockEvent);
                    } else {
                        logger.error(format("Channel %s peer %s got event block with unknown type: %s, %d",
                                channelName, peer.getName(), typeCase.name(), typeCase.getNumber()));

                        throwableList.add(new TransactionException(format("Channel %s peer %s Status got unknown type %s, %d",
                                channelName, peer.getName(), typeCase.name(), typeCase.getNumber())));

                    }
                    finishLatch.countDown();

                }

                @Override
                public void onError(Throwable t) {
                    ManagedChannel llmanagedChannel = managedChannel;
                    if (llmanagedChannel != null) {
                        llmanagedChannel.shutdownNow();
                        managedChannel = null;
                    }
                    if (!shutdown) {
                        final long reconnectCount = peer.getReconnectCount();
                        if (reconnectCount % 50 == 1) {
                            logger.warn(format("Received error on peer eventing service on channel %s, peer %s, url %s, attempts %d. %s",
                                    channelName, name, url, reconnectCount, t.getMessage()));

                        } else {
                            logger.trace(format("Received error on peer eventing service on channel %s, peer %s, url %s, attempts %d. %s",
                                    channelName, name, url, reconnectCount, t.getMessage()));

                        }

                        peer.reconnectPeerEventServiceClient(PeerEventServiceClient.this, t);

                    }
                    finishLatch.countDown();
                }

                @Override
                public void onCompleted() {
                    logger.debug(format("DeliverResponse onCompleted channel %s peer %s setting done.",
                            channelName, peer.getName()));
                    //            done = true;
                    //There should have been a done before this...
                    finishLatch.countDown();
                }
            };

            nso = filterBlock ? broadcast.deliverFiltered(so) : broadcast.deliver(so);

            nso.onNext(envelope);

            // try {
            if (!finishLatch.await(peerEventRegistrationWaitTimeMilliSecs, TimeUnit.MILLISECONDS)) {
                TransactionException ex = new TransactionException(format(
                        "Channel %s connect time exceeded for peer eventing service %s, timed out at %d ms.", channelName, name, peerEventRegistrationWaitTimeMilliSecs));
                throwableList.add(0, ex);

            }
            logger.trace("Done waiting for reply!");

            if (!throwableList.isEmpty()) {
                ManagedChannel llmanagedChannel = managedChannel;
                if (llmanagedChannel != null) {
                    llmanagedChannel.shutdownNow();
                    managedChannel = null;
                }
                Throwable throwable = throwableList.get(0);
                peer.reconnectPeerEventServiceClient(this, throwable);

            }

        } catch (InterruptedException e) {
            ManagedChannel llmanagedChannel = managedChannel;
            if (llmanagedChannel != null) {
                llmanagedChannel.shutdownNow();
                managedChannel = null;
            }
            logger.error(e); // not likely

            peer.reconnectPeerEventServiceClient(this, e);

        } finally {
            if (null != nso) {

                try {
                    nso.onCompleted();
                } catch (Exception e) {  //Best effort only report on debug
                    logger.debug(format("Exception completing connect with channel %s,  name %s, url %s %s",
                            channelName, name, url, e.getMessage()), e);
                }

            }
        }
    }

    boolean isChannelActive() {
        ManagedChannel lchannel = managedChannel;
        return lchannel != null && !lchannel.isShutdown() && !lchannel.isTerminated();
    }

    void connect(TransactionContext transactionContext) throws TransactionException {

        this.transactionContext = transactionContext;
        peerVent(transactionContext);

    }

    //=========================================================
    // Peer eventing
    void peerVent(TransactionContext transactionContext) throws TransactionException {

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

            //   properties.

            envelope = createSeekInfoEnvelope(transactionContext,
                    start.build(),
                    Ab.SeekPosition.newBuilder()
                            .setSpecified(Ab.SeekSpecified.newBuilder().setNumber(peerOptions.getStopEvents()).build())
                            .build(),
                    SeekInfo.SeekBehavior.BLOCK_UNTIL_READY,

                    clientTLSCertificateDigest);
            connectEnvelope(envelope);
        } catch (CryptoException e) {
            throw new TransactionException(e);
        }

    }

}
