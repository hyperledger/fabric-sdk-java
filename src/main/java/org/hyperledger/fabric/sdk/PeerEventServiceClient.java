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
    private static final long ORDERER_WAIT_TIME = config.getOrdererWaitTime();
    private static final Log logger = LogFactory.getLog(PeerEventServiceClient.class);
    private final String channelName;
    private final ManagedChannelBuilder channelBuilder;
    private final String name;
    private final String url;
    private final long ordererWaitTimeMilliSecs;
    private final PeerOptions peerOptions;
    private final boolean filterBlock;
    Properties properties = new Properties();
    StreamObserver<Envelope> nso = null;
    StreamObserver<DeliverResponse> so = null;
    private Channel.ChannelEventQue channelEventQue;
    private boolean shutdown = false;
    private ManagedChannel managedChannel = null;
    private transient TransactionContext transactionContext;
    private transient Peer peer;

    /**
     * Construct client for accessing Orderer server using the existing managedChannel.
     */
    PeerEventServiceClient(Peer peer, ManagedChannelBuilder<?> channelBuilder, Properties properties, PeerOptions peerOptions) {

        this.channelBuilder = channelBuilder;
        this.filterBlock = peerOptions.isRegisterEventsForFilteredBlocks();
        this.peer = peer;
        name = peer.getName();
        url = peer.getUrl();
        channelName = peer.getChannel().getName();
        this.peerOptions = peerOptions;

        this.channelEventQue = peer.getChannel().getChannelEventQue();

        if (null == properties) {

            ordererWaitTimeMilliSecs = ORDERER_WAIT_TIME;

        } else {
            this.properties = properties;

            String ordererWaitTimeMilliSecsString = properties.getProperty("ordererWaitTimeMilliSecs", Long.toString(ORDERER_WAIT_TIME));

            long tempOrdererWaitTimeMilliSecs = ORDERER_WAIT_TIME;

            try {
                tempOrdererWaitTimeMilliSecs = Long.parseLong(ordererWaitTimeMilliSecsString);
            } catch (NumberFormatException e) {
                logger.warn(format("Orderer %s wait time %s not parsable.", name, ordererWaitTimeMilliSecsString), e);
            }

            ordererWaitTimeMilliSecs = tempOrdererWaitTimeMilliSecs;
        }

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

    DeliverResponse[] connectEnvelope(Envelope envelope) throws TransactionException {

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
            final List<DeliverResponse> retList = new ArrayList<>();
            final List<Throwable> throwableList = new ArrayList<>();
            final CountDownLatch finishLatch = new CountDownLatch(1);

            so = new StreamObserver<DeliverResponse>() {
                boolean done = false;
                AtomicBoolean inRecovery = new AtomicBoolean(false);

                @Override
                public void onNext(DeliverResponse resp) {

                    // logger.info("Got Broadcast response: " + resp);
                    logger.trace(format("DeliverResponse channel %s peer %s resp status value:%d  status %s, typecase %s ",
                            channelName, peer.getName(), resp.getStatusValue(), resp.getStatus(), resp.getTypeCase()));

                    if (done) {

                        // logger.info("Got Broadcast response: " + resp);
                        logger.trace(format("DeliverResponse channel %s peer %s ignored because done. resp status value:%d  status %s, typecase %s ",
                                channelName, peer.getName(), resp.getStatusValue(), resp.getStatus(), resp.getTypeCase()));

                        return;
                    }

                    final DeliverResponse.TypeCase typeCase = resp.getTypeCase();

                    if (typeCase == STATUS) {
                        done = true;
                        logger.debug(format("DeliverResponse channel %s peer %s setting done.",
                                channelName, peer.getName()));
                        retList.add(0, resp);

                        finishLatch.countDown();

                    } else if (typeCase == FILTERED_BLOCK || typeCase == BLOCK) {
                        logger.trace(format("Channel %s peer %s got event block hex hashcode: %016x, block number: %d",
                                channelName, peer.getName(), resp.getBlock().hashCode(), resp.getBlock().getHeader().getNumber()));
                        retList.add(resp);
                        finishLatch.countDown();
                        channelEventQue.addBEvent(new BlockEvent(peer, resp));
                    } else {
                        logger.error(format("Channel %s peer %s got event block with unknown type: %s, %d",
                                channelName, peer.getName(), typeCase.name(), typeCase.getNumber())
                        );
                    }

                }

                @Override
                public void onError(Throwable t) {
                    final boolean recoverymode = inRecovery.getAndSet(true);
                    if (recoverymode) {
                        return; // make sure we do this once.
                    }
                    if (!shutdown) {
                        logger.error(format("Received error on channel %s, peer %s, url %s, %s",
                                channelName, name, url, t.getMessage()), t);

                        done = true;
                        throwableList.add(t);
                        finishLatch.countDown();
                        Peer lpeer = peer;

                        if (lpeer != null) {

                            lpeer.reconnectPeerEventServiceClient(PeerEventServiceClient.this, t);

                        }
                    }
                }

                @Override
                public void onCompleted() {
                    logger.debug(format("DeliverResponse onCompleted channel %s peer %s setting done.",
                            channelName, peer.getName()));
                    done = true;
                    //There should have been a done before this...
                    finishLatch.countDown();
                }
            };

            nso = filterBlock ? broadcast.deliverFiltered(so) : broadcast.deliver(so);

            nso.onNext(envelope);
            //nso.onCompleted();

            try {
                //   if (!finishLatch.await(ordererWaitTimeMilliSecs, TimeUnit.MILLISECONDS)) {
                if (!finishLatch.await(9999999, TimeUnit.MILLISECONDS)) {
                    TransactionException ex = new TransactionException(format(
                            "Channel %s connect time exceeded for peer eventing service %s, timed out at %d ms.", channelName, name, ordererWaitTimeMilliSecs));
                    logger.error(ex.getMessage(), ex);
                    throw ex;
                }
                logger.trace("Done waiting for reply!");

            } catch (InterruptedException e) {
                logger.error(e);
            }

            if (!throwableList.isEmpty()) {
                Throwable throwable = throwableList.get(0);
                TransactionException e = new TransactionException(format(
                        "Channel %s connect failed on peer eventing service %s. Reason: %s", channelName, name, throwable.getMessage()), throwable);
                logger.error(e.getMessage(), e);
                throw e;
            }

            return retList.toArray(new DeliverResponse[retList.size()]);
        } catch (Throwable t) {
            managedChannel = null;
            throw t;

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

        final Envelope latestBlock;
        try {

            Ab.SeekPosition.Builder start = Ab.SeekPosition.newBuilder();
            if (null != peerOptions.getNewest()) {
                start.setNewest(Ab.SeekNewest.getDefaultInstance());
            } else if (peerOptions.getStartEvents() != null) {
                start.setSpecified(Ab.SeekSpecified.newBuilder().setNumber(peerOptions.getStartEvents()));
            } else {
                start.setNewest(Ab.SeekNewest.getDefaultInstance());
            }

            latestBlock = createSeekInfoEnvelope(transactionContext,
                    start.build(),
                    Ab.SeekPosition.newBuilder()
                            .setSpecified(Ab.SeekSpecified.newBuilder().setNumber(peerOptions.getStopEvents()).build())
                            //                          .setSpecified(Ab.SeekSpecified.newBuilder().setNumber(1L).build())
                            .build(),
                    SeekInfo.SeekBehavior.BLOCK_UNTIL_READY

            );
            DeliverResponse[] deliver = connectEnvelope(latestBlock);
        } catch (CryptoException e) {
            throw new TransactionException(e);
        }

    }

}
