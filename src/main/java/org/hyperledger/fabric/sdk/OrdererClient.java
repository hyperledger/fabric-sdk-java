/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.protos.orderer.AtomicBroadcastGrpc;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;

import static java.lang.String.format;
import static org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse.TypeCase.STATUS;

/**
 * Sample client code that makes gRPC calls to the server.
 */
class OrdererClient {
    private static final Log logger = LogFactory.getLog(OrdererClient.class);
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();
    private static final Config config = Config.getConfig();
    private static final long ORDERER_WAIT_TIME = config.getOrdererWaitTime();
    private final String channelName;
    private final ManagedChannelBuilder<?> channelBuilder;
    private final String toString;
    private boolean shutdown = false;

    private ManagedChannel managedChannel = null;
    private final String name;
    private final long ordererWaitTimeMilliSecs;

    /**
     * Construct client for accessing Orderer server using the existing managedChannel.
     */
    OrdererClient(Orderer orderer, ManagedChannelBuilder<?> channelBuilder, Properties properties) {

        this.channelBuilder = channelBuilder;
        name = orderer.getName();
        String url = orderer.getUrl();
        channelName = orderer.getChannel().getName();
        toString = "OrdererClient{" + "id: " + config.getNextID() + ", channel: " + channelName + ", name: " + name + ", url: " + url + "}";

        if (null == properties) {

            ordererWaitTimeMilliSecs = ORDERER_WAIT_TIME;

        } else {

            String ordererWaitTimeMilliSecsString = properties.getProperty("ordererWaitTimeMilliSecs", Long.toString(ORDERER_WAIT_TIME));

            long tempOrdererWaitTimeMilliSecs = ORDERER_WAIT_TIME;

            try {
                tempOrdererWaitTimeMilliSecs = Long.parseLong(ordererWaitTimeMilliSecsString);
            } catch (NumberFormatException e) {
                logger.warn(format("Orderer %s wait time %s not parsable.", toString(), ordererWaitTimeMilliSecsString), e);
            }

            ordererWaitTimeMilliSecs = tempOrdererWaitTimeMilliSecs;
        }

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
        managedChannel = null;
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

    @Override
    public void finalize() throws Throwable {
        try {
            shutdown(true);
        } finally {
            super.finalize();
        }
    }

    Ab.BroadcastResponse sendTransaction(Common.Envelope envelope) throws Exception {
        logger.trace(toString() + " OrdererClient.sendTransaction entered.");
        StreamObserver<Common.Envelope> nso = null;

        if (shutdown) {
            throw new TransactionException(toString() + " is shutdown");
        }

        ManagedChannel lmanagedChannel = managedChannel;
        if (IS_TRACE_LEVEL && lmanagedChannel != null) {
            logger.trace(format("%s  managed channel isTerminated: %b, isShutdown: %b, state: %s", toString(),
                    lmanagedChannel.isTerminated(), lmanagedChannel.isShutdown(), lmanagedChannel.getState(false).name()));
        }

        if (lmanagedChannel == null || lmanagedChannel.isTerminated() || lmanagedChannel.isShutdown()) {

            if (lmanagedChannel != null && lmanagedChannel.isTerminated()) {
                logger.warn(format("%s managed channel was marked terminated", toString()));
            }
            if (lmanagedChannel != null && lmanagedChannel.isShutdown()) {
                logger.warn(format("%s managed channel was marked shutdown.", toString()));
            }

            lmanagedChannel = channelBuilder.build();
            managedChannel = lmanagedChannel;

        }

        if (IS_TRACE_LEVEL && lmanagedChannel != null) {
            logger.trace(format("%s  managed channel isTerminated: %b, isShutdown: %b, state: %s", toString(),
                    lmanagedChannel.isTerminated(), lmanagedChannel.isShutdown(), lmanagedChannel.getState(false).name()));
        }

        try {
            final CountDownLatch finishLatch = new CountDownLatch(1);
            AtomicBroadcastGrpc.AtomicBroadcastStub broadcast = AtomicBroadcastGrpc.newStub(lmanagedChannel);

            final Ab.BroadcastResponse[] ret = new Ab.BroadcastResponse[1];
            final Throwable[] throwable = new Throwable[] {null};

            StreamObserver<Ab.BroadcastResponse> so = new StreamObserver<Ab.BroadcastResponse>() {
                @Override
                public void onNext(Ab.BroadcastResponse resp) {
                    // logger.info("Got Broadcast response: " + resp);
                    logger.debug(OrdererClient.this.toString() + " resp status value: " + resp.getStatusValue() + ", resp: " + resp.getStatus());
                    if (resp.getStatus() == Common.Status.SUCCESS) {
                        ret[0] = resp;
                    } else {
                        throwable[0] = new TransactionException(format("Channel %s orderer %s status returned failure code %d (%s) during orderer next",
                                channelName, name, resp.getStatusValue(), resp.getStatus().name()));
                    }
                    finishLatch.countDown();

                }

                @Override
                public void onError(Throwable t) {
                    if (!shutdown) {
                        ManagedChannel lmanagedChannel = managedChannel;
                        managedChannel = null;
                        if (lmanagedChannel == null) {
                            logger.error(OrdererClient.this.toString() + " managed channel was null.");

                        } else {

                            logger.error(format("%s  managed channel isTerminated: %b, isShutdown: %b, state: %s", OrdererClient.this.toString(),
                                    lmanagedChannel.isTerminated(), lmanagedChannel.isShutdown(), lmanagedChannel.getState(false).name()));

                        }
                        logger.error(format("Received error %s  %s",
                                toString(), t.getMessage()), t);
                    }
                    throwable[0] = t;
                    finishLatch.countDown();
                }

                @Override
                public void onCompleted() {
                    logger.trace(OrdererClient.this.toString() + " onComplete received.");
                    finishLatch.countDown();
                }
            };

            nso = broadcast.broadcast(so);

            nso.onNext(envelope);

            try {
                if (!finishLatch.await(ordererWaitTimeMilliSecs, TimeUnit.MILLISECONDS)) {
                    TransactionException ste = new TransactionException(format("Channel %s, send transactions failed on orderer %s. Reason:  timeout after %d ms.",
                            channelName, toString(), ordererWaitTimeMilliSecs));
                    logger.error("sendTransaction error " + ste.getMessage(), ste);
                    throw ste;
                }
                if (throwable[0] != null) {
                    Throwable t = throwable[0];
                    if (t instanceof StatusRuntimeException) {
                        StatusRuntimeException sre = (StatusRuntimeException) t;
                        Status status = sre.getStatus();
                        logger.error(format("%s grpc status Code:%s, Description %s, ", toString(), status.getDescription(), status.getCode() + ""), sre.getCause());
                    }
                    //get full stack trace
                    TransactionException ste = new TransactionException(format("Channel %s, send transaction failed on orderer %s. Reason: %s",
                            channelName, toString(), throwable[0].getMessage()), throwable[0]);
                    logger.error(toString() + "sendTransaction error " + ste.getMessage(), ste);
                    throw ste;
                }
                logger.debug(toString() + " done waiting for reply! Got:" + ret[0]);

            } catch (InterruptedException e) {
                logger.error(toString(), e);

            }

            return ret[0];
        } catch (Throwable t) {
            managedChannel = null;
            throw t;

        } finally {

            if (null != nso) {

                try {
                    nso.onCompleted();
                } catch (Exception e) {  //Best effort only report on debug
                    logger.debug(format("Exception completing sendTransaction with %s %s",
                            toString(), e.getMessage()), e);
                }
            }

        }
    }

    DeliverResponse[] sendDeliver(Common.Envelope envelope) throws TransactionException {

        logger.trace(toString() + " OrdererClient.sendDeliver entered.");

        if (shutdown) {
            throw new TransactionException("Orderer client is shutdown");
        }

        StreamObserver<Common.Envelope> nso = null;

        ManagedChannel lmanagedChannel = managedChannel;
        if (IS_TRACE_LEVEL && lmanagedChannel != null) {
            logger.trace(format("%s  managed channel isTerminated: %b, isShutdown: %b, state: %s", toString(),
                    lmanagedChannel.isTerminated(), lmanagedChannel.isShutdown(), lmanagedChannel.getState(false).name()));
        }

        if (lmanagedChannel == null || lmanagedChannel.isTerminated() || lmanagedChannel.isShutdown()) {

            if (lmanagedChannel != null && lmanagedChannel.isTerminated()) {
                logger.warn(format("%s managed channel was marked terminated", toString()));
            }
            if (lmanagedChannel != null && lmanagedChannel.isShutdown()) {
                logger.warn(format("%s managed channel was marked shutdown.", toString()));
            }
            lmanagedChannel = channelBuilder.build();
            managedChannel = lmanagedChannel;

        }

        if (IS_TRACE_LEVEL && lmanagedChannel != null) {
            logger.trace(format("%s  managed channel isTerminated: %b, isShutdown: %b, state: %s", toString(),
                    lmanagedChannel.isTerminated(), lmanagedChannel.isShutdown(), lmanagedChannel.getState(false).name()));
        }
        /*
        return lchannel != null && !lchannel.isShutdown() && !lchannel.isTerminated() && ConnectivityState.READY.equals(lchannel.getState(true));
         */

        try {

            AtomicBroadcastGrpc.AtomicBroadcastStub broadcast = AtomicBroadcastGrpc.newStub(lmanagedChannel);

            // final DeliverResponse[] ret = new DeliverResponse[1];
            final List<DeliverResponse> retList = new ArrayList<>();
            final List<Throwable> throwableList = new ArrayList<>();
            final CountDownLatch finishLatch = new CountDownLatch(1);

            StreamObserver<DeliverResponse> so = new StreamObserver<DeliverResponse>() {
                boolean done = false;

                @Override
                public void onNext(DeliverResponse resp) {

                    // logger.info("Got Broadcast response: " + resp);
                    logger.debug(OrdererClient.this.toString() + "sendDeliver resp status value: " + resp.getStatusValue() + ", resp: " + resp.getStatus() + ", type case: " + resp.getTypeCase());

                    if (done) {
                        logger.trace(OrdererClient.this.toString() + " sendDeliver done!");
                        return;
                    }

                    if (resp.getTypeCase() == STATUS) {
                        done = true;
                        retList.add(0, resp);

                        finishLatch.countDown();

                    } else {
                        retList.add(resp);
                    }

                }

                @Override
                public void onError(Throwable t) {
                    if (!shutdown) {

                        ManagedChannel lmanagedChannel = managedChannel;
                        managedChannel = null;
                        if (lmanagedChannel == null) {
                            logger.error(OrdererClient.this.toString() + " managed channel was null.");

                        } else {

                            logger.error(format("%s  managed channel isTerminated: %b, isShutdown: %b, state: %s", OrdererClient.this.toString(),
                                    lmanagedChannel.isTerminated(), lmanagedChannel.isShutdown(), lmanagedChannel.getState(false).name()));

                        }
                        logger.error(format("Received error on %s %s",
                                OrdererClient.this.toString(), t.getMessage()), t);
                    }
                    throwableList.add(t);
                    finishLatch.countDown();
                }

                @Override
                public void onCompleted() {
                    logger.trace(OrdererClient.this.toString() + " onCompleted.");
                    finishLatch.countDown();
                }
            };

            nso = broadcast.deliver(so);
            nso.onNext(envelope);
            //nso.onCompleted();

            try {
                if (!finishLatch.await(ordererWaitTimeMilliSecs, TimeUnit.MILLISECONDS)) {
                    TransactionException ex = new TransactionException(format(
                            "Channel %s sendDeliver time exceeded for orderer %s, timed out at %d ms.", channelName, toString(), ordererWaitTimeMilliSecs));
                    logger.error(ex.getMessage(), ex);
                    throw ex;
                }
                logger.trace(toString() + " Done waiting for reply!");

            } catch (InterruptedException e) {
                logger.error(toString() + " " + e.getMessage(), e);
            }

            if (!throwableList.isEmpty()) {
                Throwable throwable = throwableList.get(0);
                TransactionException e = new TransactionException(format(
                        "Channel %s sendDeliver failed on orderer %s. Reason: %s", channelName, toString(), throwable.getMessage()), throwable);
                logger.error(e.getMessage(), e);
                throw e;
            }

            return retList.toArray(new DeliverResponse[0]);
        } catch (Throwable t) {
            managedChannel = null;
            logger.error(toString() + " received error " + t.getMessage(), t);
            throw t;

        } finally {
            if (null != nso) {

                try {
                    logger.debug(toString() + "completed.");
                    nso.onCompleted();
                } catch (Exception e) {  //Best effort only report on debug
                    logger.debug(format("Exception completing sendDeliver with %s %s",
                            toString(), e.getMessage()), e);
                }

            }
        }
    }

    @Override
    public String toString() {
        return toString;
    }

    boolean isChannelActive() {
        final ManagedChannel lchannel = managedChannel;
        if (null == lchannel) {
            logger.trace(toString() + " Grpc channel needs creation.");
            return false;
        }

        final boolean isTerminated = lchannel.isTerminated();
        final boolean isShutdown = lchannel.isShutdown();
        final boolean ret = !lchannel.isShutdown() && !isTerminated; // && ConnectivityState.READY.equals(lchannel.getState(true));
        logger.trace(format("%s grpc channel isActive: %b, isShutdown: %b, isTerminated: %b, state: %s ", toString(), ret, isShutdown, isTerminated, "" + lchannel.getState(false)));

        return ret;
    }
}
