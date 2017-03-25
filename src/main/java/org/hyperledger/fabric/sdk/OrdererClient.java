/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.protos.orderer.AtomicBroadcastGrpc;
import org.hyperledger.fabric.sdk.exception.TransactionException;

import static org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse.TypeCase.STATUS;

/**
 * Sample client code that makes gRPC calls to the server.
 */
class OrdererClient {
    private static final Log logger = LogFactory.getLog(OrdererClient.class);
    private final ManagedChannel channel;

    /**
     * Construct client for accessing Orderer server using the existing channel.
     */
    OrdererClient(ManagedChannelBuilder<?> channelBuilder) {
        channel = channelBuilder.build();
    }

    private void shutdown() {
        if(!channel.isShutdown()) {
            channel.shutdownNow();
        }
    }

    @Override
    public void finalize() {
        shutdown();
    }

    Ab.BroadcastResponse sendTransaction(Common.Envelope envelope) throws Exception {

        final CountDownLatch finishLatch = new CountDownLatch(1);
        AtomicBroadcastGrpc.AtomicBroadcastStub broadcast = AtomicBroadcastGrpc.newStub(channel);
        AtomicBroadcastGrpc.AtomicBroadcastBlockingStub bsc = AtomicBroadcastGrpc.newBlockingStub(channel);
        bsc.withDeadlineAfter(2, TimeUnit.MINUTES);

        final Ab.BroadcastResponse[] ret = new Ab.BroadcastResponse[1];
        final Throwable[] throwable = new Throwable[]{null};

        StreamObserver<Ab.BroadcastResponse> so = new StreamObserver<Ab.BroadcastResponse>() {
            @Override
            public void onNext(Ab.BroadcastResponse resp) {
                // logger.info("Got Broadcast response: " + resp);
                logger.debug("resp status value: " + resp.getStatusValue() + ", resp: " + resp.getStatus());
                ret[0] = resp;
                finishLatch.countDown();

            }

            @Override
            public void onError(Throwable t) {
                throwable[0] = t;
                finishLatch.countDown();
            }

            @Override
            public void onCompleted() {
                logger.warn("onCompleted");
                finishLatch.countDown();
            }
        };


        StreamObserver<Common.Envelope> nso = broadcast.broadcast(so);

        nso.onNext(envelope);
        //nso.onCompleted();

        try {
            finishLatch.await(2, TimeUnit.MINUTES);
            if (throwable[0] != null) {
                //get full stack trace
                TransactionException ste = new TransactionException("Send transactions failed. Reason: " + throwable[0].getMessage(), throwable[0]);
                logger.error("sendTransaction error " + ste.getMessage(), ste);
                throw ste;
            }
            logger.debug("Done waiting for reply! Got:" + ret[0]);

        } catch (InterruptedException e) {
            logger.error(e);

        } finally {
            shutdown();
        }

        return ret[0];
    }

    public DeliverResponse[] sendDeliver(Common.Envelope envelope) throws TransactionException{

        final CountDownLatch finishLatch = new CountDownLatch(1);
        AtomicBroadcastGrpc.AtomicBroadcastStub broadcast = AtomicBroadcastGrpc.newStub(channel);
        AtomicBroadcastGrpc.AtomicBroadcastBlockingStub bsc = AtomicBroadcastGrpc.newBlockingStub(channel);
        bsc.withDeadlineAfter(2, TimeUnit.MINUTES);

        // final DeliverResponse[] ret = new DeliverResponse[1];
        final List<DeliverResponse> retList = new ArrayList<>();
        final List<Throwable> throwableList = new ArrayList<>();
        //   ret[0] = null;

        StreamObserver<DeliverResponse> so = new StreamObserver<DeliverResponse>() {
            boolean done = false;

            @Override
            public void onNext(DeliverResponse resp) {

                // logger.info("Got Broadcast response: " + resp);
                logger.debug("resp status value: " + resp.getStatusValue() + ", resp: " + resp.getStatus() + ", type case" + resp.getTypeCase());

                if (done) {
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
                logger.error("broadcase error " + t);
                throwableList.add(t);
                finishLatch.countDown();
            }

            @Override
            public void onCompleted() {
                logger.warn("onCompleted");
                finishLatch.countDown();
            }
        };

        StreamObserver<Common.Envelope> nso = broadcast.deliver(so);
        nso.onNext(envelope);
        //nso.onCompleted();

        try {
            boolean res = finishLatch.await(2, TimeUnit.MINUTES);
            logger.trace("Done waiting for reply! Got:" + retList);

        } catch (InterruptedException e) {
            logger.error(e);
        }

        if(!throwableList.isEmpty()){
            Throwable throwable = throwableList.get(0);
            TransactionException e = new TransactionException(throwable.getMessage(), throwable);
            logger.error(e.getMessage(), e);
            throw e;
        }

        return retList.toArray(new DeliverResponse[retList.size()]);
    }
}
