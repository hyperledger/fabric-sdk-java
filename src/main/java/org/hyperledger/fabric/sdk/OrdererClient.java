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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.AtomicBroadcastGrpc;
import org.hyperledger.fabric.sdk.exception.TransactionException;

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


    void shutdown() throws InterruptedException {


        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }


    @Override
    public void finalize() {
        try {
            shutdown();
        } catch (InterruptedException e) {
            logger.debug("Failed to shutdown the OrdererClient");
        }
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

                logger.debug("onCompleted");

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


        }

        return ret[0];

    }
}
