/*
 *  Copyright 2016 Wanda Group - All Rights Reserved.
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
package org.hyperledger.fabric.sdk.events;

import io.grpc.stub.StreamObserver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.Endpoint;
import org.hyperledger.fabric.sdk.exception.NoValidPeerException;
import org.hyperledger.protos.EventsGrpc;
import org.hyperledger.protos.EventsOuterClass;
import org.hyperledger.protos.Fabric;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class EventHub {
    private static final Log logger = LogFactory.getLog(EventHub.class);

    // peer addr to connect to
    private Endpoint ep;
    // grpc events interface
    private EventsGrpc.EventsStub events;
    // grpc chat streaming interface
    private StreamObserver<EventsOuterClass.Event> sender;
    // set of clients registered for block events
    private Set<BlockListener> blockRegistrants;
    // hashtable of clients registered for transactional events
    private Map<String, TransactionListener> txRegistrants;
    // fabric connection state of this eventhub
    private boolean connected;

    public EventHub() {
        this.blockRegistrants = new HashSet<>();
        this.txRegistrants = new HashMap<>();
        this.ep = null;
        this.connected = false;
    }

    public void setPeerAddr(String peeraddr, String pem) {
        this.ep = new Endpoint(peeraddr, pem);
    }

    public boolean isconnected() {
        return this.connected;
    }

    public void connect() {
        if (this.connected) {
            return;
        }
        if (this.ep == null) {
            throw new NoValidPeerException("Must set peer address before connecting.");
        }
        this.events = EventsGrpc.newStub(ep.getChannelBuilder().build());

        StreamObserver<EventsOuterClass.Event> receiver = new StreamObserver<EventsOuterClass.Event>() {
            @Override
            public void onNext(EventsOuterClass.Event event) {
                try {
                    switch (event.getEventCase()) {
                        case BLOCK:
                            for (BlockListener listener : blockRegistrants) {
                                listener.process(event.getBlock());
                            }
                            break;
                        case REJECTION:
                            // ignore rejection event for the time being
                            break;
                        case CHAINCODEEVENT:
                            // ignore chaincode event for the time being
                            break;
                        default:
                            logger.info("Unhandled event: " + event);
                    }
                } catch (Exception e) {
                    logger.error("Error handling event: " + event + " " + e.getMessage());
                }
            }

            @Override
            public void onError(Throwable t) {
                logger.error("Error in stream: " + t.getMessage());
            }

            @Override
            public void onCompleted() {
                logger.info("Stream completed");
            }
        };

        sender = this.events.chat(receiver);

        this.connected = true;

        this.registerBlockEvent(this.txCallback);
    }

    public void disconnect() {
        if (!this.connected) {
            return;
        }
        this.unregisterBlockEvent(this.txCallback);
        this.connected = false;
    }

    private void registerBlockEvent(BlockListener blockListener){
        if (!this.connected) {
            return;
        }
        this.blockRegistrants.add(blockListener);
        if(this.blockRegistrants.size() == 1) {
            EventsOuterClass.Interest.Builder blockInterest = EventsOuterClass.Interest.newBuilder()
                    .setEventType(EventsOuterClass.EventType.BLOCK);
            EventsOuterClass.Register.Builder register = EventsOuterClass.Register.newBuilder()
                    .addEvents(blockInterest);

            EventsOuterClass.Event blockEvent = EventsOuterClass.Event.newBuilder().setRegister(register).build();
            this.sender.onNext(blockEvent);
        }
    }

    private void unregisterBlockEvent(BlockListener blockListener){
        if (!this.connected) {
            return;
        }
        if(this.blockRegistrants.size() <= 1) {
            EventsOuterClass.Interest.Builder blockInterest = EventsOuterClass.Interest.newBuilder()
                    .setEventType(EventsOuterClass.EventType.BLOCK);
            EventsOuterClass.Unregister.Builder unregister = EventsOuterClass.Unregister.newBuilder()
                    .addEvents(blockInterest);

            EventsOuterClass.Event blockEvent = EventsOuterClass.Event.newBuilder().setUnregister(unregister).build();
            this.sender.onNext(blockEvent);
        }
        this.blockRegistrants.remove(blockListener);
    }

    public void registerTxEvent(String txid, TransactionListener listener){
        this.txRegistrants.put(txid, listener);
    }

    public void unregisterTxEvent(String txid){
        this.txRegistrants.remove(txid);
    }

    private BlockListener txCallback = new BlockListener() {
        @Override
        public void process(Fabric.Block block) {
            for (Fabric.Transaction transaction : block.getTransactionsList()) {
                TransactionListener transactionListener = txRegistrants.get(transaction.getTxid());
                if (transactionListener != null) {
                    transactionListener.process(transaction);
                }
            }
        }
    };
}
