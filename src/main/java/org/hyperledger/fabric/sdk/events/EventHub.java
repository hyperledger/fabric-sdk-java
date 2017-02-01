/*
 *  Copyright 2016 IBM, DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
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

import io.grpc.ManagedChannel;
import io.grpc.stub.StreamObserver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.EventsGrpc;
import org.hyperledger.fabric.protos.peer.PeerEvents;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.Endpoint;

/**
 * Class to manage fabric events.
 * <p>
 * Feeds Chain event queues with events
 */

public class EventHub {
    private static final Log logger = LogFactory.getLog(EventHub.class);


    private final String url;
    private final String pem;
    private ManagedChannel channel;
    private boolean connected = false;
    private EventsGrpc.EventsStub events;
    private StreamObserver<PeerEvents.Event> sender;

    /**
     * Event queue for all events from eventhubs in the chain
     */
    private Chain.ChainEventQue eventQue;


    //private static EventHub eventHub = null;


    private EventHub(String url, String pem) {
        this.url = url;
        this.pem = pem;
    }

    public void connect() {
        if (connected) {
            logger.warn("Event Hub already connected.");
            return;
        }

        channel = new Endpoint(url, pem).getChannelBuilder().build();

        events = EventsGrpc.newStub(channel);


        StreamObserver<PeerEvents.Event> eventStream = new StreamObserver<PeerEvents.Event>() {
            @Override
            public void onNext(PeerEvents.Event event) {
                eventQue.addBEvent(event);  //add to chain queue

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


        sender = events.chat(eventStream);
        blockListen();

        connected = true;

    }

    private void blockListen() {


        PeerEvents.Register.Builder register = PeerEvents.Register.newBuilder()
                .addEvents(PeerEvents.Interest.newBuilder()
                        .setEventType(PeerEvents.EventType.BLOCK));

        PeerEvents.Event blockEvent = PeerEvents.Event.newBuilder().setRegister(register).build();
        sender.onNext(blockEvent);


    }

    /**
     * Create a new instance.
     *
     * @param url
     * @param pem
     * @return
     */

    public static EventHub createNewInstance(String url, String pem) {
        return new EventHub(url, pem);
    }

    /**
     * Get URL connected to.
     *
     * @return
     */
    public String getUrl() {
        return url;
    }

    /**
     * Set the chain queue that will receive events
     *
     * @param eventQue
     */
    public void setEventQue(Chain.ChainEventQue eventQue) {
        this.eventQue = eventQue;
    }


}



