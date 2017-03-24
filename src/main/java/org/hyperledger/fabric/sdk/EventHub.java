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

package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Properties;

import io.grpc.ManagedChannel;
import io.grpc.stub.StreamObserver;
import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.EventsGrpc;
import org.hyperledger.fabric.protos.peer.PeerEvents;
import org.hyperledger.fabric.sdk.exception.EventHubException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

import static org.hyperledger.fabric.sdk.helper.SDKUtil.checkGrpcUrl;

/**
 * Class to manage fabric events.
 * <p>
 * Feeds Chain event queues with events
 */

public class EventHub {
    private static final Log logger = LogFactory.getLog(EventHub.class);


    private final String url;
    private final String name;
    private final Properties properties;
    private ManagedChannel channel;
    private boolean connected = false;
    private EventsGrpc.EventsStub events;
    private StreamObserver<PeerEvents.Event> sender;
    /**
     * Event queue for all events from eventhubs in the chain
     */
    private Chain.ChainEventQue eventQue;

    EventHub(String name, String grpcURL, Properties properties) throws InvalidArgumentException {

        Exception e = checkGrpcUrl(grpcURL);
        if (e != null) {
            throw new InvalidArgumentException("Bad peer url.", e);

        }


        if (StringUtil.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for eventHub");
        }

        this.url = grpcURL;
        this.name = name;
        this.properties = properties == null ? null : (Properties) properties.clone(); //keep our own copy.
    }

    /**
     * Create a new instance.
     *
     * @param name
     * @param url
     * @param properties
     * @return
     */

    static EventHub createNewInstance(String name, String url, Properties properties) throws InvalidArgumentException {
        return new EventHub(name, url, properties);
    }


    /**
     * Event hub name
     *
     * @return event hub name
     */

    public String getName() {
        return name;
    }

    /**
     * Event hub properties
     *
     * @see HFClient#newEventHub(String, String, Properties)
     *
     * @return Event hub properties
     */
    public Properties getProperties() {
        return properties == null ? null : (Properties) properties.clone();
    }

    void connect() throws EventHubException {
        if (connected) {
            logger.warn("Event Hub already connected.");
            return;
        }

        channel = new Endpoint(url, properties).getChannelBuilder().build();

        events = EventsGrpc.newStub(channel);


        final ArrayList<Throwable> threw = new ArrayList<>();


        StreamObserver<PeerEvents.Event> eventStream = new StreamObserver<PeerEvents.Event>() {
            @Override
            public void onNext(PeerEvents.Event event) {
                eventQue.addBEvent(event);  //add to chain queue

            }

            @Override
            public void onError(Throwable t) {

                logger.error("Error in stream: " + t.getMessage(), t);
                threw.add(t);
                eventQue.eventError(t);
            }

            @Override
            public void onCompleted() {

                logger.info("Stream completed");
            }
        };


        sender = events.chat(eventStream);
        blockListen();

        //

        if (!threw.isEmpty()) {
            Throwable t = threw.iterator().next();

            EventHubException evh = new EventHubException(t.getMessage(), t);
            logger.error(String.format("EventHub %s Error in stream. error: " + t.getMessage(), url), evh);
            throw evh;

        }

        connected = true;

    }

    private void blockListen() {


        PeerEvents.Register register = PeerEvents.Register.newBuilder()
                .addEvents(PeerEvents.Interest.newBuilder()
                        .setEventType(PeerEvents.EventType.BLOCK).build()).build();

        PeerEvents.Event blockEvent = PeerEvents.Event.newBuilder().setRegister(register).build();
        sender.onNext(blockEvent);


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
    void setEventQue(Chain.ChainEventQue eventQue) {
        this.eventQue = eventQue;
    }


}



