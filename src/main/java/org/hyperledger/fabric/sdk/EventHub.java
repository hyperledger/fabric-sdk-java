/*
 *  Copyright 2016 IBM, DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
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
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.EventsGrpc;
import org.hyperledger.fabric.protos.peer.PeerEvents;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.EventHubException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.checkGrpcUrl;

/**
 * Class to manage fabric events.
 * <p>
 * Feeds Channel event queues with events
 */

public class EventHub {
    private static final Log logger = LogFactory.getLog(EventHub.class);
    private static final Config config = Config.getConfig();
    private static final long EVENTHUB_CONNECTION_WAIT_TIME = config.getEventHubConnectionWaitTime();
    private final ExecutorService executorService;

    private final String url;
    private final String name;
    private final Properties properties;
    private ManagedChannel managedChannel;
    private boolean connected = false;
    private EventsGrpc.EventsStub events;
    private StreamObserver<PeerEvents.SignedEvent> sender;
    /**
     * Event queue for all events from eventhubs in the channel
     */
    private Channel.ChannelEventQue eventQue;
    private long connectedTime = 0L; // 0 := never connected
    private boolean shutdown = false;
    private Channel channel;
    private TransactionContext transactionContext;

    /**
     * Get disconnected time.
     *
     * @return Time in milli seconds disconnect occurred. Zero if never disconnected
     */
    public long getDisconnectedTime() {
        return disconnectedTime;
    }

    private long disconnectedTime;

    /**
     * Is event hub connected.
     *
     * @return boolean if true event hub is connected.
     */
    public boolean isConnected() {
        return connected;
    }

    /**
     * Get last connect time.
     *
     * @return Time in milli seconds the event hub last connected. Zero if never connected.
     */
    public long getConnectedTime() {
        return connectedTime;
    }

    /**
     * Get last attempt time to connect the event hub.
     *
     * @return Last attempt time to connect the event hub in milli seconds. Zero when never attempted.
     */

    public long getLastConnectedAttempt() {
        return lastConnectedAttempt;
    }

    private long lastConnectedAttempt;

    EventHub(String name, String grpcURL, ExecutorService executorService, Properties properties) throws InvalidArgumentException {

        Exception e = checkGrpcUrl(grpcURL);
        if (e != null) {
            throw new InvalidArgumentException("Bad event hub url.", e);

        }

        if (StringUtil.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for eventHub");
        }

        this.url = grpcURL;
        this.name = name;
        this.executorService = executorService;
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

    static EventHub createNewInstance(String name, String url, ExecutorService executorService, Properties properties) throws InvalidArgumentException {
        return new EventHub(name, url, executorService, properties);
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
     * @return Event hub properties
     * @see HFClient#newEventHub(String, String, Properties)
     */
    public Properties getProperties() {
        return properties == null ? null : (Properties) properties.clone();
    }

    boolean connect() throws EventHubException {

        if (transactionContext == null) {
            throw new EventHubException("Eventhub reconnect failed with no user context");
        }

        return connect(transactionContext);

    }

    private StreamObserver<PeerEvents.Event> eventStream = null; // Saved here to avoid potential garbage collection

    synchronized boolean connect(final TransactionContext transactionContext) throws EventHubException {
        if (connected) {
            logger.warn(format("%s already connected.", toString()));
            return true;
        }
        eventStream = null;

        final CountDownLatch finishLatch = new CountDownLatch(1);

        logger.debug(format("EventHub %s is connecting.", name));

        lastConnectedAttempt = System.currentTimeMillis();

        managedChannel = new Endpoint(url, properties).getChannelBuilder().build();

        events = EventsGrpc.newStub(managedChannel);

        final ArrayList<Throwable> threw = new ArrayList<>();

        final StreamObserver<PeerEvents.Event> eventStreamLocal = new StreamObserver<PeerEvents.Event>() {
            @Override
            public void onNext(PeerEvents.Event event) {

                logger.debug(format("EventHub %s got  event type: %s", EventHub.this.name, event.getEventCase().name()));

                if (event.getEventCase() == PeerEvents.Event.EventCase.BLOCK) {
                    try {
                        eventQue.addBEvent(new BlockEvent(EventHub.this, event));  //add to channel queue
                    } catch (InvalidProtocolBufferException e) {
                        EventHubException eventHubException = new EventHubException(format("%s onNext error %s", this, e.getMessage()), e);
                        logger.error(eventHubException.getMessage());
                        threw.add(eventHubException);
                    }
                } else if (event.getEventCase() == PeerEvents.Event.EventCase.REGISTER) {

                    connected = true;
                    connectedTime = System.currentTimeMillis();
                    finishLatch.countDown();
                }
            }

            @Override
            public void onError(Throwable t) {
                if (shutdown) { //IF we're shutdown don't try anything more.
                    logger.trace(format("%s was shutdown.", EventHub.this.toString()));
                    connected = false;
                    eventStream = null;
                    finishLatch.countDown();
                    return;
                }

                final boolean isTerminated = managedChannel.isTerminated();
                final boolean isChannelShutdown = managedChannel.isShutdown();

                logger.error(format("%s terminated is %b shutdown is %b has error %s ", EventHub.this.toString(), isTerminated, isChannelShutdown,
                        t.getMessage()), new EventHubException(t));
                threw.add(t);
                finishLatch.countDown();

                //              logger.error("Error in stream: " + t.getMessage(), new EventHubException(t));
                if (t instanceof StatusRuntimeException) {
                    StatusRuntimeException sre = (StatusRuntimeException) t;
                    Status sreStatus = sre.getStatus();
                    logger.error(format("%s :StatusRuntimeException Status %s.  Description %s ", EventHub.this, sreStatus + "", sreStatus.getDescription()));
                    if (sre.getStatus().getCode() == Status.Code.INTERNAL || sre.getStatus().getCode() == Status.Code.UNAVAILABLE) {

                        connected = false;
                        eventStream = null;
                        disconnectedTime = System.currentTimeMillis();
                        try {
                            if (!isChannelShutdown) {
                                managedChannel.shutdownNow();
                            }
                            if (null != disconnectedHandler) {
                                try {
                                    disconnectedHandler.disconnected(EventHub.this);
                                } catch (Exception e) {
                                    logger.warn(format("Eventhub %s  %s", EventHub.this.name, e.getMessage()), e);
                                    eventQue.eventError(e);
                                }
                            }
                        } catch (Exception e) {
                            logger.warn(format("Eventhub %s Failed shutdown msg:  %s", EventHub.this.name, e.getMessage()), e);
                        }
                    }
                }

            }

            @Override
            public void onCompleted() {

                logger.warn(format("Stream completed %s", EventHub.this.toString()));
                finishLatch.countDown();

            }
        };

        sender = events.chat(eventStreamLocal);
        try {
            blockListen(transactionContext);
        } catch (CryptoException e) {
            throw new EventHubException(e);
        }

        try {
            if (!finishLatch.await(EVENTHUB_CONNECTION_WAIT_TIME, TimeUnit.MILLISECONDS)) {
                EventHubException evh = new EventHubException(format("EventHub %s failed to connect in %s ms.", name, EVENTHUB_CONNECTION_WAIT_TIME));
                logger.debug(evh.getMessage(), evh);

                throw evh;
            }
            logger.trace(format("Eventhub %s Done waiting for reply!", name));

        } catch (InterruptedException e) {
            logger.error(e);
        }



        if (!threw.isEmpty()) {
            eventStream = null;
            connected = false;
            Throwable t = threw.iterator().next();

            EventHubException evh = new EventHubException(t.getMessage(), t);
            logger.error(format("EventHub %s Error in stream. error: " + t.getMessage(), toString()), evh);
            throw evh;

        }

        logger.info(format("Eventhub %s connect is done with connect status: %b ", name, connected));

        if (connected) {
            eventStream = eventStreamLocal;
        }

        return connected;

    }

    private void blockListen(TransactionContext transactionContext) throws CryptoException {

        this.transactionContext = transactionContext;

        PeerEvents.Register register = PeerEvents.Register.newBuilder()
                .addEvents(PeerEvents.Interest.newBuilder().setEventType(PeerEvents.EventType.BLOCK).build()).build();
        ByteString blockEventByteString = PeerEvents.Event.newBuilder().setRegister(register)
                .setCreator(transactionContext.getIdentity().toByteString())
                .build().toByteString();
        PeerEvents.SignedEvent signedBlockEvent = PeerEvents.SignedEvent.newBuilder()
                .setEventBytes(blockEventByteString)
                .setSignature(transactionContext.signByteString(blockEventByteString.toByteArray()))
                .build();
        sender.onNext(signedBlockEvent);
    }

    /**
     * Get the GRPC URL used to connect.
     *
     * @return GRPC URL.
     */
    public String getUrl() {
        return url;
    }

    /**
     * Set the channel queue that will receive events
     *
     * @param eventQue
     */
    void setEventQue(Channel.ChannelEventQue eventQue) {
        this.eventQue = eventQue;
    }

    @Override
    public String toString() {
        return "EventHub:" + getName();
    }

    public void shutdown() {
        shutdown = true;
        connected = false;
        disconnectedHandler = null;
        channel = null;
        eventStream = null;
        managedChannel.shutdownNow();
    }

    void setChannel(Channel channel) throws InvalidArgumentException {
        if (channel == null) {
            throw new InvalidArgumentException("setChannel Channel can not be null");
        }

        if (null != this.channel) {
            throw new InvalidArgumentException(format("Can not add event hub  %s to channel %s because it already belongs to channel %s.",
                    name, channel.getName(), this.channel.getName()));
        }

        this.channel = channel;
    }

    /**
     * Eventhub disconnection notification interface
     */
    public interface EventHubDisconnected {

        /**
         * Called when a disconnect is detected.
         *
         * @param eventHub
         * @throws EventHubException
         */
        void disconnected(EventHub eventHub) throws EventHubException;

    }

    /**
     * Default reconnect event hub implementation.  Applications are free to replace
     */

    protected EventHubDisconnected disconnectedHandler = new EventHub.EventHubDisconnected() {
        @Override
        public synchronized void disconnected(final EventHub eventHub) throws EventHubException {
            logger.info(format("Detected disconnect %s", eventHub.toString()));

            if (eventHub.connectedTime == 0) { //means event hub never connected
                logger.error(format("%s failed on first connect no retries", eventHub.toString()));

                eventHub.setEventHubDisconnectedHandler(null); //don't try again

                //event hub never connected.
                throw new EventHubException(format("%s never connected.", eventHub.toString()));
            }

            executorService.execute(() -> {

                try {
                    Thread.sleep(500);

                    if (eventHub.connect()) {
                        logger.info(format("Successful reconnect %s", eventHub.toString()));
                    } else {
                        logger.info(format("Failed reconnect %s", eventHub.toString()));
                    }

                } catch (Exception e) {

                    logger.debug(format("Failed %s to reconnect. %s", toString(), e.getMessage()));

                }

            });

        }
    };

    /**
     * Set class to handle Event hub disconnects
     *
     * @param newEventHubDisconnectedHandler New handler to replace.  If set to null no retry will take place.
     * @return the old handler.
     */

    public EventHubDisconnected setEventHubDisconnectedHandler(EventHubDisconnected newEventHubDisconnectedHandler) {
        EventHubDisconnected ret = disconnectedHandler;
        disconnectedHandler = newEventHubDisconnectedHandler;
        return ret;
    }

}
