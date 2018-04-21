/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.peer.PeerEvents;
import org.hyperledger.fabric.protos.peer.PeerEvents.Event;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

/**
 * A wrapper for the Block returned in an Event
 *
 * @see Block
 */
public class BlockEvent extends BlockInfo {
//    private static final Log logger = LogFactory.getLog(BlockEvent.class);

    private final EventHub eventHub;
    private final Peer peer;
    private final Event event;

    /**
     * creates a BlockEvent object by parsing the input Block and retrieving its constituent Transactions
     *
     * @param eventHub a Hyperledger Fabric Block message
     * @throws InvalidProtocolBufferException
     * @see Block
     */
    BlockEvent(EventHub eventHub, Event event) throws InvalidProtocolBufferException {
        super(event.getBlock());
        this.eventHub = eventHub;
        this.peer = null;
        this.event = event;
    }

    BlockEvent(Peer peer, PeerEvents.DeliverResponse resp) {
        super(resp);
        eventHub = null;
        this.peer = peer;
        this.event = null;

    }

    /**
     * Get the Event Hub that received the event.
     *
     * @return an Event Hub. Maybe null if new peer eventing services is being used.
     * @deprecated Use new peer eventing services
     */
    public EventHub getEventHub() {
        return eventHub;
    }

    /**
     * The Peer that received this event.
     *
     * @return Peer that received this event. Maybe null if source is legacy event hub.
     */
    public Peer getPeer() {
        return peer;
    }

//    /**
//     * Raw proto buff event.
//     *
//     * @return Return raw protobuf event.
//     */
//
//    public Event getEvent() {
//        return event;
//    }

    boolean isBlockEvent() {
        if (peer != null) {
            return true; //peer always returns Block type events;
        }

        return event != null && event.getEventCase() == PeerEvents.Event.EventCase.BLOCK;
    }

    TransactionEvent getTransactionEvent(int index) throws InvalidProtocolBufferException {

        return isFiltered() ? new TransactionEvent(getEnvelopeInfo(index).filteredTx) :
                new TransactionEvent((TransactionEnvelopeInfo) getEnvelopeInfo(index));
    }

    public class TransactionEvent extends TransactionEnvelopeInfo {
        TransactionEvent(TransactionEnvelopeInfo transactionEnvelopeInfo) {
            super(transactionEnvelopeInfo.getTransactionDeserializer());
        }

        TransactionEvent(PeerEvents.FilteredTransaction filteredTransaction) {
            super(filteredTransaction);
        }

        /**
         * The BlockEvent for this TransactionEvent.
         *
         * @return BlockEvent for this transaction.
         */

        public BlockEvent getBlockEvent() {

            return BlockEvent.this;

        }

        /**
         * The event hub that received this event.
         *
         * @return May return null if peer eventing service detected the event.
         * @deprecated use new peer eventing services {@link #getPeer()}
         */

        public EventHub getEventHub() {

            return BlockEvent.this.getEventHub();
        }

        /**
         * The peer that received this event.
         *
         * @return May return null if deprecated eventhubs are still being used, otherwise return the peer.
         */

        public Peer getPeer() {

            return BlockEvent.this.getPeer();
        }
    }

    List<TransactionEvent> getTransactionEventsList() {

        ArrayList<TransactionEvent> ret = new ArrayList<TransactionEvent>(getEnvelopeCount());
        for (TransactionEvent transactionEvent : getTransactionEvents()) {
            ret.add(transactionEvent);
        }

        return ret;

    }

    public Iterable<TransactionEvent> getTransactionEvents() {

        return new TransactionEventIterable();

    }

    class TransactionEventIterator implements Iterator<TransactionEvent> {
        final int max;
        int ci = 0;

        TransactionEventIterator() {
            max = getEnvelopeCount();

        }

        @Override
        public boolean hasNext() {
            return ci < max;

        }

        @Override
        public TransactionEvent next() {

            try {
                return getTransactionEvent(ci++);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

        }

    }

    class TransactionEventIterable implements Iterable<TransactionEvent> {

        @Override
        public Iterator<TransactionEvent> iterator() {
            return new TransactionEventIterator();
        }
    }

} // BlockEvent
