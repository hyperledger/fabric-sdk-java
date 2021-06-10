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
import org.hyperledger.fabric.protos.peer.EventsPackage;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

/**
 * A wrapper for the Block returned in an Event
 *
 * @see Block
 */
public class BlockEvent extends BlockInfo {
    private final Peer peer;

    BlockEvent(Peer peer, EventsPackage.DeliverResponse resp) {
        super(resp);
        this.peer = peer;
    }

    /**
     * The Peer that received this event.
     *
     * @return Peer that received this event
     */
    public Peer getPeer() {
        return peer;
    }

    TransactionEvent getTransactionEvent(int index) throws InvalidProtocolBufferException {
        TransactionEvent ret = null;

        EnvelopeInfo envelopeInfo = getEnvelopeInfo(index);
        if (envelopeInfo.getType() == EnvelopeType.TRANSACTION_ENVELOPE) {
            if (isFiltered()) {
                ret = new TransactionEvent(getEnvelopeInfo(index).filteredTx);
            } else {
                ret = new TransactionEvent((TransactionEnvelopeInfo) getEnvelopeInfo(index));
            }
        }

        return ret;
    }

    public class TransactionEvent extends TransactionEnvelopeInfo {
        TransactionEvent(TransactionEnvelopeInfo transactionEnvelopeInfo) {
            super(transactionEnvelopeInfo.getTransactionDeserializer());
        }

        TransactionEvent(EventsPackage.FilteredTransaction filteredTransaction) {
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
         * The peer that received this event.
         *
         * @return return peer producing the event.
         */
        public Peer getPeer() {
            return BlockEvent.this.getPeer();
        }
    }

    List<TransactionEvent> getTransactionEventsList() {
        ArrayList<TransactionEvent> ret = new ArrayList<>(getTransactionCount());
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
        int returned = 0;

        TransactionEventIterator() {
            max = getTransactionCount();
        }

        @Override
        public boolean hasNext() {
            return returned < max;
        }

        @Override
        public TransactionEvent next() {
            TransactionEvent ret = null;
            // Filter for only transactions but today it's not really needed.
            //  Blocks with transactions only has transactions or a single pdate.
            try {
                do {
                    ret = getTransactionEvent(ci++);
                } while (ret == null);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
            ++returned;
            return ret;
        }
    }

    class TransactionEventIterable implements Iterable<TransactionEvent> {
        @Override
        public Iterator<TransactionEvent> iterator() {
            return new TransactionEventIterator();
        }
    }

} // BlockEvent
