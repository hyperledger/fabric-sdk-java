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

import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

import static org.hyperledger.fabric.protos.peer.FabricTransaction.Transaction;

class TransactionDeserializer {
    private final ByteString byteString;
    private WeakReference<Transaction> transaction;
    private final Map<Integer, WeakReference<TransactionActionDeserializer>> transactionActions =
            Collections.synchronizedMap(new WeakHashMap<Integer, WeakReference<TransactionActionDeserializer>>());

    TransactionDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    Transaction getTransaction() {
        Transaction ret = null;

        if (transaction != null) {
            ret = transaction.get();

        }
        if (ret == null) {

            try {
                ret = Transaction.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            transaction = new WeakReference<>(ret);

        }

        return ret;

    }

    int getActionsCount() {

        return getTransaction().getActionsCount();
    }

    TransactionActionDeserializer getTransactionAction(int index) {

        final Transaction transaction = getTransaction();

        if (index >= getActionsCount()) {
            return null;
        }

        WeakReference<TransactionActionDeserializer> envelopeWeakReference = transactionActions.get(index);
        if (null != envelopeWeakReference) {
            TransactionActionDeserializer ret = envelopeWeakReference.get();
            if (null != ret) {
                return ret;
            }
        }

        TransactionActionDeserializer transactionActionDeserialize = new TransactionActionDeserializer(transaction.getActions(index));

        transactionActions.put(index, new WeakReference<>(transactionActionDeserialize));

        return transactionActionDeserialize;

    }

    Iterable<TransactionActionDeserializer> getTransactionActions() {

        return new TransactionActionIterable();

    }

    class TransactionActionIterator implements Iterator<TransactionActionDeserializer> {
        int ci = 0;
        final int max;

        TransactionActionIterator() {
            max = getActionsCount();

        }

        @Override
        public boolean hasNext() {
            return ci < max;
        }

        @Override
        public TransactionActionDeserializer next() {
            return getTransactionAction(ci++);
        }
    }

    class TransactionActionIterable implements Iterable<TransactionActionDeserializer> {
        @Override
        public Iterator<TransactionActionDeserializer> iterator() {
            return new TransactionActionIterator();
        }
    }

}
