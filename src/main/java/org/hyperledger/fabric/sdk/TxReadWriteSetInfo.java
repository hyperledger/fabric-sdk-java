/*
 *
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.util.Iterator;

import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.ledger.rwset.Rwset.NsReadWriteSet;
import org.hyperledger.fabric.protos.ledger.rwset.Rwset.TxReadWriteSet;
import org.hyperledger.fabric.protos.ledger.rwset.kvrwset.KvRwset;

public class TxReadWriteSetInfo {
    private final TxReadWriteSet txReadWriteSet;

    public TxReadWriteSetInfo(TxReadWriteSet txReadWriteSet) {
        this.txReadWriteSet = txReadWriteSet;
    }

    public int getNsRwsetCount() {

        return txReadWriteSet.getNsRwsetCount();

    }

    public NsRwsetInfo getNsRwsetInfo(int index) {

        return new NsRwsetInfo(txReadWriteSet.getNsRwset(index));

    }

    public Iterable<NsRwsetInfo> getNsRwsetInfos() {

        return new NsRwsetInfoIterable();

    }

    public static class NsRwsetInfo {
        private final NsReadWriteSet nsReadWriteSet;

        NsRwsetInfo(NsReadWriteSet nsReadWriteSet) {

            this.nsReadWriteSet = nsReadWriteSet;
        }

        public KvRwset.KVRWSet getRwset() throws InvalidProtocolBufferException {
            return KvRwset.KVRWSet.parseFrom(nsReadWriteSet.getRwset());
        }

        public String getNamespace() {
            return nsReadWriteSet.getNamespace();
        }

    }

    public class NsRwsetInfoIterator implements Iterator<NsRwsetInfo> {
        int ci = 0;
        final int max;

        NsRwsetInfoIterator() {
            max = getNsRwsetCount();

        }

        @Override
        public boolean hasNext() {
            return ci < max;

        }

        @Override
        public NsRwsetInfo next() {

            return getNsRwsetInfo(ci++);

        }
    }

    public class NsRwsetInfoIterable implements Iterable<NsRwsetInfo> {

        @Override
        public Iterator<NsRwsetInfo> iterator() {
            return new NsRwsetInfoIterator();
        }
    }

}
