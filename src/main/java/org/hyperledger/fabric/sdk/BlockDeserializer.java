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
import java.util.Map;
import java.util.WeakHashMap;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.common.Common.BlockData;

class BlockDeserializer {
    private final Block block;
    private final Map<Integer, WeakReference<EnvelopeDeserializer>> envelopes = Collections.synchronizedMap(new WeakHashMap<Integer, WeakReference<EnvelopeDeserializer>>());

    public Block getBlock() {
        return block;
    }

    BlockDeserializer(Block block) {
        this.block = block;
    }

    ByteString getPreviousHash() {
        block.getHeader().getDataHash();

        return block.getHeader().getPreviousHash();
    }

    ByteString getDataHash() {
        return block.getHeader().getDataHash();

    }

    public long getNumber() {
        return block.getHeader().getNumber();
    }

    BlockData getData() {

        return block.getData();

    }

    EnvelopeDeserializer getData(int index) throws InvalidProtocolBufferException {
        if (index >= getData().getDataCount()) {
            return null;
        }
        WeakReference<EnvelopeDeserializer> envelopeWeakReference = envelopes.get(index);
        if (null != envelopeWeakReference) {
            EnvelopeDeserializer ret = envelopeWeakReference.get();
            if (null != ret) {
                return ret;
            }
        }

        EnvelopeDeserializer envelopeDeserializer = EnvelopeDeserializer.newInstance(getData().getData(index), getTransActionsMetaData()[index]);

        envelopes.put(index, new WeakReference<>(envelopeDeserializer));

        return envelopeDeserializer;

    }

    byte[] getTransActionsMetaData() {

        return block.getMetadata().getMetadata(Common.BlockMetadataIndex.TRANSACTIONS_FILTER_VALUE).toByteArray();

    }

}
