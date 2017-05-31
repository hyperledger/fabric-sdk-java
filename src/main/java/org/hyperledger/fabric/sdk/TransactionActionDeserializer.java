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

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.peer.FabricTransaction.TransactionAction;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

class TransactionActionDeserializer {
    private final ByteString byteString;
    private WeakReference<TransactionAction> transactionAction;
    private WeakReference<ChaincodeActionPayloadDeserializer> chaincodeActionPayloadDeserializer;

    TransactionActionDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    TransactionActionDeserializer(TransactionAction transactionAction) {
        byteString = transactionAction.toByteString();
        this.transactionAction = new WeakReference<TransactionAction>(transactionAction);
    }

    TransactionAction getTransactionAction() {
        TransactionAction ret = null;

        if (transactionAction != null) {
            ret = transactionAction.get();

        }
        if (ret == null) {

            try {
                ret = TransactionAction.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            transactionAction = new WeakReference<TransactionAction>(ret);
        }

        return ret;

    }

    ChaincodeActionPayloadDeserializer getPayload() {

        ChaincodeActionPayloadDeserializer ret = null;

        if (chaincodeActionPayloadDeserializer != null) {
            ret = chaincodeActionPayloadDeserializer.get();

        }
        if (ret == null) {

            ret = new ChaincodeActionPayloadDeserializer(getTransactionAction().getPayload());

            chaincodeActionPayloadDeserializer = new WeakReference<ChaincodeActionPayloadDeserializer>(ret);

        }

        return ret;

    }
}
