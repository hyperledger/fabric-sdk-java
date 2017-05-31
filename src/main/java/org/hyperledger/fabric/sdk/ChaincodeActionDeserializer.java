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
import org.hyperledger.fabric.protos.ledger.rwset.Rwset.TxReadWriteSet;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

import static org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeAction;

class ChaincodeActionDeserializer {
    private final ByteString byteString;
    private WeakReference<ChaincodeAction> chaincodeAction;

    ChaincodeActionDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    ChaincodeAction getChaincodeAction() {
        ChaincodeAction ret = null;

        if (chaincodeAction != null) {
            ret = chaincodeAction.get();

        }
        if (ret == null) {

            try {
                ret = ChaincodeAction.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeAction = new WeakReference<>(ret);

        }

        //TODO events ?

        //     ret.getResponse();

        return ret;

    }

    TxReadWriteSet getResults() {

        try {
            return TxReadWriteSet.parseFrom(getChaincodeAction().getResults());
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidProtocolBufferRuntimeException(e);
        }

    }

    String getResponseMessage() {
        return getChaincodeAction().getResponse().getMessage();

    }

    byte[] getResponseMessageBytes() {
        return getChaincodeAction().getResponse().getMessageBytes().toByteArray();

    }

    int getResponseStatus() {
        return getChaincodeAction().getResponse().getStatus();

    }

    ByteString getResponsePayload() {
        return getChaincodeAction().getResponse().getPayload();

    }

}
