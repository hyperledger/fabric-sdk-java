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
import org.hyperledger.fabric.protos.peer.TransactionPackage;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

class ChaincodeActionPayloadDeserializer {
    private final ByteString byteString;
    private WeakReference<TransactionPackage.ChaincodeActionPayload> chaincodeActionPayload;
    private WeakReference<ChaincodeEndorsedActionDeserializer> chaincodeEndorsedActionDeserializer;
    private WeakReference<ChaincodeProposalPayloadDeserializer> chaincodeProposalPayloadDeserializer;

    ChaincodeActionPayloadDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    TransactionPackage.ChaincodeActionPayload getChaincodeActionPayload() {
        TransactionPackage.ChaincodeActionPayload ret = chaincodeActionPayload != null ? chaincodeActionPayload.get() : null;

        if (null == ret) {
            try {
                ret = TransactionPackage.ChaincodeActionPayload.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
            chaincodeActionPayload = new WeakReference<>(ret);
        }

        return ret;
    }

    ChaincodeEndorsedActionDeserializer getAction() {
        ChaincodeEndorsedActionDeserializer ret = chaincodeEndorsedActionDeserializer != null ? chaincodeEndorsedActionDeserializer.get() : null;

        if (null == ret) {
            ret = new ChaincodeEndorsedActionDeserializer(getChaincodeActionPayload().getAction());
            chaincodeEndorsedActionDeserializer = new WeakReference<>(ret);
        }

        return ret;
    }

    ChaincodeProposalPayloadDeserializer getChaincodeProposalPayload() {
        ChaincodeProposalPayloadDeserializer ret = chaincodeProposalPayloadDeserializer != null ? chaincodeProposalPayloadDeserializer.get() : null;

        if (null == ret) {
            ret = new ChaincodeProposalPayloadDeserializer(getChaincodeActionPayload().getChaincodeProposalPayload());
            chaincodeProposalPayloadDeserializer = new WeakReference<>(ret);
        }

        return ret;
    }
}
