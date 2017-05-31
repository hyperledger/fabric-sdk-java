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
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

import static org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeProposalPayload;

class ChaincodeProposalPayloadDeserializer {
    private final ByteString byteString;
    private WeakReference<ChaincodeProposalPayload> chaincodeProposalPayload;
    private WeakReference<ChaincodeInvocationSpecDeserializer> invocationSpecDeserializer;

    ChaincodeProposalPayloadDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    ChaincodeProposalPayload getChaincodeProposalPayload() {
        ChaincodeProposalPayload ret = null;

        if (chaincodeProposalPayload != null) {
            ret = chaincodeProposalPayload.get();

        }
        if (ret == null) {

            try {
                ret = ChaincodeProposalPayload.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeProposalPayload = new WeakReference<>(ret);

        }

        return ret;

    }

    ChaincodeInvocationSpecDeserializer getChaincodeInvocationSpec() {
        ChaincodeInvocationSpecDeserializer ret = null;

        if (invocationSpecDeserializer != null) {
            ret = invocationSpecDeserializer.get();

        }
        if (ret == null) {

            ret = new ChaincodeInvocationSpecDeserializer(getChaincodeProposalPayload().getInput());

            invocationSpecDeserializer = new WeakReference<>(ret);

        }

        return ret;

    }

}
