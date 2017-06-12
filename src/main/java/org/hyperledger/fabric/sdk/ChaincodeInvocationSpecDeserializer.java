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
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInvocationSpec;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

class ChaincodeInvocationSpecDeserializer {
    private final ByteString byteString;
    private WeakReference<ChaincodeInvocationSpec> invocationSpec;
    private WeakReference<ChaincodeInputDeserializer> chaincodeInputDeserializer;

    ChaincodeInvocationSpecDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    ChaincodeInvocationSpec getChaincodeInvocationSpec() {
        ChaincodeInvocationSpec ret = null;

        if (invocationSpec != null) {
            ret = invocationSpec.get();

        }
        if (ret == null) {

            try {
                ret = ChaincodeInvocationSpec.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            invocationSpec = new WeakReference<>(ret);

        }

        return ret;

    }

    ChaincodeInputDeserializer getChaincodeInput() {
        ChaincodeInputDeserializer ret = null;

        if (chaincodeInputDeserializer != null) {
            ret = chaincodeInputDeserializer.get();

        }
        if (ret == null) {

            ret = new ChaincodeInputDeserializer(getChaincodeInvocationSpec().getChaincodeSpec().getInput());

            chaincodeInputDeserializer = new WeakReference<>(ret);

        }

        return ret;

    }
}
