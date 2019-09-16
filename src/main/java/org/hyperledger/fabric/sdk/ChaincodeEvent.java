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
import org.hyperledger.fabric.protos.peer.ChaincodeEventPackage;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

/**
 * Encapsulates a Chaincode event.
 */
public class ChaincodeEvent {
    private final ByteString byteString;
    private WeakReference<ChaincodeEventPackage.ChaincodeEvent> chaincodeEvent;

    ChaincodeEvent(ByteString byteString) {
        this.byteString = byteString;
    }

    ChaincodeEventPackage.ChaincodeEvent getChaincodeEvent() {
        ChaincodeEventPackage.ChaincodeEvent ret = chaincodeEvent != null ? chaincodeEvent.get() : null;

        if (null == ret) {
            try {
                ret = ChaincodeEventPackage.ChaincodeEvent.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
            chaincodeEvent = new WeakReference<>(ret);
        }

        return ret;
    }

    /**
     * Get Chaincode event's name;
     *
     * @return Return name;
     */
    public String getEventName() {
        return getChaincodeEvent().getEventName();
    }

    /**
     * Get Chaincode identifier.
     *
     * @return The identifier
     */
    public String getChaincodeId() {
        return getChaincodeEvent().getChaincodeId();
    }

    /**
     * Get transaction id associated with this event.
     *
     * @return The transactions id.
     */
    public String getTxId() {
        return getChaincodeEvent().getTxId();
    }

    /**
     * Binary data associated with this event.
     *
     * @return binary data set by the chaincode for this event. This may return null.
     */
    public byte[] getPayload() {
        ByteString ret = getChaincodeEvent().getPayload();
        if (null == ret) {
            return null;
        }

        return ret.toByteArray();
    }
}
