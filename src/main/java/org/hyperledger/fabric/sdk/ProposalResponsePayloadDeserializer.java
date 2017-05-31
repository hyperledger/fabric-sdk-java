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

import static org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponsePayload;

class ProposalResponsePayloadDeserializer {
    private final ByteString byteString;
    private WeakReference<ProposalResponsePayload> proposalResponsePayload;
    private WeakReference<ChaincodeActionDeserializer> chaincodeAction;

    ProposalResponsePayloadDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    ProposalResponsePayload getProposalResponsePayload() {
        ProposalResponsePayload ret = null;

        if (proposalResponsePayload != null) {
            ret = proposalResponsePayload.get();

        }
        if (ret == null) {

            try {
                ret = ProposalResponsePayload.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            proposalResponsePayload = new WeakReference<>(ret);

        }

        return ret;

    }

    ChaincodeActionDeserializer getExtension() {

        ChaincodeActionDeserializer ret = null;

        if (chaincodeAction != null) {
            ret = chaincodeAction.get();

        }
        if (ret == null) {

            ret = new ChaincodeActionDeserializer(getProposalResponsePayload().getExtension());

            chaincodeAction = new WeakReference<>(ret);

        }

        return ret;

    }

}
