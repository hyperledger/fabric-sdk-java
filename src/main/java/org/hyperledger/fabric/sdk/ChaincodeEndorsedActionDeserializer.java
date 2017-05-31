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
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

import static org.hyperledger.fabric.protos.peer.FabricTransaction.ChaincodeEndorsedAction;

class ChaincodeEndorsedActionDeserializer {
    private final ByteString byteString;
    private WeakReference<ChaincodeEndorsedAction> chaincodeEndorsedAction;
    private WeakReference<ProposalResponsePayloadDeserializer> proposalResponsePayload;

    ChaincodeEndorsedActionDeserializer(ChaincodeEndorsedAction action) {
        byteString = action.toByteString();
        chaincodeEndorsedAction = new WeakReference<>(action);

    }

    ChaincodeEndorsedAction getChaincodeEndorsedAction() {
        ChaincodeEndorsedAction ret = null;

        if (chaincodeEndorsedAction != null) {
            ret = chaincodeEndorsedAction.get();

        }
        if (ret == null) {

            try {
                ret = ChaincodeEndorsedAction.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

            chaincodeEndorsedAction = new WeakReference<>(ret);
        }

        return ret;

    }

    int getEndorsementsCount() {

        return getChaincodeEndorsedAction().getEndorsementsCount();

    }

    List<FabricProposalResponse.Endorsement> getEndorsements() {

        return getChaincodeEndorsedAction().getEndorsementsList();
    }

    byte[] getEndorsementSignature(int index) {

        return getChaincodeEndorsedAction().getEndorsements(index).getSignature().toByteArray();
    }

    ProposalResponsePayloadDeserializer getProposalResponsePayload() {

        ProposalResponsePayloadDeserializer ret = null;

        if (proposalResponsePayload != null) {
            ret = proposalResponsePayload.get();

        }
        if (ret == null) {

            ret = new ProposalResponsePayloadDeserializer(getChaincodeEndorsedAction().getProposalResponsePayload());
            proposalResponsePayload = new WeakReference<>(ret);

        }

        return ret;

    }

}
