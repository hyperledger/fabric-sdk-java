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
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.TransactionPackage;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

class ChaincodeEndorsedActionDeserializer {
    private final ByteString byteString;
    private WeakReference<TransactionPackage.ChaincodeEndorsedAction> chaincodeEndorsedAction;
    private WeakReference<ProposalResponsePayloadDeserializer> proposalResponsePayload;

    ChaincodeEndorsedActionDeserializer(TransactionPackage.ChaincodeEndorsedAction action) {
        byteString = action.toByteString();
        chaincodeEndorsedAction = new WeakReference<>(action);

    }

    TransactionPackage.ChaincodeEndorsedAction getChaincodeEndorsedAction() {
        TransactionPackage.ChaincodeEndorsedAction ret = chaincodeEndorsedAction != null ? chaincodeEndorsedAction.get() : null;

        if (null == ret) {
            try {
                ret = TransactionPackage.ChaincodeEndorsedAction.parseFrom(byteString);
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

    List<ProposalResponsePackage.Endorsement> getEndorsements() {
        return getChaincodeEndorsedAction().getEndorsementsList();
    }

    byte[] getEndorsementSignature(int index) {
        return getChaincodeEndorsedAction().getEndorsements(index).getSignature().toByteArray();
    }

    ProposalResponsePayloadDeserializer getProposalResponsePayload() {
        ProposalResponsePayloadDeserializer ret = proposalResponsePayload != null ? proposalResponsePayload.get() : null;

        if (null == ret) {
            ret = new ProposalResponsePayloadDeserializer(getChaincodeEndorsedAction().getProposalResponsePayload());
            proposalResponsePayload = new WeakReference<>(ret);
        }

        return ret;
    }
}
