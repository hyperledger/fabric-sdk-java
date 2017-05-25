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
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

class PayloadDeserializer {
    private final ByteString byteString;
    private WeakReference<Payload> payload;

    PayloadDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    Payload getPayload() {
        Payload ret = null;

        if (payload != null) {
            ret = payload.get();

        }
        if (ret == null) {

            try {
                ret = Payload.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
            payload = new WeakReference<>(ret);

        }

        return ret;
    }

    HeaderDeserializer getHeader() {

        return new HeaderDeserializer(getPayload().getHeader());

    }

//    void transactionEvent(int index) {
//        int txIndex = index;
//        //    = bgetData(txIndex);
//        // this.enclosingBlock = block;
////            this.txEnvelope = txEnvelope;
//        Payload payload = getPayload();
////            Header plh = payload.getHeader();
//        //  ChannelHeader channelHeader = ChannelHeader.parseFrom(plh.getChannelHeader());
//        String txID = getHeader().getChannelHeader().getTxId();
//
//// NEW....................
//
//        //   ByteString bdb = payload.getData();
////            String ho = Hex.encodeHexString(bdb.toByteArray());
////            System.out.println(ho);
//
////        TransactionDeserializer ts = new TransactionDeserializer(getPayload().getData());
////
////        for (TransactionActionDeserializer transactionActionDeserialize : ts.getTransactionActions()) {
////
////            System.out.println(transactionActionDeserialize + "");
////
////        }
////
////        for (TransactionActionDeserializer x : ts.getTransactionActions()) {
////
////            System.out.println(x + "");
////
////        }
////
////        Transaction tx = Transaction.parseFrom(payload.getData());
////        List<FabricTransaction.TransactionAction> al = tx.getActionsList();
////        for (TransactionAction ta : al) {
////
////            //         FabricTransaction.ChaincodeActionPayload tap = ta.getHeader();
////
////            ChaincodeActionPayload tap = ChaincodeActionPayload.parseFrom(ta.getPayload());//<<<
////            FabricProposal.ChaincodeProposalPayload ccpp = FabricProposal.ChaincodeProposalPayload.parseFrom(tap.getChaincodeProposalPayload());
////            Chaincode.ChaincodeInput cinput = Chaincode.ChaincodeInput.parseFrom(ccpp.getInput());
////
////            for (ByteString x : cinput.getArgsList()) {
////
////                System.out.println("x " + x);
////
////            }
////
////            ChaincodeEndorsedAction cae = tap.getAction();
////
////            // FabricProposalResponse.ProposalResponsePayload cpr = FabricProposalResponse.ProposalResponsePayload.parseFrom(cae.getProposalResponsePayload());
////            FabricProposalResponse.ProposalResponsePayload cpr = FabricProposalResponse.ProposalResponsePayload.parseFrom(cae.getProposalResponsePayload());
////            FabricProposal.ChaincodeAction ca = FabricProposal.ChaincodeAction.parseFrom(cpr.getExtension());
////
////            FabricProposalResponse.Response rsp = ca.getResponse();
////            System.out.println(String.format(" resp message= %s,  status=%d", new String(rsp.getPayload().toByteArray()), rsp.getStatus()));
////
////            ByteString rwset = ca.getResults();
////
////            ///<<<<<<<<<<<<<<
////
////            Rwset.TxReadWriteSet txReadWriteSet = Rwset.TxReadWriteSet.parseFrom(ca.getResults());
////
////            FabricProposalResponse.Response a = ca.getResponse();
////
////            //cae.getProposalResponsePayload();r
////            System.out.println("rwset:'" + txReadWriteSet);
////
////        }
//
//            /*
//            ChaincodeEndorsedAction.getAction
//            ProposalResponsePayload
//               ProposalResponsePayload.getExtension
//               ChaincodeAction.getResults()
//             */
//
////
////            FabricProposal.Proposal sp = FabricProposal.Proposal.parseFrom(bdb);
////            Header ph = Header.parseFrom(sp.getHeader());
////
////            ChannelHeader pch = ChannelHeader.parseFrom(ph.getChannelHeader());
//
//    }
//
//    /*
//    EnvelopeDeserializer
//    PayloadDeserializer
//     */
//
////    private void getChannelIDFromBlock() throws InvalidProtocolBufferException {
////        blockData = block.getData();
////        ByteString data = blockData.getData(0);
////        Common.Envelope envelope = Envelope.parseFrom(data);
////        Payload payload = Payload.parseFrom(envelope.getPayload());
////        Common.Header plh = payload.getHeader();
////        ChannelHeader channelHeader = ChannelHeader.parseFrom(plh.getChannelHeader());
////        channelID = channelHeader.getChannelId();
////    }

}
