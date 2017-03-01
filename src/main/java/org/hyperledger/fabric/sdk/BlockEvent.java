/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.common.Common.BlockData;
import org.hyperledger.fabric.protos.common.Common.BlockMetadata;
import org.hyperledger.fabric.protos.common.Common.BlockMetadataIndex;
import org.hyperledger.fabric.protos.common.Common.ChannelHeader;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.peer.FabricTransaction.Transaction;
import org.hyperledger.fabric.protos.peer.FabricTransaction.TxValidationCode;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

/**
 * A wrapper for the Block returned in an Event
 *
 * @see Block
 */
public class BlockEvent {
    private static final Log logger = LogFactory.getLog(BlockEvent.class);

    private final Block block ;
    private BlockData blockData;
    private BlockMetadata blockMetadata;

    private String channelID ;  // TODO a block contains payloads from a single channel ??????
    private final ArrayList<TransactionEvent> txList = new ArrayList<>() ;
    private byte[] txResults;   // mapping of Block.Metadata[TRANSACTIONS_FILTER] which is an array of Golang uint8
    private int transactionsInBlock;


    /**
     * creates a BlockEvent object by parsing the input Block and retrieving its constituent Transactions
     * @param block a Hyperledger Fabric Block message
     *
     * @throws InvalidProtocolBufferException
     * @see Block
     */
    BlockEvent(Block block) throws InvalidProtocolBufferException {
        this.block = block ;
        blockMetadata = this.block.getMetadata();
        getChannelIDFromBlock();
        populateResultsMap();
        processTransactions();
    }

    /**
     * getChannelIDFromBlock retrieves the channel ID from the Block by parsing
     * the header of the first transaction in the block
     *
     * @throws InvalidProtocolBufferException
     */
    private void getChannelIDFromBlock() throws InvalidProtocolBufferException {
        blockData = block.getData();
        ByteString data = blockData.getData(0);
        Envelope envelope = Envelope.parseFrom(data);
        Payload payload = Payload.parseFrom(envelope.getPayload());
        Header plh = payload.getHeader();
        ChannelHeader channelHeader = ChannelHeader.parseFrom(plh.getChannelHeader());
        channelID = channelHeader.getChannelId();
    }

    /**
     * populateResultsMap parses the Block and retrieves the bit string that lists the transaction results
     */
    private void populateResultsMap() {
        ByteString txResultsBytes = blockMetadata.getMetadata(BlockMetadataIndex.TRANSACTIONS_FILTER_VALUE);
        txResults = txResultsBytes.toByteArray();
    }

    /**
     * processTransactions retrieves the Transactions from the Block and wrappers each into
     * its own TransactionEvent
     *
     * @throws InvalidProtocolBufferException
     * @see Block
     * @see Transaction
     * @see TransactionEvent
     */
    private void processTransactions() throws InvalidProtocolBufferException {
        int blockIndex = -1;
        transactionsInBlock = blockData.getDataCount();
        for (ByteString db : blockData.getDataList()) {
            blockIndex++;
            Envelope env = Envelope.parseFrom(db);
            txList.add(new TransactionEvent(blockIndex, env));
        }
    }

    /**
     *
     * @return the Block associated with this BlockEvent
     */
    public Block getBlock() {
        return block;
    }

    /**
     * @return the channel ID from the Block
     */
    public String getChannelID() {
        return channelID;
    }

    /**
     * @return a List of the TransactionEvents contained in this Block
     */
    public List<BlockEvent.TransactionEvent> getTransactionEvents() {
        return txList;
    }

    /**
     * A wrapper of a Transaction contained in the Block of this event.
     *
     */
    public class TransactionEvent {
        private final int txIndex;
        private final Block enclosingBlock;
        private final Envelope txEnvelope;
        private final String txID;

        /**
         * constructs a TransactionEvent by parsing the given Envelope
         *
         * @param index the position of this Transaction in the Block
         * @param txEnvelope the Envelope that wraps the Transaction payload in the Block
         * @throws InvalidProtocolBufferException
         */
        TransactionEvent(int index, Envelope txEnvelope) throws InvalidProtocolBufferException {
            this.txIndex = index;
            this.enclosingBlock = block;
            this.txEnvelope = txEnvelope;
            Payload payload = Payload.parseFrom(txEnvelope.getPayload());
            Header plh = payload.getHeader();
            ChannelHeader channelHeader = ChannelHeader.parseFrom(plh.getChannelHeader());
            txID = channelHeader.getTxId();
        }

        /**
         * @return the transaction ID
         */
        public String getTransactionID(){
            return this.txID;
        }

        /**
         * @return the Envelope wrapper of this Transaction payload
         */
        public Envelope getEnvelope() {
            return this.txEnvelope;
        }

        /**
         * @return the Block that contains this Transaction
         */
        public Block getBlock() {
            return this.enclosingBlock;
        }

        /**
         * @return the position of this Transaction in the Block
         */
        public int getIndexInBlock() {
            return this.txIndex;
        }

        /**
         * @return whether this Transaction is marked as TxValidationCode.VALID
         */
        public boolean isValid() {
            if (txIndex >= transactionsInBlock) {
                return false;
            }
            byte txResult = txResults[this.txIndex];
            logger.debug("TxID " + this.txID + " txResult = " + txResult);

            return txResult == TxValidationCode.VALID_VALUE ;
        }

        /**
         * @return the validation code of this Transaction (enumeration TxValidationCode in Transaction.proto)
         */
        public byte validationCode() {
            if (txIndex >= transactionsInBlock) {
                return (byte) TxValidationCode.INVALID_OTHER_REASON_VALUE ;
            }
            return txResults[this.txIndex];
        }
    } // TransactionEvent

} // BlockEvent
