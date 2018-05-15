/*
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
 */
package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.ledger.rwset.Rwset.TxReadWriteSet;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInput;
import org.hyperledger.fabric.protos.peer.FabricTransaction;
import org.hyperledger.fabric.protos.peer.PeerEvents;
import org.hyperledger.fabric.protos.peer.PeerEvents.FilteredTransaction;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.hyperledger.fabric.sdk.transaction.ProtoUtils;

import static java.lang.String.format;
import static org.hyperledger.fabric.protos.peer.FabricProposalResponse.Endorsement;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;

/**
 * BlockInfo contains the data from a {@link Block}
 */
public class BlockInfo {
    private final BlockDeserializer block; //can be only one or the other.
    private final PeerEvents.FilteredBlock filteredBlock;

    BlockInfo(Block block) {

        filteredBlock = null;
        this.block = new BlockDeserializer(block);
    }

    BlockInfo(PeerEvents.DeliverResponse resp) {

        final PeerEvents.DeliverResponse.TypeCase type = resp.getTypeCase();

        if (type == PeerEvents.DeliverResponse.TypeCase.BLOCK) {
            final Block respBlock = resp.getBlock();
            filteredBlock = null;
            if (respBlock == null) {
                throw new AssertionError("DeliverResponse type block but block is null");
            }
            this.block = new BlockDeserializer(respBlock);
        } else if (type == PeerEvents.DeliverResponse.TypeCase.FILTERED_BLOCK) {
            filteredBlock = resp.getFilteredBlock();
            block = null;
            if (filteredBlock == null) {
                throw new AssertionError("DeliverResponse type filter block but filter block is null");
            }

        } else {
            throw new AssertionError(format("DeliverResponse type has unexpected type: %s, %d", type.name(), type.getNumber()));
        }

    }

    public boolean isFiltered() {
        if (filteredBlock == null && block == null) {
            throw new AssertionError("Both block and filter is null.");
        }
        if (filteredBlock != null && block != null) {
            throw new AssertionError("Both block and filter are set.");
        }
        return filteredBlock != null;
    }

    public String getChannelId() throws InvalidProtocolBufferException {

        return isFiltered() ? filteredBlock.getChannelId() : getEnvelopeInfo(0).getChannelId();
    }

    /**
     * @return the raw {@link Block}
     */
    public Block getBlock() {
        return isFiltered() ? null : block.getBlock();
    }

    /**
     * @return the raw {@link org.hyperledger.fabric.protos.peer.PeerEvents.FilteredBlock}
     */
    public PeerEvents.FilteredBlock getFilteredBlock() {
        return !isFiltered() ? null : filteredBlock;
    }

    /**
     * @return the {@link Block} previousHash value and null if filtered block.
     */
    public byte[] getPreviousHash() {
        return isFiltered() ? null : block.getPreviousHash().toByteArray();
    }

    /**
     * @return the {@link Block} data hash value and null if filtered block.
     */
    public byte[] getDataHash() {

        return isFiltered() ? null : block.getDataHash().toByteArray();
    }

    /**
     * @return the {@link Block} transaction metadata value return null if filtered block.
     */
    public byte[] getTransActionsMetaData() {

        return isFiltered() ? null : block.getTransActionsMetaData();
    }

    /**
     * @return the {@link Block} index number
     */
    public long getBlockNumber() {
        return isFiltered() ? filteredBlock.getNumber() : block.getNumber();
    }

    /**
     * getEnvelopeCount
     *
     * @return the number of transactions in this block.
     */

    public int getEnvelopeCount() {
        return isFiltered() ? filteredBlock.getFilteredTransactionsCount() : block.getData().getDataCount();
    }

    private int transactionCount = -1;

    /**
     * Number of endorser transaction found in the block.
     *
     * @return Number of endorser transaction found in the block.
     */

    public int getTransactionCount() {
        if (isFiltered()) {

            int ltransactionCount = transactionCount;
            if (ltransactionCount < 0) {
                ltransactionCount = 0;

                for (int i = filteredBlock.getFilteredTransactionsCount() - 1; i >= 0; --i) {
                    FilteredTransaction filteredTransactions = filteredBlock.getFilteredTransactions(i);
                    Common.HeaderType type = filteredTransactions.getType();
                    if (type == Common.HeaderType.ENDORSER_TRANSACTION) {
                        ++ltransactionCount;
                    }
                }
                transactionCount = ltransactionCount;
            }

            return transactionCount;
        }
        int ltransactionCount = transactionCount;
        if (ltransactionCount < 0) {

            ltransactionCount = 0;
            for (int i = getEnvelopeCount() - 1; i >= 0; --i) {
                try {
                    EnvelopeInfo envelopeInfo = getEnvelopeInfo(i);
                    if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                        ++ltransactionCount;
                    }
                } catch (InvalidProtocolBufferException e) {
                    throw new InvalidProtocolBufferRuntimeException(e);
                }
            }
            transactionCount = ltransactionCount;
        }
        return transactionCount;
    }

    /**
     * Wrappers Envelope
     */

    public class EnvelopeInfo {
        private final EnvelopeDeserializer envelopeDeserializer;
        private final HeaderDeserializer headerDeserializer;
        protected final FilteredTransaction filteredTx;

        /**
         * This block is filtered
         *
         * @return true if it's filtered.
         */
        boolean isFiltered() {
            return filteredTx != null;

        }

        //private final EnvelopeDeserializer envelopeDeserializer;

        EnvelopeInfo(EnvelopeDeserializer envelopeDeserializer) {
            this.envelopeDeserializer = envelopeDeserializer;
            headerDeserializer = envelopeDeserializer.getPayload().getHeader();
            filteredTx = null;
        }

        EnvelopeInfo(FilteredTransaction filteredTx) {
            this.filteredTx = filteredTx;
            envelopeDeserializer = null;
            headerDeserializer = null;

        }

        /**
         * Get channel id
         *
         * @return The channel id also referred to as channel name.
         */
        public String getChannelId() {

            return BlockInfo.this.isFiltered() ? filteredBlock.getChannelId() : headerDeserializer.getChannelHeader().getChannelId();
        }

        public class IdentitiesInfo {
            final String mspid;
            final String id;

            /**
             * The identification of the identity usually the certificate.
             *
             * @return The certificate of the user in PEM format.
             */
            public String getId() {
                return id;
            }

            /**
             * The MSPId of the user.
             *
             * @return The MSPid of the user.
             */
            public String getMspid() {
                return mspid;
            }

            IdentitiesInfo(Identities.SerializedIdentity identity) {
                mspid = identity.getMspid();
                id = identity.getIdBytes().toStringUtf8();

            }

        }

        /**
         * This is the creator or submitter of the transaction.
         * Returns null for a filtered block.
         *
         * @return {@link IdentitiesInfo}
         */
        public IdentitiesInfo getCreator() {
            return isFiltered() ? null : new IdentitiesInfo(headerDeserializer.getCreator());

        }

        /**
         * The nonce of the transaction.
         *
         * @return return null for filtered block.
         */
        public byte[] getNonce() {
            return isFiltered() ? null : headerDeserializer.getNonce();

        }

        /**
         * The transaction ID
         *
         * @return the transaction id.
         */
        public String getTransactionID() {

            return BlockInfo.this.isFiltered() ? filteredTx.getTxid() : headerDeserializer.getChannelHeader().getTxId();
        }

        /**
         * @return epoch and -1 if filtered block.
         * @deprecated
         */

        public long getEpoch() {

            return BlockInfo.this.isFiltered() ? -1 : headerDeserializer.getChannelHeader().getEpoch();
        }

        /**
         * Timestamp
         *
         * @return timestamp and null if filtered block.
         */

        public Date getTimestamp() {

            return BlockInfo.this.isFiltered() ? null :
                    ProtoUtils.getDateFromTimestamp(headerDeserializer.getChannelHeader().getTimestamp());
        }

        /**
         * @return whether this Transaction is marked as TxValidationCode.VALID
         */
        public boolean isValid() {
            return BlockInfo.this.isFiltered() ? filteredTx.getTxValidationCode().getNumber() == FabricTransaction.TxValidationCode.VALID_VALUE
                    : envelopeDeserializer.isValid();
        }

        /**
         * @return the validation code of this Transaction (enumeration TxValidationCode in Transaction.proto)
         */
        public byte getValidationCode() {
            if (BlockInfo.this.isFiltered()) {

                return (byte) filteredTx.getTxValidationCode().getNumber();

            }
            return envelopeDeserializer.validationCode();
        }

        public EnvelopeType getType() {

            final int type;

            if (BlockInfo.this.isFiltered()) {

                type = filteredTx.getTypeValue();

            } else {
                type = headerDeserializer.getChannelHeader().getType();

            }

            switch (type) {
                case Common.HeaderType.ENDORSER_TRANSACTION_VALUE:
                    return EnvelopeType.TRANSACTION_ENVELOPE;

                default:
                    return EnvelopeType.ENVELOPE;
            }

        }

    }

    /**
     * Return a specific envelope in the block by it's index.
     *
     * @param envelopeIndex
     * @return EnvelopeInfo that contains information on the envelope.
     * @throws InvalidProtocolBufferException
     */

    public EnvelopeInfo getEnvelopeInfo(int envelopeIndex) throws InvalidProtocolBufferException {

        try {

            EnvelopeInfo ret;

            if (isFiltered()) {

                switch (filteredBlock.getFilteredTransactions(envelopeIndex).getType().getNumber()) {
                    case Common.HeaderType.ENDORSER_TRANSACTION_VALUE:
                        ret = new TransactionEnvelopeInfo(this.filteredBlock.getFilteredTransactions(envelopeIndex));
                        break;
                    default: //just assume base properties.
                        ret = new EnvelopeInfo(this.filteredBlock.getFilteredTransactions(envelopeIndex));
                        break;
                }

            } else {

                EnvelopeDeserializer ed = EnvelopeDeserializer.newInstance(block.getBlock().getData().getData(envelopeIndex), block.getTransActionsMetaData()[envelopeIndex]);

                switch (ed.getType()) {
                    case Common.HeaderType.ENDORSER_TRANSACTION_VALUE:
                        ret = new TransactionEnvelopeInfo((EndorserTransactionEnvDeserializer) ed);
                        break;
                    default: //just assume base properties.
                        ret = new EnvelopeInfo(ed);
                        break;

                }

            }
            return ret;

        } catch (InvalidProtocolBufferRuntimeException e) {
            throw e.getCause();
        }

    }

    /**
     * Return and iterable EnvelopeInfo over each Envelope contained in the Block
     *
     * @return
     */

    public Iterable<EnvelopeInfo> getEnvelopeInfos() {

        return new EnvelopeInfoIterable();
    }

    public class TransactionEnvelopeInfo extends EnvelopeInfo {

        TransactionEnvelopeInfo(FilteredTransaction filteredTx) {
            super(filteredTx);
            this.transactionDeserializer = null;
        }

        /**
         * Signature for the transaction.
         *
         * @return byte array that as the signature.
         */
        public byte[] getSignature() {

            return transactionDeserializer.getSignature();
        }

        TransactionEnvelopeInfo(EndorserTransactionEnvDeserializer transactionDeserializer) {
            super(transactionDeserializer);

            this.transactionDeserializer = transactionDeserializer;
        }

        EndorserTransactionEnvDeserializer getTransactionDeserializer() {
            return transactionDeserializer;
        }

        protected final EndorserTransactionEnvDeserializer transactionDeserializer;

        public int getTransactionActionInfoCount() {
            return BlockInfo.this.isFiltered() ? filteredTx.getTransactionActions().getChaincodeActionsCount() : transactionDeserializer.getPayload().getTransaction().getActionsCount();
        }

        public Iterable<TransactionActionInfo> getTransactionActionInfos() {

            return new TransactionActionIterable();
        }

        public class TransactionActionInfo {

            private final TransactionActionDeserializer transactionAction;
            private final PeerEvents.FilteredChaincodeAction filteredAction;
            List<EndorserInfo> endorserInfos = null;

            private boolean isFiltered() {
                return filteredAction != null;

            }

            TransactionActionInfo(TransactionActionDeserializer transactionAction) {

                this.transactionAction = transactionAction;
                filteredAction = null;
            }

            TransactionActionInfo(PeerEvents.FilteredChaincodeAction filteredAction) {
                this.filteredAction = filteredAction;
                transactionAction = null;

            }

            public byte[] getResponseMessageBytes() {
                return isFiltered() ? null : transactionAction.getPayload().getAction().getProposalResponsePayload().getExtension().getResponseMessageBytes();
            }

            public String getResponseMessage() {
                return isFiltered() ? null :
                        transactionAction.getPayload().getAction().getProposalResponsePayload().getExtension().getResponseMessage();
            }

            public int getResponseStatus() {
                return isFiltered() ? -1 : transactionAction.getPayload().getAction().getProposalResponsePayload().getExtension().getResponseStatus();
            }

            int getChaincodeInputArgsCount = -1;

            public int getChaincodeInputArgsCount() {
                if (isFiltered()) {
                    return 0;
                }
                if (getChaincodeInputArgsCount < 0) {
                    getChaincodeInputArgsCount = transactionAction.getPayload().getChaincodeProposalPayload().
                            getChaincodeInvocationSpec().getChaincodeInput().getChaincodeInput().getArgsCount();
                }
                return getChaincodeInputArgsCount;
            }

            public byte[] getChaincodeInputArgs(int index) {
                if (isFiltered()) {
                    return null;
                }

                ChaincodeInput input = transactionAction.getPayload().getChaincodeProposalPayload().
                        getChaincodeInvocationSpec().getChaincodeInput().getChaincodeInput();

                return input.getArgs(index).toByteArray();
            }

            int getEndorsementsCount = -1;

            public int getEndorsementsCount() {
                if (isFiltered()) {
                    return 0;
                }
                if (getEndorsementsCount < 0) {
                    getEndorsementsCount = transactionAction.getPayload().getAction().getEndorsementsCount();
                }
                return getEndorsementsCount;
            }

            public EndorserInfo getEndorsementInfo(int index) {
                if (isFiltered()) {
                    return null;
                }
                if (null == endorserInfos) {
                    endorserInfos = new ArrayList<>();

                    for (Endorsement endorsement : transactionAction.getPayload().getAction()
                            .getChaincodeEndorsedAction().getEndorsementsList()) {

                        endorserInfos.add(new EndorserInfo(endorsement));

                    }
                }
                return endorserInfos.get(index);

            }

            public byte[] getProposalResponseMessageBytes() {
                if (isFiltered()) {
                    return null;
                }

                return transactionAction.getPayload().getAction().getProposalResponsePayload().getExtension().getResponseMessageBytes();

            }

            public byte[] getProposalResponsePayload() {
                if (isFiltered()) {
                    return null;
                }
                byte[] ret = null;

                ByteString retByteString = transactionAction.getPayload().getAction().getProposalResponsePayload().
                        getExtension().getResponsePayload();
                if (null != retByteString) {

                    ret = retByteString.toByteArray();
                }
                return ret;

            }

            public int getProposalResponseStatus() {
                if (isFiltered()) {
                    return -1;
                }

                return transactionAction.getPayload().getAction().getProposalResponsePayload().
                        getExtension().getResponseStatus();

            }

            /**
             * get name of chaincode with this transaction action
             *
             * @return name of chaincode.  Maybe null if no chaincode or if block is filtered.
             */
            public String getChaincodeIDName() {
                if (isFiltered()) {
                    return null;
                }
                String name = null;

                Chaincode.ChaincodeID ccid = transactionAction.getPayload().getAction().getProposalResponsePayload().
                        getExtension().getChaincodeID();

                if (ccid != null) {
                    name = ccid.getName();
                }

                return name;

            }

            /**
             * get path of chaincode with this transaction action
             *
             * @return path of chaincode.  Maybe null if no chaincode or if block is filtered.
             */
            public String getChaincodeIDPath() {
                if (isFiltered()) {
                    return null;
                }
                String path = null;

                Chaincode.ChaincodeID ccid = transactionAction.getPayload().getAction().getProposalResponsePayload().
                        getExtension().getChaincodeID();

                if (ccid != null) {
                    path = ccid.getPath();
                }

                return path;

            }

            /**
             * get version of chaincode with this transaction action
             *
             * @return version of chaincode.  Maybe null if no chaincode or if block is filtered.
             */

            public String getChaincodeIDVersion() {
                if (isFiltered()) {
                    return null;
                }
                String version = null;

                Chaincode.ChaincodeID ccid = transactionAction.getPayload().getAction().getProposalResponsePayload().
                        getExtension().getChaincodeID();

                if (ccid != null) {
                    version = ccid.getVersion();
                }

                return version;

            }

            /**
             * Get read write set for this transaction. Will return null on for Eventhub events.
             * For eventhub events find the block by block number to get read write set if needed.
             *
             * @return Read write set.
             */

            public TxReadWriteSetInfo getTxReadWriteSet() {

                if (BlockInfo.this.isFiltered()) {
                    return null;

                } else {

                    TxReadWriteSet txReadWriteSet = transactionAction.getPayload().getAction().getProposalResponsePayload()
                            .getExtension().getResults();
                    if (txReadWriteSet == null) {
                        return null;
                    }

                    return new TxReadWriteSetInfo(txReadWriteSet);
                }

            }

            /**
             * Get chaincode events for this transaction.
             *
             * @return A chaincode event if the chaincode set an event otherwise null.
             */

            public ChaincodeEvent getEvent() {
                if (isFiltered()) {
                    final PeerEvents.FilteredChaincodeAction chaincodeActions = filteredAction;
                    return new ChaincodeEvent(chaincodeActions.getChaincodeEvent().toByteString());
                }

                return transactionAction.getPayload().getAction().getProposalResponsePayload()
                        .getExtension().getEvent();

            }

        }

        public TransactionActionInfo getTransactionActionInfo(int index) {
            return BlockInfo.this.isFiltered() ? new TransactionActionInfo(filteredTx.getTransactionActions().getChaincodeActionsList().get(index))
                    : new TransactionActionInfo(transactionDeserializer.getPayload().getTransaction().getTransactionAction(index));
        }

        public class TransactionActionInfoIterator implements Iterator<TransactionActionInfo> {
            int ci = 0;
            final int max;

            TransactionActionInfoIterator() {
                max = getTransactionActionInfoCount();

            }

            @Override
            public boolean hasNext() {
                return ci < max;

            }

            @Override
            public TransactionActionInfo next() {

                if (ci >= max) {
                    throw new ArrayIndexOutOfBoundsException(format("Current index: %d. Max index: %d", ci, max));
                }

                //   return BlockInfo.this.isFiltered() ? new TransactionActionInfo(filteredTx.getFilteredAction(ci++))
                return BlockInfo.this.isFiltered() ? new TransactionActionInfo(filteredTx.getTransactionActions().getChaincodeActions(ci++))
                        : getTransactionActionInfo(ci++);
            }
        }

        public class TransactionActionIterable implements Iterable<TransactionActionInfo> {

            @Override
            public Iterator<TransactionActionInfo> iterator() {
                return new TransactionActionInfoIterator();
            }
        }
    }

    class EnvelopeInfoIterator implements Iterator<EnvelopeInfo> {
        int ci = 0;
        final int max;

        EnvelopeInfoIterator() {
            max = isFiltered() ? filteredBlock.getFilteredTransactionsCount() : block.getData().getDataCount();

        }

        @Override
        public boolean hasNext() {
            return ci < max;

        }

        @Override
        public EnvelopeInfo next() {

            if (ci >= max) {
                throw new ArrayIndexOutOfBoundsException(format("Current index: %d. Max index: %d", ci, max));
            }

            try {
                return getEnvelopeInfo(ci++);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

        }
    }

    class EnvelopeInfoIterable implements Iterable<EnvelopeInfo> {

        @Override
        public Iterator<EnvelopeInfo> iterator() {
            return new EnvelopeInfoIterator();
        }
    }

    public static class EndorserInfo {
        private final Endorsement endorsement;

        EndorserInfo(Endorsement endorsement) {

            this.endorsement = endorsement;
        }

        public byte[] getSignature() {
            return endorsement.getSignature().toByteArray();
        }

        /**
         * @return
         * @deprecated use getId and getMspid
         */
        public byte[] getEndorser() {
            return endorsement.getEndorser().toByteArray();
        }

        public String getId() {

            try {
                return Identities.SerializedIdentity.parseFrom(endorsement.getEndorser()).getIdBytes().toStringUtf8();
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }

        }

        public String getMspid() {
            try {
                return Identities.SerializedIdentity.parseFrom(endorsement.getEndorser()).getMspid();
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
        }

    }

    public enum EnvelopeType {

        TRANSACTION_ENVELOPE,
        ENVELOPE

    }

}


