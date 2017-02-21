/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import org.hyperledger.fabric.protos.common.Ledger;

/**
 * BlockchainInfo contains information about the blockchain ledger.
 */
public class BlockchainInfo {

    private final Ledger.BlockchainInfo blockchainInfo;

    BlockchainInfo(Ledger.BlockchainInfo blockchainInfo) {
        this.blockchainInfo = blockchainInfo;
    }

    /**
     * @return the current ledger blocks height
     */
    public long getHeight() {
        return blockchainInfo.getHeight();
    }

    /**
     * @return the current bloch hash
     */
    public byte[] getCurrentBlockHash() {
        return blockchainInfo.getCurrentBlockHash().toByteArray();
    }

    /**
     * @return the previous block hash
     */
    public byte[] getPreviousBlockHash() {
        return blockchainInfo.getPreviousBlockHash().toByteArray();
    }

    /**
     * @return the protobuf BlockchainInfo struct this object is based on.
     */
    public Ledger.BlockchainInfo getBlockchainInfo() {
        return blockchainInfo;
    }
}

