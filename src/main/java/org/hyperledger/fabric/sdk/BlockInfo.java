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

import org.hyperledger.fabric.protos.common.Common.Block;

/**
 * BlockInfo contains the data from a {@link Block}
 *
 */
public class BlockInfo {
    private final Block block;

    BlockInfo(Block block) {
        this.block = block;
    }

    /**
     * @return the raw {@link Block}
     */
    public Block getBlock() {
        return block;
    }

    /**
     * @return the {@link Block} previousHash value
     */
    public byte[] getPreviousHash() {
        return block.getHeader().getPreviousHash().toByteArray() ;
    }

    /**
     * @return the {@link Block} index number
     */
    public long getBlockNumber() {
        return block.getHeader().getNumber() ;
    }

}
