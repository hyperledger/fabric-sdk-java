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

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

/**
 * Collection of information on chaincode collection.
 */
public class CollectionConfigPackage {

    private final ByteString collectionConfigBytes;
    private org.hyperledger.fabric.protos.peer.Collection.CollectionConfigPackage cp;

    CollectionConfigPackage(ByteString collectionConfig) {
        this.collectionConfigBytes = collectionConfig;

    }

    /**
     * The raw collection information returned from the peer.
     *
     * @return The raw collection information returned from the peer.
     * @throws InvalidProtocolBufferException
     */

    public org.hyperledger.fabric.protos.peer.Collection.CollectionConfigPackage getCollectionConfigPackage() throws InvalidProtocolBufferException {
        if (null == cp) {
            cp = org.hyperledger.fabric.protos.peer.Collection.CollectionConfigPackage.parseFrom(collectionConfigBytes);
        }

        return cp;

    }

    /**
     * Collection of the chaincode collections.
     *
     * @return Collection of the chaincode collection
     * @throws InvalidProtocolBufferException
     */
    public Collection<CollectionConfig> getCollectionConfigs() throws InvalidProtocolBufferException {
        List<CollectionConfig> ret = new LinkedList<>();
        for (org.hyperledger.fabric.protos.peer.Collection.CollectionConfig collectionConfig : getCollectionConfigPackage().getConfigList()) {
            ret.add(new CollectionConfig(collectionConfig));

        }
        return ret;

    }

    /**
     * Collection information.
     */

    public static class CollectionConfig {
        final org.hyperledger.fabric.protos.peer.Collection.CollectionConfig collectionConfig;

        /**
         * Name of the collection.
         *
         * @return
         */
        public String getName() {
            return getStaticCollectionConfig.getName();
        }

        /**
         * return required peer
         *
         * @return required peer count.
         */

        public int getRequiredPeerCount() {
            return getStaticCollectionConfig.getRequiredPeerCount();
        }

        /**
         * Minimum peer count.
         *
         * @return minimum peer count.
         */
        public int getMaximumPeerCount() {
            return getStaticCollectionConfig.getMaximumPeerCount();
        }

        /**
         * Block to live.
         *
         * @return block to live.
         */
        public long getBlockToLive() {
            return getStaticCollectionConfig.getBlockToLive();
        }

        final org.hyperledger.fabric.protos.peer.Collection.StaticCollectionConfig getStaticCollectionConfig;

        CollectionConfig(org.hyperledger.fabric.protos.peer.Collection.CollectionConfig collectionConfig) {
            this.collectionConfig = collectionConfig;
            this.getStaticCollectionConfig = collectionConfig.getStaticCollectionConfig();

        }

        /**
         * The collection information returned directly from the peer.
         *
         * @return The collection information returned directly from the peer.
         */
        public org.hyperledger.fabric.protos.peer.Collection.CollectionConfig getCollectionConfig() {
            org.hyperledger.fabric.protos.peer.Collection.StaticCollectionConfig staticCollectionConfig = collectionConfig.getStaticCollectionConfig();

            return this.collectionConfig;
        }

    }

}
