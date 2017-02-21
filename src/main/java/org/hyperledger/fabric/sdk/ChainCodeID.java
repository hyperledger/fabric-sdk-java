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


import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID;

/**
 * ChainCodeID identifies chaincode.
 */
public class ChainCodeID {

    private final ChaincodeID fabricChainCodeID;

    private ChainCodeID() {

        fabricChainCodeID = null;

    }


    public ChaincodeID getFabricChainCodeID() {
        return fabricChainCodeID;
    }


    ChainCodeID(ChaincodeID chaincodeID) {
        this.fabricChainCodeID = chaincodeID;
    }

    public String getName() {
        return fabricChainCodeID.getName();
    }

    public String getPath() {
        return fabricChainCodeID.getPath();

    }

    public String getVersion() {
        return fabricChainCodeID.getVersion();

    }

    /**
     * Build a new ChainCodeID
     */

    public static class Builder {
        private final ChaincodeID.Builder protoBuilder = ChaincodeID.newBuilder();

        private Builder() {
        }

        /**
         * @param name of the Chaincode
         * @return Builder
         */

        public Builder setName(String name) {
            this.protoBuilder.setName(name);
            return this;
        }

        /**
         * Set the version of the ChainCode
         *
         * @param version of the chaincode
         * @return Builder
         */
        public Builder setVersion(String version) {
            this.protoBuilder.setVersion(version);
            return this;
        }


        /**
         * Set path of chaincode
         *
         * @param path of chaincode
         * @return Builder
         */


        public Builder setPath(String path) {
            this.protoBuilder.setPath(path);
            return this;
        }

        public ChainCodeID build() {
            return new ChainCodeID(this.protoBuilder.build());
        }
    }

    /**
     *  Chaincode builder
     *
     * @return ChaincodeID builder.
     */

    public static Builder newBuilder() {
        return new Builder();
    }


}
