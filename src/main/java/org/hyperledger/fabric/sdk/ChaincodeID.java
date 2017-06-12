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

/**
 * ChaincodeID identifies chaincode.
 */
public final class ChaincodeID {

    private final org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID fabricChaincodeID;

    public org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID getFabricChaincodeID() {
        return fabricChaincodeID;
    }

    ChaincodeID(org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID chaincodeID) {
        this.fabricChaincodeID = chaincodeID;
    }

    public String getName() {
        return fabricChaincodeID.getName();
    }

    public String getPath() {
        return fabricChaincodeID.getPath();

    }

    public String getVersion() {
        return fabricChaincodeID.getVersion();

    }

    /**
     * Build a new ChaincodeID
     */

    public static final class Builder {
        private final org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID.Builder protoBuilder = org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID.newBuilder();

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
         * Set the version of the Chaincode
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

        public ChaincodeID build() {
            return new ChaincodeID(this.protoBuilder.build());
        }
    }

    /**
     * Chaincode builder
     *
     * @return ChaincodeID builder.
     */

    public static Builder newBuilder() {
        return new Builder();
    }

}
