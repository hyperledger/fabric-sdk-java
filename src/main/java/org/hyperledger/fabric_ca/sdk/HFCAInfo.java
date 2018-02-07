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

package org.hyperledger.fabric_ca.sdk;

/**
 * Fabric Certificate authority information
 * Contains information for the Fabric certificate authority
 */
public class HFCAInfo {

    private final String caName;
    private final String caChain;
    private final String version;

    // Contains server/ca information
    HFCAInfo(String caName, String caChain, String version) {
        this.caName = caName;
        this.caChain = caChain;
        this.version = version;
    }

    /**
     * The CAName for the Fabric Certificate Authority.
     *
     * @return The CA Name.
     */

    public String getCAName() {
        return caName;
    }

    /**
     * The Certificate Authority's Certificate Chain.
     *
     * @return Certificate Chain in X509 PEM format.
     */

    public String getCACertificateChain() {
        return caChain;
    }

    /**
     * Version of Fabric CA server
     *
     * @return Version of Fabric CA server, value will be
     * null for Fabric CA prior to 1.1.0
     */

    public String getVersion() {
        return version;
    }
}