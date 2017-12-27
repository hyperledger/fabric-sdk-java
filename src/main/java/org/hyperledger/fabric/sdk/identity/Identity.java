/*
 *
 *  Copyright IBM Corp. All Rights Reserved.
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

package org.hyperledger.fabric.sdk.identity;

import org.hyperledger.fabric.protos.msp.Identities;

/**
 * Identity corresponds to the Identity in fabric MSP.
 * The Identity is attached to the transaction signature and
 * can be unique per user or unlinkable (depending on the implementation and requirements)
 * This is to be used at the peer side when verifying certificates/credentials that transactions are signed
 * with, and verifying signatures that correspond to these certificates.
 */
public interface Identity {

    /**
     * Converts an identity to bytes
     *
     * @return SerializedIdentity
     */
    Identities.SerializedIdentity createSerializedIdentity();
}
