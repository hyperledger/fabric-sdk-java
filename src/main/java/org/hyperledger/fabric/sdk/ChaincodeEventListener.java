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

/**
 * ChaincodeEventListener  implemented by classes needing to receive chaincode events.
 */
public interface ChaincodeEventListener {
    /**
     * Receiving a chaincode event. ChaincodeEventListener should not be long lived as they can take up thread resources.
     *
     * @param handle         The handle of the chaincode event listener that produced this event.
     * @param blockEvent     The block event information that contained the chaincode event. See {@link BlockEvent}
     * @param chaincodeEvent The chaincode event. see {@link ChaincodeEvent}
     */
    void received(String handle, BlockEvent blockEvent, ChaincodeEvent chaincodeEvent);
}
