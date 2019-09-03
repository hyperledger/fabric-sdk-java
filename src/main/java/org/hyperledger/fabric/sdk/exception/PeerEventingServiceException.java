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

package org.hyperledger.fabric.sdk.exception;

import org.hyperledger.fabric.protos.peer.EventsPackage;

public class PeerEventingServiceException extends TransactionException {

    private static final long serialVersionUID = 1L;

    /**
     * @return if timed out the time that was waited; otherwise, -1
     */
    public long getTimedOut() {
        return timedOut;
    }

    private long timedOut = -1L;

    /**
     * If response from the Peer's error is received return it.
     *
     * @return Response error from peer if received otherwise null.
     */
    public EventsPackage.DeliverResponse getResp() {
        return resp;
    }

    private EventsPackage.DeliverResponse resp;

    public PeerEventingServiceException(String message, Throwable parent) {
        super(message, parent);
    }

    public PeerEventingServiceException(String message) {
        super(message);
    }

    public PeerEventingServiceException(Throwable t) {
        super(t);
    }

    public void setResponse(EventsPackage.DeliverResponse resp) {
        this.resp = resp;
    }

    public void setTimedOut(long peerEventRegistrationWaitTimeMilliSecs) {
        this.timedOut = peerEventRegistrationWaitTimeMilliSecs;
    }
}
