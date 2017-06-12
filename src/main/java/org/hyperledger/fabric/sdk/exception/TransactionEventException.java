/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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
package org.hyperledger.fabric.sdk.exception;

import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;

/**
 * The exception to be thrown when we receive an event for an invalid Transaction
 */
public class TransactionEventException extends TransactionException {

    private static final long serialVersionUID = -5980057390186258323L;

    private final TransactionEvent transactionEvent;

    /**
     * save the TransactionEvent in the exception so that caller can use for debugging
     *
     * @param message
     * @param transactionEvent
     */
    public TransactionEventException(String message, TransactionEvent transactionEvent) {
        super(message);
        this.transactionEvent = transactionEvent;
    }

    /**
     * save the TransactionEvent in the exception so that caller can use for debugging
     *
     * @param message
     * @param transactionEvent
     * @param throwable
     */
    public TransactionEventException(String message, TransactionEvent transactionEvent, Throwable throwable) {
        super(message, throwable);
        this.transactionEvent = transactionEvent;
    }

    /**
     * @return the transactionEvent that precipitated this exception
     */
    public TransactionEvent getTransactionEvent() {
        return this.transactionEvent;
    }

}
