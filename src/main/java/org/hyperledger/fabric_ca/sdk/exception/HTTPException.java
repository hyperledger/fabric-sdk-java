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

package org.hyperledger.fabric_ca.sdk.exception;

public class HTTPException extends BaseException {

    private static final long serialVersionUID = 1L;
    private int statusCode = -1;

    /**
     * @param message error message
     * @param statusCode HTTP status code
     * @param parent
     */
    public HTTPException(String message, int statusCode, Throwable parent) {
        super(message, parent);
        this.statusCode = statusCode;
    }

    /**
     * @param message error message
     * @param statusCode HTTP status code
     */
    public HTTPException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    /**
     * @param message error message
     * @param parent
     */
    public HTTPException(String message, Throwable parent) {
        super(message, parent);
    }

    /**
     * @param message error message
     */
    public HTTPException(String message) {
        super(message);
    }

    /**
     * @return HTTP status code
     */
    public int getStatusCode() {
        return this.statusCode;
    }
}
