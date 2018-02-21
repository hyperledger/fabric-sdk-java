/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.io.File;
import java.io.InputStream;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

/**
 * InstallProposalRequest.
 */
public class InstallProposalRequest extends TransactionRequest {

    private File chaincodeSourceLocation = null;
    private InputStream chaincodeInputStream = null;
    private File chaincodeMetaInfLocation = null;

    File getChaincodeMetaInfLocation() {
        return chaincodeMetaInfLocation;
    }

    /**
     * Set the META-INF directory to be used for packaging chaincode.
     * Only applies if source location {@link #chaincodeSourceLocation} for the chaincode is set.
     *
     * @param chaincodeMetaInfLocation The directory where the "META-INF" directory is located..
     * @see <a href="http://hyperledger-fabric.readthedocs.io/en/master/couchdb_as_state_database.html#using-couchdb-from-chaincode">
     * Fabric Read the docs couchdb as a state database
     * </a>
     */

    public void setChaincodeMetaInfLocation(File chaincodeMetaInfLocation) throws InvalidArgumentException {
        if (chaincodeMetaInfLocation == null) {
            throw new InvalidArgumentException("Chaincode META-INF location may not be null.");
        }

        if (chaincodeInputStream != null) {
            throw new InvalidArgumentException("Chaincode META-INF location may not be set with chaincode input stream set.");
        }
        this.chaincodeMetaInfLocation = chaincodeMetaInfLocation;
    }



    InstallProposalRequest(User userContext) {
        super(userContext);
    }

    public InputStream getChaincodeInputStream() {
        return chaincodeInputStream;
    }

    /**
     * Chaincode input stream containing the actual chaincode. Only format supported is a tar zip compressed input of the source.
     * Only input stream or source location maybe used at the same time.
     * The contents of the stream are not validated or inspected by the SDK.
     *
     * @param chaincodeInputStream
     * @throws InvalidArgumentException
     */

    public void setChaincodeInputStream(InputStream chaincodeInputStream) throws InvalidArgumentException {
        if (chaincodeInputStream == null) {
            throw new InvalidArgumentException("Chaincode input stream may not be null.");
        }
        if (chaincodeSourceLocation != null) {
            throw new InvalidArgumentException("Error setting chaincode input stream. Chaincode source location already set. Only one or the other maybe set.");
        }
        if (chaincodeMetaInfLocation != null) {
            throw new InvalidArgumentException("Error setting chaincode input stream. Chaincode META-INF location  already set. Only one or the other maybe set.");
        }
        this.chaincodeInputStream = chaincodeInputStream;
    }

    public File getChaincodeSourceLocation() {
        return chaincodeSourceLocation;
    }

    /**
     * The location of the chaincode.
     * Chaincode input stream and source location can not both be set.
     *
     * @param chaincodeSourceLocation
     * @throws InvalidArgumentException
     */
    public void setChaincodeSourceLocation(File chaincodeSourceLocation) throws InvalidArgumentException {
        if (chaincodeSourceLocation == null) {
            throw new InvalidArgumentException("Chaincode source location may not be null.");
        }
        if (chaincodeInputStream != null) {
            throw new InvalidArgumentException("Error setting chaincode location. Chaincode input stream already set. Only one or the other maybe set.");
        }

        this.chaincodeSourceLocation = chaincodeSourceLocation;
    }

}
