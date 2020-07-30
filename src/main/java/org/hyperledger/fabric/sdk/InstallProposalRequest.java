/*
Copyright DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.hyperledger.fabric.sdk;

import java.io.File;
import java.io.InputStream;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

/**
 * InstallProposalRequest.
 * @deprecated See {@link LifecycleInstallChaincodeRequest}
 */
@Deprecated
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
