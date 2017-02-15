/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Arrays;

import org.hyperledger.fabric.sdk.helper.Config;

/**
 * A base transaction request common for InstallProposalRequest, InvokeRequest, and QueryRequest.
 */
public class TransactionRequest {

    private final Config config = Config.getConfig();

    // The local path containing the chaincode to deploy in network mode.
    protected String chaincodePath;
    // The name identifier for the chaincode to deploy in development mode.
    protected String chaincodeName;


    // The version of the chainCode
    protected String chaincodeVersion;
    // The chaincode ID as provided by the 'submitted' event emitted by a TransactionContext
    private ChainCodeID chaincodeID;


    // The name of the function to invoke
    protected String fcn;
    // The arguments to pass to the chaincode invocation
    protected ArrayList<String> args;
    // Optionally provide a user certificate which can be used by chaincode to perform access control
    private Certificate userCert;
    // Chaincode language
    protected Type chaincodeLanguage = Type.GO_LANG;
    // The timeout for a single proposal request to endorser in milliseconds
    protected long proposalWaitTime = config.getProposalWaitTime();


    public String getChaincodePath() {
        return null == chaincodePath ? "" : chaincodePath;
    }

    public TransactionRequest setChaincodePath(String chaincodePath) {

        this.chaincodePath = chaincodePath;
        return this;
    }

    public String getChaincodeName() {
        return chaincodeName;
    }

    public TransactionRequest setChaincodeName(String chaincodeName) {
        this.chaincodeName = chaincodeName;
        return this;
    }

    public TransactionRequest setChaincodeVersion(String chaincodeVersion) {
        this.chaincodeVersion = chaincodeVersion;
        return this;
    }

    public String getChaincodeVersion() {
        return chaincodeVersion;
    }

    public ChainCodeID getChaincodeID() {
        return chaincodeID;
    }

    public void setChaincodeID(ChainCodeID chaincodeID) {
        this.chaincodeID = chaincodeID;
        this.chaincodeName = chaincodeID.getName();
        this.chaincodePath = chaincodeID.getPath();
        this.chaincodeVersion = chaincodeID.getVersion();
    }

    public String getFcn() {
        return fcn;
    }

    public TransactionRequest setFcn(String fcn) {
        this.fcn = fcn;
        return this;
    }

    public ArrayList<String> getArgs() {
        return args;
    }

    public TransactionRequest setArgs(String[] args) {

        this.args = new ArrayList<String>(Arrays.asList(args));
        return this;
    }

    public TransactionRequest setArgs(ArrayList<String> args) {
        this.args = args;
        return this;
    }

    public Certificate getUserCert() {
        return userCert;
    }

    public void setUserCert(Certificate userCert) {
        this.userCert = userCert;
    }


    //Mirror Fabric try not expose and of it's classes
    public enum Type {
        JAVA,
        GO_LANG
    }

    public Type getChaincodeLanguage() {
        return chaincodeLanguage;
    }

    /**
     * The chain code language type: default type Type.GO_LANG
     *
     * @param chaincodeLanguage . Type.Java Type.GO_LANG
     */
    public void setChaincodeLanguage(Type chaincodeLanguage) {
        this.chaincodeLanguage = chaincodeLanguage;
    }

    /**
     * Gets the timeout for a single proposal request to endorser in milliseconds.
     *
     * @return the timeout for a single proposal request to endorser in milliseconds
     */
    public long getProposalWaitTime() {
        return proposalWaitTime;
    }

    /**
     * Sets the timeout for a single proposal request to endorser in milliseconds.
     *
     * @param proposalWaitTime the timeout for a single proposal request to endorser in milliseconds
     */
    public void setProposalWaitTime(long proposalWaitTime) {
        this.proposalWaitTime = proposalWaitTime;
    }
}
