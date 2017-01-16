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

/**
 * A base transaction request common for DeploymentProposalRequest, InvokeRequest, and QueryRequest.
 */
public class TransactionRequest {
    // The local path containing the chaincode to deploy in network mode.
    private String chaincodePath;
    // The name identifier for the chaincode to deploy in development mode.
    private String chaincodeName;
	// The chaincode ID as provided by the 'submitted' event emitted by a TransactionContext
    private ChainCodeID chaincodeID;
    // The name of the function to invoke
    private String fcn;
    // The arguments to pass to the chaincode invocation
    private ArrayList<String> args;
    // Specify whether the transaction is confidential or not.  The default value is false.
    private boolean confidential = false;
    // Optionally provide a user certificate which can be used by chaincode to perform access control
    private Certificate userCert;
    // Optionally provide additional metadata
    private byte[] metadata;
    // Chaincode language
    private Type chaincodeLanguage = Type.GO_LANG;


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
	public ChainCodeID getChaincodeID() {
		return chaincodeID;
	}
	public void setChaincodeID(ChainCodeID chaincodeID) {
		this.chaincodeID = chaincodeID;
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

		this.args = new ArrayList( Arrays.asList( args ) );
		return this;
	}
	public TransactionRequest setArgs(ArrayList<String> args) {
		this.args = args;
		return this;
	}
	public boolean isConfidential() {
		return confidential;
	}
	public void setConfidential(boolean confidential) {
		this.confidential = confidential;
	}
	public Certificate getUserCert() {
		return userCert;
	}
	public void setUserCert(Certificate userCert) {
		this.userCert = userCert;
	}
	public byte[] getMetadata() {
		return metadata;
	}
	public void setMetadata(byte[] metadata) {
		this.metadata = metadata;
	}


    //Mirror Fabric try not expose and of it's classes
	public enum Type{
		JAVA,
		GO_LANG
	}

	public Type getChaincodeLanguage() {
		return chaincodeLanguage;
	}

	/**
	 * The chain code language type: default type Type.GO_LANG
	 * @param chaincodeLanguage . Type.Java Type.GO_LANG
	 */
	public void setChaincodeLanguage(Type chaincodeLanguage) {
		this.chaincodeLanguage = chaincodeLanguage;
	}


}
