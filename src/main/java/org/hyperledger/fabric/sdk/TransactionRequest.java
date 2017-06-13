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

package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;

/**
 * A base transaction request common for InstallProposalRequest,trRequest, and QueryRequest.
 */
public class TransactionRequest {
    private User userContext;

    boolean submitted = false;

    private final Config config = Config.getConfig();

    // The local path containing the chaincode to deploy in network mode.
    protected String chaincodePath;
    // The name identifier for the chaincode to deploy in development mode.
    protected String chaincodeName;

    // The version of the chaincode
    protected String chaincodeVersion;
    // The chaincode ID as provided by the 'submitted' event emitted by a TransactionContext
    private ChaincodeID chaincodeID;

    // The name of the function to invoke
    protected String fcn;
    // The arguments to pass to the chaincode invocation as strings
    protected ArrayList<String> args;
    // the arguments to pass to the chaincode invocation as byte arrays
    protected ArrayList<byte[]> argBytes;

    // Chaincode language
    protected Type chaincodeLanguage = Type.GO_LANG;
    // The endorsementPolicy associated with this chaincode
    private ChaincodeEndorsementPolicy endorsementPolicy = null;
    // The timeout for a single proposal request to endorser in milliseconds
    protected long proposalWaitTime = config.getProposalWaitTime();

    protected Map<String, byte[]> transientMap;

    /**
     * The user context to use on this request.
     *
     * @return User context that is used for signing
     */
    User getUserContext() {
        return userContext;
    }

    /**
     * Set the user context for this request. This context will override the user context set
     * on {@link HFClient#setUserContext(User)}
     *
     * @param userContext The user context for this request used for signing.
     */
    public void setUserContext(User userContext) {
        this.userContext = userContext;
    }

    /**
     * Transient data added to the proposal that is not added to the ledger.
     *
     * @return Map of strings to bytes that's added to the proposal
     */

    public Map<String, byte[]> getTransientMap() {
        return transientMap;
    }

    /**
     * Determines whether an empty channel ID should be set on proposals built
     * from this request. Some peer requests (e.g. queries to QSCC) require the
     * field to be blank. Subclasses should override this method as needed.
     * <p>
     * This implementation returns {@code false}.
     *
     * @return {@code true} if an empty channel ID should be used; otherwise
     * {@code false}.
     */
    public boolean noChannelID() {
        return false;
    }

    /**
     * Some proposal responses from Fabric are not signed. We default to always verify a ProposalResponse.
     * Subclasses should override this method if you do not want the response signature to be verified
     *
     * @return true if proposal response is to be checked for a valid signature
     */
    public boolean doVerify() {
        return true;
    }

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

    public ChaincodeID getChaincodeID() {
        return chaincodeID;
    }

    public void setChaincodeID(ChaincodeID chaincodeID) {

        if (chaincodeName != null) {

            throw new IllegalArgumentException("Chaincode name has already been set.");
        }
        if (chaincodeVersion != null) {

            throw new IllegalArgumentException("Chaincode version has already been set.");
        }

        if (chaincodePath != null) {

            throw new IllegalArgumentException("Chaincode path has already been set.");
        }

        this.chaincodeID = chaincodeID;
        chaincodeName = chaincodeID.getName();
        chaincodePath = chaincodeID.getPath();
        chaincodeVersion = chaincodeID.getVersion();
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

        this.args = new ArrayList<>(Arrays.asList(args));
        return this;
    }

    public TransactionRequest setArgBytes(ArrayList<byte[]> args) {
        this.argBytes = args;
        return this;
    }

    public ArrayList<byte[]> getArgBytes() {
        return argBytes;
    }

    public TransactionRequest setArgBytes(byte[][] args) {

        this.argBytes = new ArrayList<>(Arrays.asList(args));
        return this;
    }

    public TransactionRequest setArgs(ArrayList<String> args) {
        this.args = args;
        return this;
    }

    //Mirror Fabric try not expose any of its classes
    public enum Type {
        JAVA,
        GO_LANG
    }

    public Type getChaincodeLanguage() {
        return chaincodeLanguage;
    }

    /**
     * The chaincode language type: default type Type.GO_LANG
     *
     * @param chaincodeLanguage . Type.Java Type.GO_LANG
     */
    public void setChaincodeLanguage(Type chaincodeLanguage) {
        this.chaincodeLanguage = chaincodeLanguage;
    }

    /**
     * sets the endorsementPolicy associated with the chaincode of this transaction
     *
     * @param policy a Policy object
     * @see ChaincodeEndorsementPolicy
     */
    public void setChaincodeEndorsementPolicy(ChaincodeEndorsementPolicy policy) {
        this.endorsementPolicy = policy;
    }

    /**
     * returns the Policy object associated with the chaincode of this transaction
     *
     * @return a Policy object
     * @see ChaincodeEndorsementPolicy
     */
    public ChaincodeEndorsementPolicy getChaincodeEndorsementPolicy() {
        return this.endorsementPolicy;
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

    /**
     * If this request has been submitted already.
     *
     * @return true if the already submitted.
     */

    public boolean isSubmitted() {
        return submitted;
    }

    void setSubmitted() throws InvalidArgumentException {

        if (submitted) {
            // Has already been submitted.
            throw new InvalidArgumentException("Request has been already submitted and can not be reused.");
        }
        User.userContextCheck(userContext);
        this.submitted = true;
    }

    protected TransactionRequest(User userContext) {
        this.userContext = userContext;
    }

}
