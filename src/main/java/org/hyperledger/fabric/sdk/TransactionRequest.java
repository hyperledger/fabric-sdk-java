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
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

/**
 * A base transaction request common for InstallProposalRequest,trRequest, and QueryRequest.
 */
public class TransactionRequest {
    protected boolean init = false;
    private User userContext;

    private final Config config = Config.getConfig();

    // The local path containing the chaincode to deploy in network mode.
    protected String chaincodePath;

    public void setChaincodeName(String chaincodeName) {
        this.chaincodeName = chaincodeName;
    }

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
    protected ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = null;

    private TransactionContext transactionContext;

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
        User.userContextCheck(userContext);
        this.userContext = userContext;
        this.transactionContext = null;
    }

    /**
     * Get the transaction context to be used when submitting this transaction request, if one has been set.
     * @return A transaction context.
     */
    public Optional<TransactionContext> getTransactionContext() {
        return Optional.ofNullable(transactionContext);
    }

    /**
     * Get the transaction context to be used when submitting this transaction request.
     * @param transactionContext A transaction ID.
     */
    public void setTransactionContext(final TransactionContext transactionContext) {
        userContext = transactionContext.getUser();
        this.transactionContext = transactionContext;
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

    public String getChaincodeName() {
        return chaincodeName;
    }

//    public TransactionRequest setChaincodeName(String chaincodeName) {
//        this.chaincodeName = chaincodeName;
//        return this;
//    }

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

    public TransactionRequest setArgs(String... args) {

        this.args = new ArrayList<>(Arrays.asList(args));
        return this;
    }

//    public TransactionRequest setArgBytes(ArrayList<byte[]> args) {
//        this.argBytes = args;
//        return this;
//    }

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

    public TransactionRequest setArgs(byte[]... args) {

        ArrayList<byte[]> argBytes = new ArrayList<>(args.length);

        argBytes.addAll(Arrays.asList(args));

        this.argBytes = argBytes;
        return this;
    }

    public Chaincode.ChaincodeID getFabricChaincodeID() {

        ChaincodeID chaincodeID = getChaincodeID();
        Chaincode.ChaincodeID fabricChaincodeID = null;

        if (null == chaincodeID) {

            Chaincode.ChaincodeID.Builder builder = Chaincode.ChaincodeID.newBuilder().setName(getChaincodeName());
            if (getChaincodeVersion() != null) {
                builder.setVersion(getChaincodeVersion());
            }
            if (getChaincodePath() != null) {
                builder.setPath(getChaincodePath());
            }
            fabricChaincodeID = builder.build();

        } else {
            fabricChaincodeID = chaincodeID.getFabricChaincodeID();
        }

        return fabricChaincodeID;

    }

    public void setInit(boolean init) {
        this.init = init;
    }

    public boolean isInit() {
        return init;
    }

    //Mirror Fabric try not expose any of its classes
    public enum Type {
        JAVA,
        GO_LANG,
        NODE;

        private static final Map<Type, String> cpv = new HashMap<>(4);
        private static final Map<String, Type> cpvr = new HashMap<>(4);

        static {
            cpv.put(Type.JAVA, "java");
            cpv.put(Type.GO_LANG, "golang");
            cpv.put(Type.NODE, "node");

            cpvr.put("java", Type.JAVA);
            cpvr.put("golang", Type.GO_LANG);
            cpvr.put("node", Type.NODE);
        }

        public String toPackageName() {
            String ret = cpv.get(this);
            if (null == ret) {
                ret = "golang";
            }
            return ret;
        }

        public static Type fromPackageName(String name) {
            Type ret = cpvr.get(name);
            return ret;

        }
    }

    public Type getChaincodeLanguage() {
        return chaincodeLanguage;
    }

    /**
     * The chaincode language type: default type Type.GO_LANG
     *
     * @param chaincodeLanguage . Type.Java Type.GO_LANG Type.NODE
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
     * get collection configuration for this chaincode.
     *
     * @return collection configuration if set.
     */
    public ChaincodeCollectionConfiguration getChaincodeCollectionConfiguration() {
        return chaincodeCollectionConfiguration;

    }

    /**
     * Set collection configuration for this chaincode.
     *
     * @param chaincodeCollectionConfiguration
     */
    public void setChaincodeCollectionConfiguration(ChaincodeCollectionConfiguration chaincodeCollectionConfiguration) {
        this.chaincodeCollectionConfiguration = chaincodeCollectionConfiguration;
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

    protected TransactionRequest(User userContext) {
        User.userContextCheck(userContext);
        this.userContext = userContext;
    }

}
