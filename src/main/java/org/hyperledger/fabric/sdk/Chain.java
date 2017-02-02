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

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.common.Common.BlockData;
import org.hyperledger.fabric.protos.common.Common.ChainHeader;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.common.Configuration.ConfigurationItem;
import org.hyperledger.fabric.protos.common.Configuration.ConfigurationItem.ConfigurationType;
import org.hyperledger.fabric.protos.common.Configuration.SignedConfigurationItem;
import org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.protos.peer.PeerEvents.Event.EventCase;
import org.hyperledger.fabric.sdk.events.BlockListener;
import org.hyperledger.fabric.sdk.events.EventHub;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.InvalidTransactionException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.transaction.DeploymentProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.ProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Vector;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.String.format;
import static org.hyperledger.fabric.protos.common.Configuration.ConfigurationSignature;
import static org.hyperledger.fabric.protos.common.Configuration.Policy;
import static org.hyperledger.fabric.protos.common.Configuration.SignaturePolicy;
import static org.hyperledger.fabric.protos.common.Configuration.SignaturePolicyEnvelope;
import static org.hyperledger.fabric.protos.peer.PeerEvents.Event;
import static org.hyperledger.fabric.sdk.helper.SDKUtil.checkGrpcUrl;
import static org.hyperledger.fabric.sdk.helper.SDKUtil.nullOrEmptyString;


/**
 * The class representing a chain with which the client SDK interacts.
 */
public class Chain {
    private static final Log logger = LogFactory.getLog(Chain.class);

    // Name of the chain is only meaningful to the client
    private String name;

    // The peers on this chain to which the client can connect
    private final Collection<Peer> peers = new Vector<>();

    // Security enabled flag
    private boolean securityEnabled = true;

    // A user cache associated with this chain
    // TODO: Make an LRU to limit size of user cache
    private final Map<String, User> members = new HashMap<>();

    // The number of tcerts to get in each batch
    private int tcertBatchSize = 200;

    // The registrar (if any) that registers & enrolls new members/users
    private User registrar;

    // The member services used for this chain
    private MemberServices memberServices;

    // The key-val store used for this chain
    private KeyValStore keyValStore;

    // Is in dev mode or network mode
    private boolean devMode = false;

    // If in prefetch mode, we prefetch tcerts from member services to help performance
    private boolean preFetchMode = true;

    // Temporary variables to control how long to wait for deploy and invoke to complete before
    // emitting events.  This will be removed when the SDK is able to receive events from the
    private int deployWaitTime = 20;
    private int invokeWaitTime = 5;

    // The crypto primitives object
    private CryptoPrimitives cryptoPrimitives;
    private final Collection<Orderer> orderers = new LinkedList<>();
    HFClient client;
    private boolean initialized = false;
    private int max_message_count = 50;
    private final Collection<EventHub> eventHubs = new LinkedList<>();
    private final ExecutorService es = Executors.newCachedThreadPool();


    public Enrollment getEnrollment() {
        return enrollment;
    }

    private Enrollment enrollment;

    /**
     * isInitialized - Has the chain been initialized?
     *
     * @return boolean true if chain is initialized
     */

    public boolean isInitialized() {
        return initialized;
    }

    /**
     * @param name
     * @param client
     */

    Chain(String name, HFClient client) throws InvalidArgumentException {
        if (nullOrEmptyString(name)) {
            throw new InvalidArgumentException("Chain name is invalid can not be null or empty.");
        }
        if (null == client) {
            throw new InvalidArgumentException("Chain client is invalid can not be null.");
        }
        this.name = name;
        this.client = client;
    }

    /**
     * Get the chain name
     *
     * @returns The name of the chain
     */
    public String getName() {
        return this.name;
    }

    /**
     * Add a peer to the chain
     *
     * @param peer the Peer to add.
     * @return
     * @throws InvalidArgumentException
     */
    public Chain addPeer(Peer peer) throws InvalidArgumentException {

        if (null == peer) {
            throw new InvalidArgumentException("Peer is invalid can not be null.");
        }
        if (nullOrEmptyString(peer.getName())) {
            throw new InvalidArgumentException("Peer added to chan has no name.");
        }

        Exception e = checkGrpcUrl(peer.getUrl());
        if (e != null) {
            throw new InvalidArgumentException("Peer added to chan has invalid url.", e);
        }

        peer.setChain(this);
        this.peers.add(peer);
        return this;
    }

    /**
     * addOrderer - Add an Orderer to the chain
     *
     * @param orderer
     * @return
     * @throws InvalidArgumentException
     */

    public Chain addOrderer(Orderer orderer) throws InvalidArgumentException {

        if (null == orderer) {
            throw new InvalidArgumentException("Orderer is invalid can not be null.");
        }

        Exception e = checkGrpcUrl(orderer.getUrl());
        if (e != null) {
            throw new InvalidArgumentException("Peer added to chan has invalid url.", e);
        }

        orderer.setChain(this);
        this.orderers.add(orderer);
        return this;
    }


    public Chain addEventHub(EventHub eventHub) throws InvalidArgumentException {
        if (null == eventHub) {
            throw new InvalidArgumentException("Orderer is invalid can not be null.");
        }

        Exception e = checkGrpcUrl(eventHub.getUrl());
        if (e != null) {
            throw new InvalidArgumentException("Peer added to chan has invalid url.", e);
        }


        eventHub.setEventQue(chainEventQue);
        eventHubs.add(eventHub);
        return this;

    }


    /**
     * Get the peers for this chain.
     */
    public Collection<Peer> getPeers() {
        return Collections.unmodifiableCollection(this.peers);
    }

    /**
     * Get the registrar associated with this chain
     *
     * @return The user whose credentials are used to perform registration, or undefined if not set.
     */
    public User getRegistrar() {
        return this.registrar;
    }

    /**
     * Set the registrar
     *
     * @param registrar The user whose credentials are used to perform registration.
     */
    public void setRegistrar(User registrar) {
        this.registrar = registrar;
    }

    /**
     * Set the member services URL
     *
     * @param url User services URL of the form: "grpc://host:port" or "grpcs://host:port"
     * @param pem
     * @throws CertificateException
     */
    public void setMemberServicesUrl(String url, String pem) throws CertificateException, MalformedURLException {
        this.setMemberServices(new MemberServicesFabricCAImpl(url, pem));
    }

    /**
     * Get the member service associated this chain.
     *
     * @returns MemberServices associated with the chain, or undefined if not set.
     */
    public MemberServices getMemberServices() {
        return this.memberServices;
    }


    /**
     * Set the member service
     *
     * @param memberServices The MemberServices instance
     */
    public void setMemberServices(MemberServices memberServices) {
        this.memberServices = memberServices;
        if (memberServices instanceof MemberServicesFabricCAImpl) {
            this.cryptoPrimitives = ((MemberServicesFabricCAImpl) memberServices).getCrypto();
        }
    }

    /**
     * Determine if security is enabled.
     *
     * @return true if security is enabled, false otherwise
     */
    public boolean isSecurityEnabled() {
        return this.memberServices != null;
    }

    /**
     * Determine if pre-fetch mode is enabled to prefetch tcerts.
     *
     * @return true if  pre-fetch mode is enabled, false otherwise
     */
    public boolean isPreFetchMode() {
        return this.preFetchMode;
    }

    /**
     * Set prefetch mode to true or false.
     */
    public void setPreFetchMode(boolean preFetchMode) {
        this.preFetchMode = preFetchMode;
    }

    /**
     * Determine if dev mode is enabled.
     */
    public boolean isDevMode() {
        return this.devMode;
    }

    /**
     * Set dev mode to true or false.
     */
    public void setDevMode(boolean devMode) {

        this.devMode = devMode;
    }

    /**
     * Get the deploy wait time in seconds.
     */
    public int getDeployWaitTime() {
        return this.deployWaitTime;
    }

    /**
     * Set the deploy wait time in seconds.
     *
     * @param waitTime Deploy wait time
     */
    public void setDeployWaitTime(int waitTime) {
        this.deployWaitTime = waitTime;
    }

    /**
     * Get the invoke wait time in seconds
     *
     * @return invoke wait time
     */
    public int getInvokeWaitTime() {
        return this.invokeWaitTime;
    }

    /**
     * Set the invoke wait time in seconds.
     *
     * @param waitTime Invoke wait time
     */
    public void setInvokeWaitTime(int waitTime) {
        logger.trace("setInvokeWaitTime is:" + waitTime);
        this.invokeWaitTime = waitTime;
    }

    /**
     * Get the key val store implementation (if any) that is currently associated with this chain.
     *
     * @returnsThe current KeyValStore associated with this chain, or undefined if not set.
     */
    public KeyValStore getKeyValStore() {
        return this.keyValStore;
    }

    /**
     * Set the key value store implementation.
     */
    public void setKeyValStore(KeyValStore keyValStore) {
        this.keyValStore = keyValStore;
    }

    /**
     * Get the tcert batch size.
     */
    public int getTCertBatchSize() {
        return this.tcertBatchSize;
    }

    /**
     * Set the tcert batch size.
     */
    public void setTCertBatchSize(int batchSize) {
        this.tcertBatchSize = batchSize;
    }


    public Chain initialize() throws InvalidArgumentException { //TODO for multi chain
        if (peers.size() == 0) {  // assume this makes no sense.  have no orders seems reasonable if all you do is query.

            throw new InvalidArgumentException("Chain needs at least one peer.");

        }
        if (nullOrEmptyString(name)) {

            throw new InvalidArgumentException("Chain initialized with null or empty name.");

        }
        if (client == null) {
            throw new InvalidArgumentException("Chain initialized with no client.");
        }

        if (this.client.getUserContext() == null) {

            throw new InvalidArgumentException("Chain initialized on HFClient with no user context.");
        }

        runEventQue();


        for (EventHub eh : eventHubs) {
            eh.connect();
        }


        registerTransactionListenerProcessor();


        this.initialized = true;

        return this;

    }


    private static Policy buildPolicyEnvelope(int nOf) {

        SignaturePolicy.NOutOf nOutOf = SignaturePolicy.NOutOf.newBuilder().setN(nOf).build();

        SignaturePolicy signaturePolicy = SignaturePolicy.newBuilder()
                .setFrom(nOutOf).build();

        SignaturePolicyEnvelope signaturePolicyEnvelope = SignaturePolicyEnvelope.newBuilder()
                .setVersion(0)
                .setPolicy(signaturePolicy).build();

        return Policy.newBuilder()
                .setType(Policy.PolicyType.SIGNATURE.getNumber())
                .setPolicy(signaturePolicyEnvelope.toByteString())
                .build();
    }


    private static SignedConfigurationItem buildSignedConfigurationItem(ChainHeader chainHeader, ConfigurationType type,
                                                                        long lastModified, String modificationPolicy,
                                                                        String key, ByteString value
    ) {
        return buildSignedConfigurationItem(chainHeader, type,
                lastModified, modificationPolicy,
                key, value,
                null);

    }

    private static SignedConfigurationItem buildSignedConfigurationItem(ChainHeader chainHeader, ConfigurationType type,
                                                                        long lastModified, String modificationPolicy,
                                                                        String key, ByteString value,
                                                                        ConfigurationSignature signatures) {


        ConfigurationItem configurationItem = ConfigurationItem.newBuilder()
                .setHeader(chainHeader)
                .setType(type)
                .setLastModified(lastModified)
                .setModificationPolicy(modificationPolicy)
                .setKey(key)
                .setValue(value)
                .build();

        SignedConfigurationItem.Builder signedConfigurationItem = SignedConfigurationItem.newBuilder();
        signedConfigurationItem.setConfigurationItem(configurationItem.toByteString());
        if (signatures != null) {
            signedConfigurationItem.addSignatures(signatures);
        }

        return signedConfigurationItem.build();
    }

    /**
     * Get the user with a given name
     *
     * @return user
     */
    public User getMember(String name) {
        if (null == keyValStore)
            throw new RuntimeException("No key value store was found.  You must first call Chain.setKeyValStore");
        if (null == memberServices)
            throw new RuntimeException("No user services was found.  You must first call Chain.setMemberServices or Chain.setMemberServicesUrl");

        // Try to get the user state from the cache
        User user = members.get(name);
        if (null != user) return user;

        // Create the user and try to restore it's state from the key value store (if found).
        user = new User(name, this);
        user.restoreState();
        return user;

    }

    /**
     * Get a user.
     * A user is a specific type of member.
     * Another type of member is a peer.
     */
    User getUser(String name) {
        return getMember(name);
    }


    /**
     * Register a user or other user type with the chain.
     *
     * @param registrationRequest Registration information.
     * @throws RegistrationException if the registration fails
     */
    public User register(RegistrationRequest registrationRequest) throws RegistrationException {
        User user = getMember(registrationRequest.getEnrollmentID());
        user.register(registrationRequest);
        return user;
    }

    /**
     * Enroll a user or other identity which has already been registered.
     *
     * @param name   The name of the user or other member to enroll.
     * @param secret The enrollment secret of the user or other member to enroll.
     * @throws EnrollmentException
     */

    public User enroll(String name, String secret) throws EnrollmentException {
        User user = getMember(name);
        if (!user.isEnrolled()) {
            user.enroll(secret);
        }
        enrollment = user.getEnrollment();

        members.put(name, user);

        return user;
    }

    /**
     * Register and enroll a user or other member type.
     * This assumes that a registrar with sufficient privileges has been set.
     *
     * @param registrationRequest Registration information.
     * @throws RegistrationException
     * @throws EnrollmentException
     */
    public User registerAndEnroll(RegistrationRequest registrationRequest) throws RegistrationException, EnrollmentException {
        User user = getMember(registrationRequest.getEnrollmentID());
        user.registerAndEnroll(registrationRequest);
        return user;
    }


    public Collection<Orderer> getOrderers() {
        return Collections.unmodifiableCollection(orderers);
    }

    /**
     * createNewInstance
     *
     * @param name
     * @return A new chain
     */
    public static Chain createNewInstance(String name, HFClient clientContext) throws InvalidArgumentException {
        return new Chain(name, clientContext);
    }


    public Collection<ProposalResponse> sendDeploymentProposal(DeploymentProposalRequest deploymentProposalRequest, Collection<Peer> peers) throws Exception {

        if (null == deploymentProposalRequest) {
            throw new InvalidArgumentException("sendDeploymentProposal deploymentProposalRequest is null");
        }
        if (null == peers) {
            throw new InvalidArgumentException("sendDeploymentProposal peers is null");
        }
        if (peers.isEmpty()) {
            throw new InvalidArgumentException("sendDeploymentProposal peers to send to is empty.");
        }
        if (!isInitialized()) {
            throw new DeploymentException("sendDeploymentProposal on chain not initialized.");
        }


        TransactionContext transactionContext = new TransactionContext(this, this.client.getUserContext(), cryptoPrimitives);
        DeploymentProposalBuilder deploymentProposalbuilder = DeploymentProposalBuilder.newBuilder();
        deploymentProposalbuilder.context(transactionContext);
        deploymentProposalbuilder.setChaincodeLanguage(deploymentProposalRequest.getChaincodeLanguage());
        deploymentProposalbuilder.argss(deploymentProposalRequest.getArgs());
        deploymentProposalbuilder.chaincodeName(deploymentProposalRequest.getChaincodeName());
        deploymentProposalbuilder.chaincodePath(deploymentProposalRequest.getChaincodePath());


        FabricProposal.Proposal deploymentProposal = deploymentProposalbuilder.build();
        FabricProposal.SignedProposal signedProposal = getSignedProposal(deploymentProposal);


        Collection<ProposalResponse> proposalResponses = new LinkedList<>();

        for (Peer peer : peers) {//TODO need to make async.

            FabricProposalResponse.ProposalResponse fabricResponse = peer.sendProposal(signedProposal);


            ProposalResponse proposalResponse = new ProposalResponse(transactionContext.getTxID(),
                    transactionContext.getChainID(), fabricResponse.getResponse().getStatus(),
                    fabricResponse.getResponse().getMessage());
            proposalResponse.setProposalResponse(fabricResponse);
            proposalResponse.setProposal(signedProposal);

            proposalResponse.verify();

            proposalResponses.add(proposalResponse);

        }

        return proposalResponses;
    }


    private FabricProposal.SignedProposal getSignedProposal(FabricProposal.Proposal deploymentProposal) throws CryptoException {
        byte[] ecdsaSignature = cryptoPrimitives.ecdsaSignToBytes(enrollment.getKey(), deploymentProposal.toByteArray());
        FabricProposal.SignedProposal.Builder signedProposal = FabricProposal.SignedProposal.newBuilder();


        signedProposal.setProposalBytes(deploymentProposal.toByteString());

        signedProposal.setSignature(ByteString.copyFrom(ecdsaSignature));
        return signedProposal.build();
    }

    private FabricProposal.SignedProposal signTransActionEnvelope(FabricProposal.Proposal deploymentProposal) throws CryptoException {
        byte[] ecdsaSignature = cryptoPrimitives.ecdsaSignToBytes(enrollment.getKey(), deploymentProposal.toByteArray());
        FabricProposal.SignedProposal.Builder signedProposal = FabricProposal.SignedProposal.newBuilder();


        signedProposal.setProposalBytes(deploymentProposal.toByteString());

        signedProposal.setSignature(ByteString.copyFrom(ecdsaSignature));
        return signedProposal.build();
    }


    public Collection<ProposalResponse> sendInvokeProposal(InvokeProposalRequest invokeProposalRequest, Collection<Peer> peers) throws Exception {


        return sendProposal(invokeProposalRequest, peers);
    }


    public Collection<ProposalResponse> sendQueryProposal(QueryProposalRequest queryProposalRequest, Collection<Peer> peers) throws Exception {

        return sendProposal(queryProposalRequest, peers);
    }

    private Collection<ProposalResponse> sendProposal(TransactionRequest queryProposalRequest, Collection<Peer> peers) throws Exception {

        if (null == queryProposalRequest) {
            throw new InvalidTransactionException("sendProposal queryProposalRequest is null");
        }
        if (null == peers) {
            throw new InvalidTransactionException("sendProposal peers is null");
        }
        if (peers.isEmpty()) {
            throw new InvalidTransactionException("sendProposal peers to send to is empty.");
        }
        if (!isInitialized()) {
            throw new InvalidTransactionException("sendProposal on chain not initialized.");
        }

        if (this.client.getUserContext() == null) {

            throw new InvalidTransactionException("sendProposal on chain not initialized.");
        }

        TransactionContext transactionContext = new TransactionContext(this, this.client.getUserContext(), cryptoPrimitives);
        ProposalBuilder proposalBuilder = ProposalBuilder.newBuilder();
        proposalBuilder.context(transactionContext);


        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom(queryProposalRequest.getFcn(), StandardCharsets.UTF_8));
        for (String arg : queryProposalRequest.getArgs()) {
            argList.add(ByteString.copyFrom(arg.getBytes()));
        }

        proposalBuilder.args(argList);
        proposalBuilder.chaincodeID(queryProposalRequest.getChaincodeID().getFabricChainCodeID());
        proposalBuilder.ccType(queryProposalRequest.getChaincodeLanguage() == TransactionRequest.Type.JAVA ?
                Chaincode.ChaincodeSpec.Type.JAVA : Chaincode.ChaincodeSpec.Type.GOLANG);


        FabricProposal.SignedProposal invokeProposal = getSignedProposal(proposalBuilder.build());


        Collection<ProposalResponse> proposalResponses = new LinkedList<>();
        for (Peer peer : peers) {//TODO need to make async.

            FabricProposalResponse.ProposalResponse fabricResponse = peer.sendProposal(invokeProposal);


            ProposalResponse proposalResponse = new ProposalResponse(transactionContext.getTxID(),
                    transactionContext.getChainID(), fabricResponse.getResponse().getStatus(),
                    fabricResponse.getResponse().getMessage());
            proposalResponse.setProposalResponse(fabricResponse);
            proposalResponse.setProposal(invokeProposal);

            proposalResponse.verify();

            proposalResponses.add(proposalResponse);


        }

        return proposalResponses;
    }


    /////////////////////////////////////////////////////////
    // transactions order


    public CompletableFuture<Envelope> sendTransaction(Collection<ProposalResponse> proposalResponses, Collection<Orderer> orderers) throws InvalidArgumentException, CryptoException, InvalidProtocolBufferException {

        if (null == proposalResponses) {

            throw new InvalidArgumentException("sendTransaction proposalResponses was null");
        }

        if (null == orderers) {
            throw new InvalidArgumentException("sendTransaction Orderers is null");
        }
        if (orderers.isEmpty()) {
            throw new InvalidArgumentException("sendTransaction Orderers to send to is empty.");
        }
        if (!isInitialized()) {
            throw new DeploymentException("sendTransaction on chain not initialized.");
        }


        List<FabricProposalResponse.Endorsement> ed = new LinkedList<>();
        FabricProposal.Proposal proposal = null;
        FabricProposal.ChaincodeProposalPayload proposalResponsePayload = null;
        String proposalTransactionID = null;



        for (ProposalResponse arg : proposalResponses) {
            ed.add(arg.getProposalResponse().getEndorsement());
            if (proposal == null) {

                proposal = arg.getProposal();
                proposalResponsePayload = FabricProposal.ChaincodeProposalPayload.parseFrom(arg.getProposalResponse().getPayload());
                proposalTransactionID = arg.getTransactionID();

            }
        }


        TransactionBuilder transactionBuilder = TransactionBuilder.newBuilder();
        TransactionContext transactionContext = new TransactionContext(proposalTransactionID, this, this.client.getUserContext(), cryptoPrimitives);

        Payload transactionPayload = transactionBuilder
                .hash(transactionContext.getCryptoPrimitives()::hash)
                .chaincodeProposal(proposal)
                .endorsements(ed)
                .proposalResponcePayload(proposalResponsePayload).build();


        Envelope transactionEnvelope = createTransactionEnvelop(transactionPayload);


        CompletableFuture<Envelope> sret = registerTxListener(proposalTransactionID);

        boolean success = false;
        for (Orderer orderer : orderers) {//TODO need to make async.

            BroadcastResponse resp = orderer.sendTransaction(transactionEnvelope);
            if (resp.getStatus() == Common.Status.SUCCESS) {

                success = true;
                break;

            }

            //TransactionResponse tresp = new TransactionResponse(transactionContext.getTxID(), transactionContext.getChainID(), resp.getStatusValue(), resp.getStatus().name());

        }

        if (success) {
            logger.debug(format("Successful sent to Orderer transaction id: %s", proposalTransactionID));
            return sret;
        } else {
            CompletableFuture<Envelope> ret = new CompletableFuture<>();
            ret.completeExceptionally(new Exception(format("Failed to place transaction %s on Orderer", proposalTransactionID )));
            return ret;
        }

    }


    private Envelope createTransactionEnvelop(Payload transactionPayload) throws CryptoException {

        Envelope.Builder ceb = Envelope.newBuilder();
        ceb.setPayload(transactionPayload.toByteString());

        byte[] ecdsaSignature = cryptoPrimitives.ecdsaSignToBytes(enrollment.getKey(), transactionPayload.toByteArray());
        ceb.setSignature(ByteString.copyFrom(ecdsaSignature));

        logger.debug("Done creating transaction ready for orderer");

        return ceb.build();
    }

    ////////////////  Chain Block monitoring //////////////////////////////////

    /**
     * registerBlockListener - Register a block listener.
     * @param listener
     * @return
     */
    public String registerBlockListener(BlockListener listener) {


        return new BL(listener).getHandle();

    }


    /**
     * A queue each eventing hub will write events to.
     */


    private final ChainEventQue chainEventQue = new ChainEventQue();


    public class ChainEventQue {

        private final BlockingQueue<Event> events = new LinkedBlockingQueue<>();//Thread safe
        private long previous = Long.MIN_VALUE;

        public boolean addBEvent(Event event) {

            //For now just support blocks --- other types are also reported as blocks.

            if (event.getEventCase() != EventCase.BLOCK) {
                return false;
            }

            Block block = event.getBlock();
            final long num = block.getHeader().getNumber();

            //If being fed by multiple eventhubs make sure we don't add dups here.
            synchronized (this) {
                if (num <= previous) {
                    return false; // seen it!
                }
                previous = num;


                events.add(event);
            }

            return true;

        }

        public Event getNextEvent() {
            Event ret = null;
            try {
                ret = events.take();
            } catch (InterruptedException e) {
                logger.warn(e);
            }

            return ret;
        }

    }

    private Runnable eventTask;
    //  private Runnable cleanUpTask;


    /**
     * Runs processing events from event hubs.
     */

    private void runEventQue() {

        eventTask = () -> {


            for (;;) {
                final Event event = chainEventQue.getNextEvent();
                if (event == null) {
                    continue;
                }


                final Block block = event.getBlock();

                BlockData data = block.getData();

                for (ByteString db : data.getDataList()) {

                    try {
                        Envelope env = Envelope.parseFrom(db);


                        Payload payload = Payload.parseFrom(env.getPayload());
                        Header plh = payload.getHeader();


                        String blockchainID = plh.getChainHeader().getChainID();

                        if (!Objects.equals(name, blockchainID)) {
                            continue; // not targeted for this chain
                        }

                        final ArrayList<BL> blcopy = new ArrayList<>(blockListeners.size() + 3);

                        synchronized (blockListeners) {

                            blcopy.addAll(blockListeners.values());
                        }


                        for (BL l : blcopy) {
                            try {

                                es.execute(() -> l.listener.received(event.getBlock()));

                            } catch (Throwable e) { //Don't let one register stop rest.
                                logger.error(e);
                            }

                        }


                    } catch (InvalidProtocolBufferException e) {
                        logger.error(e);

                    }

                }

            }

        };

        new Thread(eventTask).start();


//        Do our own time out. of tasks
//        cleanUpTask = () -> {
//
//
//            for (;;) {
//
//                synchronized (txListeners) {
//
//                    for (LinkedList<TL> tll : txListeners.values()) {
//
//                        if (tll == null) {
//                            continue;
//                        }
//
//                        for (TL tl : tll) {
//                            tl.timedOut();
//                        }
//                    }
//                }
//
//
//                try {
//                    Thread.sleep(1000);
//                } catch (InterruptedException e) {
//                    logger.error(e);
//
//                }
//
//            }
//
//        };
//
//
//        new Thread(cleanUpTask).start();
//
    }


    private final LinkedHashMap<String, BL> blockListeners = new LinkedHashMap<>();


    class BL {

        final BlockListener listener;

        public String getHandle() {
            return handle;
        }

        final String handle;

        BL(BlockListener listener) {

            handle = SDKUtil.generateUUID();

            this.listener = listener;
            synchronized (blockListeners) {

                blockListeners.put(handle, this);

            }

        }
    }


    //////////  Transaction monitoring  /////////////////////////////

    /**
     * Own block listener to manage transactions.
     *
     * @return
     */


    private String registerTransactionListenerProcessor() {

        //Transaction listener is internal Block listener for transactions

        return registerBlockListener(block -> {


            //System.err.println("Got BLOCK :" + block);
            if (txListeners.isEmpty()) {
                return;
            }


            BlockData data = block.getData();

            for (ByteString db : data.getDataList()) {

                try {
                    Envelope env = Envelope.parseFrom(db);


                    Payload payload = Payload.parseFrom(env.getPayload());
                    Header plh = payload.getHeader();


                    final String txID = plh.getChainHeader().getTxID();

                    logger.debug("Got Block with txID= " + txID);

                    List<TL> txL = new ArrayList<>(txListeners.size() + 2);


                    synchronized (txListeners) {

                        LinkedList<TL> list = txListeners.get(txID);
                        if (null != list) {
                            txL.addAll(list);
                        }

                    }

                    for (TL l : txL) {
                        try {
                            l.fire(env);
                        } catch (Throwable e) {
                            logger.error(e); //Don't let one register stop rest.
                        }
                    }


                } catch (InvalidProtocolBufferException e) {
                    logger.error(e);

                }


            }

        });
    }

    private final LinkedHashMap<String, LinkedList<TL>> txListeners = new LinkedHashMap<>();


    private class TL {
        final String txID;
        final AtomicBoolean fired = new AtomicBoolean(false);
        final CompletableFuture<Envelope> future;
//        final long createdTime = System.currentTimeMillis();//seconds
//        final long waitTime;


        TL(String txID, CompletableFuture<Envelope> future) {
            this.txID = txID;
            this.future = future;
//            if (waitTimeSeconds > 0) {
//                this.waitTime = waitTimeSeconds * 1000;
//            } else {
//                this.waitTime = -1;
//            }
            addListener();
        }

        private void addListener() {
            synchronized (txListeners) {
                LinkedList<TL> tl = txListeners.computeIfAbsent(txID, k -> new LinkedList<>());
                tl.add(this);
            }
        }

        public void fire(Envelope envelope) {

            if (fired.getAndSet(true)) {
                return;
            }

            synchronized (txListeners) {
                LinkedList<TL> l = txListeners.get(txID);
                if (null != l) {
                    l.removeFirstOccurrence(this);
                }
            }
            if (future.isDone()) {
                return;
            }

            es.execute(() -> future.complete(envelope));

        }

        //KEEP THIS FOR NOW in case in the future we decide we want it.

//        public boolean timedOut() {
//
//            if (fired.get()) {
//                return false;
//            }
//            if (waitTime == -1) {
//                return false;
//            }
//
//            if (createdTime + waitTime > System.currentTimeMillis()) {
//                return false;
//            }
//
//            LinkedList<TL> l = txListeners.get(txID);
//            if (null != l) {
//                l.removeFirstOccurrence(this);
//            }
//
//            logger.debug("timeout:" + txID);
//
//            if (fired.getAndSet(true)) {
//                return false;
//            }
//
//            es.execute(() -> {
//                future.completeExceptionally(new TimeoutException("Transaction " + txID + " timed out."));
//            });
//
//            return true;
//
//        }
    }

    /**
     * Register a transactionId that to get notification on when the event is seen in the block chain.
     *
     * @param txid
     * @return
     */

    public CompletableFuture<Envelope> registerTxListener(String txid) {

        CompletableFuture<Envelope> future = new CompletableFuture<>();

        new TL(txid, future);

        return future;


    }

}
