/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.StatusRuntimeException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.common.Common.ChannelHeader;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.common.Policies.Policy;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.protos.peer.PeerEvents.Event.EventCase;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.events.BlockListener;
import org.hyperledger.fabric.sdk.events.EventHub;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.InvalidTransactionException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.transaction.InstallProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.InstantiateProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.JoinPeerProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.ProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.ProtoUtils;
import org.hyperledger.fabric.sdk.transaction.TransactionBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;
import static org.hyperledger.fabric.protos.common.Common.HeaderType;
import static org.hyperledger.fabric.protos.common.Common.SignatureHeader;
import static org.hyperledger.fabric.protos.common.Common.Status;
import static org.hyperledger.fabric.protos.common.Policies.SignaturePolicy;
import static org.hyperledger.fabric.protos.common.Policies.SignaturePolicyEnvelope;
import static org.hyperledger.fabric.protos.peer.PeerEvents.Event;
import static org.hyperledger.fabric.sdk.helper.SDKUtil.checkGrpcUrl;
import static org.hyperledger.fabric.sdk.helper.SDKUtil.getNonce;
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
    private Block genesisBlock;

    Chain(String name, HFClient hfClient, Orderer orderer, ChainConfiguration chainConfiguration) throws InvalidArgumentException, TransactionException {
        this(name, hfClient);

        try {
            Envelope envelope = Envelope.parseFrom(chainConfiguration.getChainConfigurationAsBytes());

            BroadcastResponse trxResult = orderer.sendTransaction(envelope);
            if (200 != trxResult.getStatusValue()) {
                throw new TransactionException(format("New chain %s error. StatusValue %d. Status %s", name,
                        trxResult.getStatusValue(), "" + trxResult.getStatus()));
            }

            getGenesisBlock(orderer);
            if (genesisBlock == null) {
                throw new TransactionException(format("New chain %s error. Genesis bock returned null", name));
            }
            addOrderer(orderer);
        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e.getMessage(), e);
        }

    }


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
        keyValStore = client.getKeyValStore();
        if (null == keyValStore) {
            throw new InvalidArgumentException(format("Keystore value in chain %s can not be null", name));
        }

        memberServices = client.getMemberServices();

        if (null == memberServices) {
            throw new InvalidArgumentException(format("MemberServices value in chain %s can not be null", name));
        }

        cryptoPrimitives = client.getCryptoPrimitives();

        if (null == cryptoPrimitives) {
            throw new InvalidArgumentException(format("CryptoPrimitives value in chain %s can not be null", name));
        }

        User user = client.getUserContext();
        if (null == user) {
            throw new InvalidArgumentException(format("User context in chain %s can not be null", name));
        }

        enrollment = user.getEnrollment();

        if (null == enrollment) {
            throw new InvalidArgumentException(format("User in chain %s is not enrolled.", name));
        }

    }

    /**
     * Get the chain name
     *
     * @return The name of the chain
     */
    public String getName() {
        return this.name;
    }

    /**
     * Add a peer to the chain
     *
     * @param peer The Peer to add.
     * @return Chain The current chain added.
     * @throws InvalidArgumentException
     */
    public Chain addPeer(Peer peer) throws InvalidArgumentException {

        if (null == peer) {
            throw new InvalidArgumentException("Peer is invalid can not be null.");
        }
        if (nullOrEmptyString(peer.getName())) {
            throw new InvalidArgumentException("Peer added to chain has no name.");
        }

        Exception e = checkGrpcUrl(peer.getUrl());
        if (e != null) {
            throw new InvalidArgumentException("Peer added to chan has invalid url.", e);
        }

        peer.setChain(this);
        this.peers.add(peer);
        return this;
    }

    Chain joinPeer(Peer peer) throws ProposalException {
        if (genesisBlock == null && orderers.isEmpty()) {
            ProposalException e = new ProposalException("Chain missing genesis block and no orderers configured");
            logger.error(e.getMessage(), e);
        }
        try {

            genesisBlock = getGenesisBlock(orderers.iterator().next());

            peer.setChain(this);

            TransactionContext transactionContext = getTransactionContext();
            transactionContext.verify(false); // not targeted to a chain does not seem to be signed.

            FabricProposal.Proposal joinProposal = JoinPeerProposalBuilder.newBuilder()
                    .context(transactionContext)
                    .genesisBlock(genesisBlock)
                    .build();

            SignedProposal signedProposal = getSignedProposal(joinProposal);


            Collection<ProposalResponse> resp = sendProposalToPeers(new ArrayList<>(Arrays.asList(new Peer[]{peer})),
                    signedProposal, transactionContext);

            ProposalResponse pro = resp.iterator().next();

            if (pro.getStatus() == ProposalResponse.Status.SUCCESS) {
                logger.info(format("Peer %s joined into chain %s", peer.getName(), name));
                addPeer(peer);

            } else {
                throw new ProposalException(format("Join peer to chain %s failed.  Status %s, details: %s",
                        name, pro.getStatus().toString(), pro.getMessage()));

            }
        } catch (ProposalException e) {
            logger.error(e);
            throw e;
        } catch (Exception e) {
            logger.error(e);
            throw new ProposalException(e.getMessage(), e);
        }

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
            throw new InvalidArgumentException("EventHub is invalid can not be null.");
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
     * Get the member service associated this chain.
     *
     * @return MemberServices associated with the chain, or undefined if not set.
     */
    public MemberServices getMemberServices() {
        return this.memberServices;
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
     * @return The current KeyValStore associated with this chain, or undefined if not set.
     */
    KeyValStore getKeyValStore() {
        return this.keyValStore;
    }

//    /**
//     * Set the key value store implementation.
//     */
//    public void setKeyValStore(KeyValStore keyValStore) {
//        this.keyValStore = keyValStore;
//    }

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


    private Block getGenesisBlock(Orderer order) throws TransactionException {
        try {
            if (null == genesisBlock) {

                Ab.SeekSpecified seekSpecified = Ab.SeekSpecified.newBuilder()
                        .setNumber(0)
                        .build();
                Ab.SeekPosition seekPosition = Ab.SeekPosition.newBuilder()
                        .setSpecified(seekSpecified)
                        .build();

                Ab.SeekSpecified seekStopSpecified = Ab.SeekSpecified.newBuilder()
                        .setNumber(0)
                        .build();

                Ab.SeekPosition seekStopPosition = Ab.SeekPosition.newBuilder()
                        .setSpecified(seekStopSpecified)
                        .build();

                Ab.SeekInfo seekInfo = Ab.SeekInfo.newBuilder()
                        .setStart(seekPosition)
                        .setStop(seekStopPosition)
                        .setBehavior(Ab.SeekInfo.SeekBehavior.BLOCK_UNTIL_READY)
                        .build();

                ChannelHeader deliverChainHeader = ProtoUtils.createChannelHeader(HeaderType.DELIVER_SEEK_INFO, "4", name, 0, null);


                String mspid = getEnrollment().getMSPID();
                String cert = getEnrollment().getCert();

                Identities.SerializedIdentity identity = Identities.SerializedIdentity.newBuilder()
                        .setIdBytes(ByteString.copyFromUtf8(cert)).
                                setMspid(mspid).build();


                SignatureHeader deliverSignatureHeader = SignatureHeader.newBuilder()
                        .setCreator(identity.toByteString())
                        .setNonce(getNonce())
                        .build();

                Header deliverHeader = Header.newBuilder()
                        .setSignatureHeader(deliverSignatureHeader.toByteString())
                        .setChannelHeader(deliverChainHeader.toByteString())
                        .build();

                Payload deliverPayload = Payload.newBuilder()
                        .setHeader(deliverHeader)
                        .setData(seekInfo.toByteString())
                        .build();

                byte[] deliverPayload_bytes = deliverPayload.toByteArray();

                byte[] deliver_signature = cryptoPrimitives.ecdsaSignToBytes(enrollment.getKey(), deliverPayload_bytes);

                Envelope deliverEnvelope = Envelope.newBuilder()
                        .setSignature(ByteString.copyFrom(deliver_signature))
                        .setPayload(ByteString.copyFrom(deliverPayload_bytes))
                        .build();

                DeliverResponse[] deliver = order.sendDeliver(deliverEnvelope);
                if (deliver.length != 2) {
                    TransactionException exp = new TransactionException(format("Bad deliver expected 2 responses and got %d", deliver.length));
                    logger.error(exp.getMessage(), exp);
                    throw exp;
                }
                DeliverResponse status = deliver[0];//status is last
                if (status.getStatusValue() != 200) {
                    TransactionException exp = new TransactionException(format("Bad deliver expected status 200  got  %d, Chain %s" + status.getStatusValue(), name));
                    logger.error(exp.getMessage(), exp);
                    throw exp;
                }
                DeliverResponse blockresp = deliver[1];
                //
                //        BlockData blockData = block.getData();
                //        BlockHeader blockHeader = block.getHeader();
                //        BlockMetadata blockMetadata = block.getMetadata();
                //        int datacount = blockData.getDataCount();
                //        ByteString data = blockData.getData(0);
                //
                //        Envelope respEnv = Envelope.parseFrom(data);
                //        ByteString respPayload = respEnv.getPayload();
                //        Payload payLoad = Payload.parseFrom(respEnv.getPayload());
                //        ByteString payloaddata = payLoad.getData();
                //


                //        Configuration configurationEnvelope = Configuration.parseFrom(payLoad.getData());
                //        int itemsCount = configurationEnvelope.getItemsCount();
                //        System.out.println("respEnv:" + itemsCount);

                ///  Now do join peer proposal....


                genesisBlock = blockresp.getBlock();
            }
        } catch (CryptoException e) {
            TransactionException exp = new TransactionException("getGenesisBlock " + e.getMessage(), e);
            logger.error(exp.getMessage(), exp);
            throw exp;
        }
        if (genesisBlock == null) {

            TransactionException exp = new TransactionException("getGenesisBlock returned null");
            logger.error(exp.getMessage(), exp);
            throw exp;

        }
        return genesisBlock;
    }


    private static Policy buildPolicyEnvelope(int nOf) {

        SignaturePolicy.NOutOf nOutOf = SignaturePolicy.NOutOf.newBuilder().setN(nOf).build();

        SignaturePolicy signaturePolicy = SignaturePolicy.newBuilder().setNOutOf(nOutOf)
                .build();

        SignaturePolicyEnvelope signaturePolicyEnvelope = SignaturePolicyEnvelope.newBuilder()
                .setVersion(0)
                .setPolicy(signaturePolicy).build();

        return Policy.newBuilder()
                .setType(Policy.PolicyType.SIGNATURE.getNumber())
                .setPolicy(signaturePolicyEnvelope.toByteString())
                .build();
    }


//    private static SignedConfigurationItem buildSignedConfigurationItem(ChannelHeader chainHeader, ConfigurationType type,
//                                                                        long lastModified, String modificationPolicy,
//                                                                        String key, ByteString value
//    ) {
//        return buildSignedConfigurationItem(chainHeader, type,
//                lastModified, modificationPolicy,
//                key, value,
//                null);
//
//    }
//
//    private static SignedConfigurationItem buildSignedConfigurationItem(ChannelHeader chainHeader, ConfigurationType type,
//                                                                        long lastModified, String modificationPolicy,
//                                                                        String key, ByteString value,
//                                                                        ConfigurationSignature signatures) {
//
//
//
//
//
//        int configurationItem = Configtx.ConfigItem.newBuilder()
//
//                .setHeader(chainHeader)
//                .setType(type)
//                .setLastModified(lastModified)
//                .setModificationPolicy(modificationPolicy)
//                .setKey(key)
//                .setValue(value)
//                .build();
//
//        SignedConfigurationItem.Builder signedConfigurationItem = SignedConfigurationItem.newBuilder();
//        signedConfigurationItem.setConfigurationItem(configurationItem.toByteString());
//        if (signatures != null) {
//            signedConfigurationItem.addSignatures(signatures);
//        }
//
//        return signedConfigurationItem.build();
//    }

//    /**
//     * Get the user with a given name
//     *
//     * @return user
//     */
//    public User getMember(String name) {
//        if (null == keyValStore)
//            throw new RuntimeException("No key value store was found.  You must first call Chain.setKeyValStore");
//        if (null == memberServices)
//            throw new RuntimeException("No user services was found.  You must first call Chain.setMemberServices or Chain.setMemberServicesUrl");
//
//        // Try to get the user state from the cache
//        User user = members.get(name);
//        if (null != user) return user;
//
//        // Create the user and try to restore it's state from the key value store (if found).
//        user = new User(name, this);
//        user.restoreState();
//        return user;
//
//    }
//
////    /**
//     * Get a user.
//     * A user is a specific type of member.
//     * Another type of member is a peer.
//     */
//    User getUser(String name) {
//        return getMember(name);
//    }
//

//    /**
//     * Register a user or other user type with the chain.
//     *
//     * @param registrationRequest Registration information.
//     * @throws RegistrationException if the registration fails
//     */
//    public User register(RegistrationRequest registrationRequest) throws RegistrationException {
//        User user = getMember(registrationRequest.getEnrollmentID());
//        user.register(registrationRequest);
//        return user;
//    }
//
//    /**
//     * Enroll a user or other identity which has already been registered.
//     *
//     * @param name   The name of the user or other member to enroll.
//     * @param secret The enrollment secret of the user or other member to enroll.
//     * @throws EnrollmentException
//     */
//
//    public User enroll(String name, String secret) throws EnrollmentException {
//        User user = getMember(name);
//        if (!user.isEnrolled()) {
//            user.enroll(secret);
//        }
//        enrollment = user.getEnrollment();
//
//        members.put(name, user);
//
//        return user;
//    }
//
//    /**
//     * Register and enroll a user or other member type.
//     * This assumes that a registrar with sufficient privileges has been set.
//     *
//     * @param registrationRequest Registration information.
//     * @throws RegistrationException
//     * @throws EnrollmentException
//     */
//    public User registerAndEnroll(RegistrationRequest registrationRequest) throws RegistrationException, EnrollmentException {
//        User user = getMember(registrationRequest.getEnrollmentID());
//        user.registerAndEnroll(registrationRequest);
//        return user;
//    }
//

    public Collection<Orderer> getOrderers() {
        return Collections.unmodifiableCollection(orderers);
    }

    /**
     * createNewInstance
     *
     * @param name
     * @return A new chain
     */
    static Chain createNewInstance(String name, HFClient clientContext) throws InvalidArgumentException {
        return new Chain(name, clientContext);
    }

    static Chain createNewInstance(String name, HFClient hfClient, Orderer orderer, ChainConfiguration chainConfiguration) throws InvalidArgumentException, TransactionException {

        return new Chain(name, hfClient, orderer, chainConfiguration);

    }


    public Collection<ProposalResponse> sendInstantiationProposal(InstantiateProposalRequest instantiateProposalRequest, Collection<Peer> peers) throws Exception {

        if (null == instantiateProposalRequest) {
            throw new InvalidArgumentException("sendDeploymentProposal deploymentProposalRequest is null");
        }
        if (null == peers) {
            throw new InvalidArgumentException("sendDeploymentProposal peers is null");
        }
        if (peers.isEmpty()) {
            throw new InvalidArgumentException("sendDeploymentProposal peers to send to is empty.");
        }
        if (!isInitialized()) {
            throw new ProposalException("sendDeploymentProposal on chain not initialized.");
        }


        TransactionContext transactionContext = getTransactionContext();
        transactionContext.setProposalWaitTime(instantiateProposalRequest.getProposalWaitTime());
        InstantiateProposalBuilder instantiateProposalbuilder = InstantiateProposalBuilder.newBuilder();
        instantiateProposalbuilder.context(transactionContext);
        instantiateProposalbuilder.setChaincodeLanguage(instantiateProposalRequest.getChaincodeLanguage());
        instantiateProposalbuilder.argss(instantiateProposalRequest.getArgs());
        instantiateProposalbuilder.chaincodeName(instantiateProposalRequest.getChaincodeName());
        instantiateProposalbuilder.chaincodePath(instantiateProposalRequest.getChaincodePath());
        instantiateProposalbuilder.chaincodeVersion(instantiateProposalRequest.getChaincodeVersion());
        instantiateProposalbuilder.chaincodEndorsementPolicy(instantiateProposalRequest.getChaincodeEndorsementPolicy());


        FabricProposal.Proposal instantiateProposal = instantiateProposalbuilder.build();
        SignedProposal signedProposal = getSignedProposal(instantiateProposal);


        return sendProposalToPeers(peers, signedProposal, transactionContext);
    }

    private TransactionContext getTransactionContext() {
        return new TransactionContext(this, this.client.getUserContext(), cryptoPrimitives);
    }

    public Collection<ProposalResponse> sendInstallProposal(InstallProposalRequest installProposalRequest, Collection<Peer> peers)
            throws Exception {
        if (null == installProposalRequest) {
            throw new InvalidArgumentException("sendInstallProposal deploymentProposalRequest is null");
        }
        if (null == peers) {
            throw new InvalidArgumentException("sendInstallProposal peers is null");
        }
        if (peers.isEmpty()) {
            throw new InvalidArgumentException("sendInstallProposal peers to send to is empty.");
        }
        if (!isInitialized()) {
            throw new ProposalException("sendInstallProposal on chain not initialized.");
        }


        TransactionContext transactionContext = getTransactionContext();
        transactionContext.verify(false);  // Install will have no signing cause it's not really targeted to a chain.
        transactionContext.setProposalWaitTime(installProposalRequest.getProposalWaitTime());
        InstallProposalBuilder installProposalbuilder = InstallProposalBuilder.newBuilder();
        installProposalbuilder.context(transactionContext);
        installProposalbuilder.setChaincodeLanguage(installProposalRequest.getChaincodeLanguage());
        installProposalbuilder.chaincodeName(installProposalRequest.getChaincodeName());
        installProposalbuilder.chaincodePath(installProposalRequest.getChaincodePath());
        installProposalbuilder.chaincodeVersion(installProposalRequest.getChaincodeVersion());

        FabricProposal.Proposal deploymentProposal = installProposalbuilder.build();
        SignedProposal signedProposal = getSignedProposal(deploymentProposal);


        return sendProposalToPeers(peers, signedProposal, transactionContext);
    }


    private SignedProposal getSignedProposal(FabricProposal.Proposal proposal) throws CryptoException {
        byte[] ecdsaSignature = cryptoPrimitives.ecdsaSignToBytes(enrollment.getKey(), proposal.toByteArray());
        SignedProposal.Builder signedProposal = SignedProposal.newBuilder();


        signedProposal.setProposalBytes(proposal.toByteString());

        signedProposal.setSignature(ByteString.copyFrom(ecdsaSignature));
        return signedProposal.build();
    }

    private SignedProposal signTransActionEnvelope(FabricProposal.Proposal deploymentProposal) throws CryptoException {
        byte[] ecdsaSignature = cryptoPrimitives.ecdsaSignToBytes(enrollment.getKey(), deploymentProposal.toByteArray());
        SignedProposal.Builder signedProposal = SignedProposal.newBuilder();


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

        TransactionContext transactionContext = getTransactionContext();
        transactionContext.setProposalWaitTime(queryProposalRequest.getProposalWaitTime());
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


        SignedProposal invokeProposal = getSignedProposal(proposalBuilder.build());
        return sendProposalToPeers(peers, invokeProposal, transactionContext);
    }

    private Collection<ProposalResponse> sendProposalToPeers(Collection<Peer> peers,
                                                             SignedProposal signedProposal,
                                                             TransactionContext transactionContext) throws Exception {
        class Pair {
            private final Peer peer;
            private final Future<FabricProposalResponse.ProposalResponse> future;

            private Pair(Peer peer, Future<FabricProposalResponse.ProposalResponse> future) {
                this.peer = peer;
                this.future = future;
            }
        }
        List<Pair> peerFuturePairs = new ArrayList<>();
        for (Peer peer : peers) {
            peerFuturePairs.add(new Pair(peer, peer.sendProposalAsync(signedProposal)));
        }

        Collection<ProposalResponse> proposalResponses = new ArrayList<>();
        for (Pair peerFuturePair : peerFuturePairs) {
            FabricProposalResponse.ProposalResponse fabricResponse = null;
            String message;
            int status;
            try {
                fabricResponse = peerFuturePair.future.get(transactionContext.getProposalWaitTime(), TimeUnit.MILLISECONDS);
                message = fabricResponse.getResponse().getMessage();
                status = fabricResponse.getResponse().getStatus();
            } catch (InterruptedException e) {
                message = "Sending proposal to peer failed because of interruption";
                status = 500;
                logger.error(message, e);
            } catch (TimeoutException e) {
                message = format("Sending proposal to peer failed because of timeout(%d milliseconds) expiration",
                        transactionContext.getProposalWaitTime());
                status = 500;
                logger.error(message, e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof Error) {
                    logger.error(cause.getMessage(), new Exception(cause));//wrapped in exception to get full stack trace.
                    throw (Error) cause;
                } else {
                    if (cause instanceof StatusRuntimeException) {
                        message = format("Sending proposal to peer failed because of gRPC failure=%s",
                                ((StatusRuntimeException) cause).getStatus());
                    } else {
                        message = format("Sending proposal to peer failed because of %s", cause.getMessage());
                    }
                    status = 500;
                    logger.error(message, new Exception(cause));//wrapped in exception to get full stack trace.
                }
            }

            ProposalResponse proposalResponse = new ProposalResponse(transactionContext.getTxID(),
                    transactionContext.getChainID(), status, message);
            proposalResponse.setProposalResponse(fabricResponse);
            proposalResponse.setProposal(signedProposal);
            proposalResponse.setPeer(peerFuturePair.peer);

            if (fabricResponse != null && transactionContext.getVerify()) {
                proposalResponse.verify(cryptoPrimitives);
            }

            proposalResponses.add(proposalResponse);
        }

        return proposalResponses;
    }

    /////////////////////////////////////////////////////////
    // transactions order


    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses, Collection<Orderer> orderers) throws TransactionException {
        try {

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
                throw new TransactionException("sendTransaction on chain not initialized.");
            }


            List<FabricProposalResponse.Endorsement> ed = new LinkedList<>();
            FabricProposal.Proposal proposal = null;
            ByteString proposalResponsePayload = null;
            String proposalTransactionID = null;


            for (ProposalResponse sdkProposalResponse : proposalResponses) {
                ed.add(sdkProposalResponse.getProposalResponse().getEndorsement());
                if (proposal == null) {
                    proposal = sdkProposalResponse.getProposal();
                    proposalTransactionID = sdkProposalResponse.getTransactionID();
                    proposalResponsePayload = sdkProposalResponse.getProposalResponse().getPayload();

                }
            }


            TransactionBuilder transactionBuilder = TransactionBuilder.newBuilder();

            Payload transactionPayload = transactionBuilder
                    .chaincodeProposal(proposal)
                    .endorsements(ed)
                    .proposalResponsePayload(proposalResponsePayload).build();


            Envelope transactionEnvelope = createTransactionEnvelop(transactionPayload);


            CompletableFuture<TransactionEvent> sret = registerTxListener(proposalTransactionID);

            boolean success = false;
            Exception se = null;
            for (Orderer orderer : orderers) {

                try {
                    BroadcastResponse resp = orderer.sendTransaction(transactionEnvelope);
                    if (resp.getStatus() == Status.SUCCESS) {

                        success = true;
                        break;

                    }
                } catch (Exception e) {
                    se = e;
                    logger.error(e.getMessage(), e);

                }

                //TransactionResponse tresp = new TransactionResponse(transactionContext.getTxID(), transactionContext.getChainID(), resp.getStatusValue(), resp.getStatus().name());

            }

            if (success) {
                logger.debug(format("Successful sent to Orderer transaction id: %s", proposalTransactionID));
                return sret;
            } else {
                CompletableFuture<TransactionEvent> ret = new CompletableFuture<>();
                ret.completeExceptionally(new Exception(format("Failed to place transaction %s on Orderer. Cause: %s", proposalTransactionID, se.getMessage())));
                return ret;
            }
        } catch (Exception e) {
            throw new TransactionException("sendTransaction: " + e.getMessage(), e);
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
     *
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


            for (; ; ) {
                final Event event = chainEventQue.getNextEvent();
                if (event == null) {
                    continue;
                }

                try {
                    final BlockEvent blockEvent = new BlockEvent(event.getBlock());

                    String blockchainID = blockEvent.getChannelID();

                    if (!Objects.equals(name, blockchainID)) {
                        continue; // not targeted for this chain
                    }

                    final ArrayList<BL> blcopy = new ArrayList<>(blockListeners.size() + 3);
                    synchronized (blockListeners) {
                        blcopy.addAll(blockListeners.values());
                    }


                    for (BL l : blcopy) {
                        try {
                            es.execute(() -> l.listener.received(blockEvent));
                        } catch (Throwable e) { //Don't let one register stop rest.
                            logger.error("Error trying to call block listener on chain " + blockEvent.getChannelID(), e);
                        }
                    }
                } catch (InvalidProtocolBufferException e) {
                    logger.error("Unable to parse event", e);
                    logger.debug("event:\n)");
                    logger.debug(event.toString());
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

        // Transaction listener is internal Block listener for transactions

        return registerBlockListener(blockEvent -> {

            if (txListeners.isEmpty()) {
                return;
            }

            for (TransactionEvent transactionEvent : blockEvent.getTransactionEvents()) {

                logger.debug("Got event for transaction " + transactionEvent.getTransactionID());

                List<TL> txL = new ArrayList<>(txListeners.size() + 2);
                synchronized (txListeners) {
                    LinkedList<TL> list = txListeners.get(transactionEvent.getTransactionID());
                    if (null != list) {
                        txL.addAll(list);
                    }
                }

                for (TL l : txL) {
                    try {
                        l.fire(transactionEvent);
                    } catch (Throwable e) {
                        logger.error(e); // Don't let one register stop rest.
                    }
                }
            }
        });
    }

    private final LinkedHashMap<String, LinkedList<TL>> txListeners = new LinkedHashMap<>();


    private class TL {
        final String txID;
        final AtomicBoolean fired = new AtomicBoolean(false);
        final CompletableFuture<TransactionEvent> future;
//        final long createdTime = System.currentTimeMillis();//seconds
//        final long waitTime;


        TL(String txID, CompletableFuture<BlockEvent.TransactionEvent> future) {
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

        public void fire(BlockEvent.TransactionEvent transactionEvent) {

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

            if (transactionEvent.isValid())
                es.execute(() -> future.complete(transactionEvent));
            else
                es.execute(() -> future.completeExceptionally(
                        new TransactionEventException("Received invalid transaction event. Transaction ID : " + transactionEvent.getTransactionID(),
                                transactionEvent)));
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

    public CompletableFuture<TransactionEvent> registerTxListener(String txid) {

        CompletableFuture<TransactionEvent> future = new CompletableFuture<>();

        new TL(txid, future);

        return future;


    }

}
