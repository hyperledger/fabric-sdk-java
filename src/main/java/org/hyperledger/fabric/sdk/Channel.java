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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.StatusRuntimeException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common.Block;
import org.hyperledger.fabric.protos.common.Common.BlockMetadata;
import org.hyperledger.fabric.protos.common.Common.ChannelHeader;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.common.Common.LastConfig;
import org.hyperledger.fabric.protos.common.Common.Metadata;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.common.Configtx.ConfigEnvelope;
import org.hyperledger.fabric.protos.common.Configtx.ConfigGroup;
import org.hyperledger.fabric.protos.common.Configtx.ConfigSignature;
import org.hyperledger.fabric.protos.common.Configtx.ConfigUpdateEnvelope;
import org.hyperledger.fabric.protos.common.Ledger;
import org.hyperledger.fabric.protos.common.Policies.Policy;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.msp.MspConfig;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.protos.orderer.Ab.SeekInfo;
import org.hyperledger.fabric.protos.orderer.Ab.SeekPosition;
import org.hyperledger.fabric.protos.orderer.Ab.SeekSpecified;
import org.hyperledger.fabric.protos.peer.Configuration.AnchorPeer;
import org.hyperledger.fabric.protos.peer.Configuration.AnchorPeers;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.Response;
import org.hyperledger.fabric.protos.peer.FabricTransaction.ProcessedTransaction;
import org.hyperledger.fabric.protos.peer.PeerEvents.Event.EventCase;
import org.hyperledger.fabric.protos.peer.Query;
import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.protos.peer.Query.ChaincodeQueryResponse;
import org.hyperledger.fabric.protos.peer.Query.ChannelQueryResponse;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.EventHubException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.transaction.InstallProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.InstantiateProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.JoinPeerProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.ProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.ProtoUtils;
import org.hyperledger.fabric.sdk.transaction.QueryInstalledChaincodesBuilder;
import org.hyperledger.fabric.sdk.transaction.QueryInstantiatedChaincodesBuilder;
import org.hyperledger.fabric.sdk.transaction.QueryPeerChannelsBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;
import org.hyperledger.fabric.sdk.transaction.UpgradeProposalBuilder;

import static java.lang.String.format;
import static org.hyperledger.fabric.protos.common.Common.HeaderType;
import static org.hyperledger.fabric.protos.common.Common.SignatureHeader;
import static org.hyperledger.fabric.protos.common.Common.Status;
import static org.hyperledger.fabric.protos.common.Configtx.ConfigValue;
import static org.hyperledger.fabric.protos.common.Policies.SignaturePolicy;
import static org.hyperledger.fabric.protos.common.Policies.SignaturePolicyEnvelope;
import static org.hyperledger.fabric.sdk.helper.Utils.checkGrpcUrl;
import static org.hyperledger.fabric.sdk.helper.Utils.toHexString;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createChannelHeader;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getCurrentFabricTimestamp;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getSignatureHeaderAsByteString;

/**
 * The class representing a channel with which the client SDK interacts.
 */
public class Channel {
    private static final Log logger = LogFactory.getLog(Channel.class);
    private final static boolean isDebugLevel = logger.isDebugEnabled();
    private static final Config config = Config.getConfig();
    static final String SYSTEM_CHANNEL_NAME = "";

    // Name of the channel is only meaningful to the client
    private String name;

    // The peers on this channel to which the client can connect
    private final Collection<Peer> peers = new Vector<>();

    // Security enabled flag
    private boolean securityEnabled = true;

    // Temporary variables to control how long to wait for deploy and invoke to complete before
    // emitting events.  This will be removed when the SDK is able to receive events from the
    private int deployWaitTime = 20;
    private int transactionWaitTime = 5;

    // contains the anchor peers parsed from the channel's configBlock
    private Set<Anchor> anchorPeers;

    // The crypto primitives object
    private CryptoSuite cryptoSuite;
    private final Collection<Orderer> orderers = new LinkedList<>();
    HFClient client;
    private boolean initialized = false;
    private int max_message_count = 50;
    private boolean shutdown = false;

    /**
     * Get eventHubs on the channel
     *
     * @return
     */
    public Collection<EventHub> getEventHubs() {
        return Collections.unmodifiableCollection(eventHubs);
    }

    private final Collection<EventHub> eventHubs = new LinkedList<>();
    private ExecutorService executorService;
    private Block genesisBlock;
    private final boolean systemChannel;

    ExecutorService getChannelExecutorService() {
        return executorService;
    }

    Channel(String name, HFClient hfClient, Orderer orderer, ChannelConfiguration channelConfiguration, byte[][] signers) throws InvalidArgumentException, TransactionException {
        this(name, hfClient, false);

        logger.debug(format("Creating new channel %s on the Fabric", name));

        try {
            Envelope ccEnvelope = Envelope.parseFrom(channelConfiguration.getChannelConfigurationAsBytes());

            final Payload ccPayload = Payload.parseFrom(ccEnvelope.getPayload());
            final ChannelHeader ccChannelHeader = ChannelHeader.parseFrom(ccPayload.getHeader().getChannelHeader());

            if (ccChannelHeader.getType() != HeaderType.CONFIG_UPDATE.getNumber()) {
                throw new InvalidArgumentException(format("Creating channel; %s expected config block type %s, but got: %s",
                        name,
                        HeaderType.CONFIG_UPDATE.name(),
                        HeaderType.forNumber(ccChannelHeader.getType())));
            }

            if (!name.equals(ccChannelHeader.getChannelId())) {

                throw new InvalidArgumentException(format("Expected config block for channel: %s, but got: %s", name,
                        ccChannelHeader.getChannelId()));
            }

            TransactionContext transactionContext = getTransactionContext();

            final ConfigUpdateEnvelope configUpdateEnv = ConfigUpdateEnvelope.parseFrom(ccPayload.getData());
            final ConfigUpdateEnvelope.Builder configUpdateEnvBuilder = configUpdateEnv.toBuilder();

            configUpdateEnvBuilder.clearSignatures();

            for (byte[] signer : signers) {

                configUpdateEnvBuilder.addSignatures(
                        ConfigSignature.parseFrom(signer));

            }

            //--------------
            // Construct Payload Envelope.

            final ByteString sigHeaderByteString = getSignatureHeaderAsByteString(transactionContext);

            final ChannelHeader payloadChannelHeader = ProtoUtils.createChannelHeader(HeaderType.CONFIG_UPDATE,
                    transactionContext.getTxID(), name, transactionContext.getEpoch(), transactionContext.getFabricTimestamp(), null);

            final Header payloadHeader = Header.newBuilder().setChannelHeader(payloadChannelHeader.toByteString())
                    .setSignatureHeader(sigHeaderByteString).build();

            final ByteString payloadByteString = Payload.newBuilder()
                    .setHeader(payloadHeader)
                    .setData(configUpdateEnvBuilder.build().toByteString())
                    .build().toByteString();

            ByteString payloadSignature = transactionContext.signByteStrings(payloadByteString);

            if (isDebugLevel) {
                logger.debug(format("Sending to orderer payloadSignature: 0x%s ", toHexString(payloadSignature)));
            }

            Envelope payloadEnv = Envelope.newBuilder()
                    .setSignature(payloadSignature)
                    .setPayload(payloadByteString).build();

            BroadcastResponse trxResult = orderer.sendTransaction(payloadEnv);
            if (200 != trxResult.getStatusValue()) {
                throw new TransactionException(format("New channel %s error. StatusValue %d. Status %s", name,
                        trxResult.getStatusValue(), "" + trxResult.getStatus()));
            }

            getGenesisBlock(orderer);
            if (genesisBlock == null) {
                throw new TransactionException(format("New channel %s error. Genesis bock returned null", name));
            }
            addOrderer(orderer);
            logger.debug(format("Created new channel %s on the Fabric done.", name));
        } catch (TransactionException e) {

            logger.error(format("Channel %s error: %s", name, e.getMessage()), e);
            throw e;
        } catch (Exception e) {
            String msg = format("Channel %s error: %s", name, e.getMessage());

            logger.error(msg, e);
            throw new TransactionException(msg, e);
        }

    }

    Enrollment getEnrollment() {
        return client.getUserContext().getEnrollment();
    }

    /**
     * For requests that are not targeted for a specific channel.
     * User's can not directly create this channel.
     *
     * @param client
     * @return
     * @throws InvalidArgumentException
     */

    static Channel newSystemChannel(HFClient client) throws InvalidArgumentException {
        return new Channel(null, client, true);
    }

    public boolean isInitialized() {
        return initialized;
    }

    Channel(String name, HFClient client) throws InvalidArgumentException {
        this(name, client, false);
    }

    /**
     * @param name
     * @param client
     */

    Channel(String name, HFClient client, final boolean systemChannel) throws InvalidArgumentException {

        this.systemChannel = systemChannel;

        if (systemChannel) {
            name = SYSTEM_CHANNEL_NAME;///It's special !
            initialized = true;
        } else {
            if (Utils.isNullOrEmpty(name)) {
                throw new InvalidArgumentException("Channel name is invalid can not be null or empty.");
            }
        }

        if (null == client) {
            throw new InvalidArgumentException("Channel client is invalid can not be null.");
        }
        this.name = name;
        this.client = client;
        this.executorService = client.getExecutorService();

        cryptoSuite = client.getCryptoSuite();

        if (null == cryptoSuite) {
            throw new InvalidArgumentException(format("CryptoPrimitives value in channel %s can not be null", name));
        }

        User user = client.getUserContext();
        if (null == user) {
            throw new InvalidArgumentException(format("User context in channel %s can not be null", name));
        }

        //enrollment = user.getEnrollment();

        if (null == client.getUserContext().getEnrollment()) {
            throw new InvalidArgumentException(format("User context %s is not enrolled.", name));
        }
        logger.debug(format("Creating channel: %s, client context %s", isSystemChannel() ? "SYSTEM_CHANNEL" : name, client.getUserContext().getName()));

    }

    /**
     * Get the channel name
     *
     * @return The name of the channel
     */
    public String getName() {
        return this.name;
    }

    /**
     * Add a peer to the channel
     *
     * @param peer The Peer to add.
     * @return Channel The current channel added.
     * @throws InvalidArgumentException
     */
    public Channel addPeer(Peer peer) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (null == peer) {
            throw new InvalidArgumentException("Peer is invalid can not be null.");
        }
        if (Utils.isNullOrEmpty(peer.getName())) {
            throw new InvalidArgumentException("Peer added to channel has no name.");
        }

        Exception e = checkGrpcUrl(peer.getUrl());
        if (e != null) {
            throw new InvalidArgumentException("Peer added to chan has invalid url.", e);
        }

        peer.setChannel(this);

        peers.add(peer);

        return this;
    }

    public Channel joinPeer(Peer peer) throws ProposalException {

        logger.debug(format("Channel %s joining peer %s, url: %s", name, peer.getName(), peer.getUrl()));

        if (shutdown) {
            throw new ProposalException(format("Channel %s has been shutdown.", name));
        }

        Channel peerChannel = peer.getChannel();
        if (null != peerChannel) {
            throw new ProposalException(format("Can not add peer %s to channel %s because it already belongs to channel %s.", peer.getName(), name, peerChannel));

        }

        if (genesisBlock == null && orderers.isEmpty()) {
            ProposalException e = new ProposalException("Channel missing genesis block and no orderers configured");
            logger.error(e.getMessage(), e);
        }
        try {

            genesisBlock = getGenesisBlock(orderers.iterator().next());
            logger.debug(format("Channel %s got genesis block", name));

            final Channel systemChannel = newSystemChannel(client); //channel is not really created and this is targeted to system channel

            TransactionContext transactionContext = systemChannel.getTransactionContext();

            FabricProposal.Proposal joinProposal = JoinPeerProposalBuilder.newBuilder()
                    .context(transactionContext)
                    .genesisBlock(genesisBlock)
                    .build();

            logger.debug("Getting signed proposal.");
            SignedProposal signedProposal = getSignedProposal(joinProposal);
            logger.debug("Got signed proposal.");

            Collection<ProposalResponse> resp = sendProposalToPeers(new ArrayList<>(Arrays.asList(peer)),
                    signedProposal, transactionContext);

            ProposalResponse pro = resp.iterator().next();

            if (pro.getStatus() == ProposalResponse.Status.SUCCESS) {
                logger.info(format("Peer %s joined into channel %s", peer.getName(), name));
                addPeer(peer);

            } else {
                throw new ProposalException(format("Join peer to channel %s failed.  Status %s, details: %s",
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
     * addOrderer - Add an Orderer to the channel
     *
     * @param orderer
     * @return
     * @throws InvalidArgumentException
     */

    public Channel addOrderer(Orderer orderer) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (null == orderer) {
            throw new InvalidArgumentException("Orderer is invalid can not be null.");
        }

        Exception e = checkGrpcUrl(orderer.getUrl());
        if (e != null) {
            throw new InvalidArgumentException("Peer added to chan has invalid url.", e);
        }

        logger.debug(format("Channel %s adding orderer%s, url: %s", name, orderer.getName(), orderer.getUrl()));

        orderer.setChannel(this);
        this.orderers.add(orderer);
        return this;
    }

    /**
     * Add eventhub to channel.
     *
     * @param eventHub
     * @return
     * @throws InvalidArgumentException
     */

    public Channel addEventHub(EventHub eventHub) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
        if (null == eventHub) {
            throw new InvalidArgumentException("EventHub is invalid can not be null.");
        }

        Exception e = checkGrpcUrl(eventHub.getUrl());
        if (e != null) {
            throw new InvalidArgumentException("Peer added to chan has invalid url.", e);
        }

        logger.debug(format("Channel %s adding event hub %s, url: %s", name, eventHub.getName(), eventHub.getUrl()));
        eventHub.setChannel(this);
        eventHub.setEventQue(channelEventQue);
        eventHubs.add(eventHub);
        return this;

    }

    /**
     * Get the peers for this channel.
     */
    public Collection<Peer> getPeers() {
        return Collections.unmodifiableCollection(this.peers);
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
     * Get the transaction wait time in seconds
     *
     * @return transaction wait time
     */
    public int getTransactionWaitTime() {
        return this.transactionWaitTime;
    }

    /**
     * Set the transaction wait time in seconds.
     *
     * @param waitTime Invoke wait time
     */
    public void setTransactionWaitTime(int waitTime) {
        logger.trace("setTransactionWaitTime is:" + waitTime);
        transactionWaitTime = waitTime;
    }

    /**
     * Initialize the Channel.  Starts the channel. event hubs will connect.
     *
     * @return
     * @throws InvalidArgumentException
     * @throws TransactionException
     */

    public Channel initialize() throws InvalidArgumentException, TransactionException {

        logger.debug(format("Channel %s initialize shutdown %b", name, shutdown));

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (peers.size() == 0) {

            throw new InvalidArgumentException("Channel needs at least one peer.");

        }
        if (Utils.isNullOrEmpty(name)) {

            throw new InvalidArgumentException("Can not initialize Channel without a valid name.");

        }
        if (client == null) {
            throw new InvalidArgumentException("Can not initialize channel without a client object.");
        }

        if (this.client.getUserContext() == null) {

            throw new InvalidArgumentException("Can not initialize the channel without a valid user context");
        }

        try {
            parseConfigBlock();// Parse config block for this channel to get it's information.

            loadCACertificates();  // put all MSP certs into cryptoSuite

            startEventQue(); //Run the event for event messages from event hubs.
            logger.debug(format("Eventque started %s", "" + eventQueueThread));

            for (EventHub eh : eventHubs) { //Connect all event hubs
                eh.connect(getTransactionContext());
            }

            logger.debug(format("%d eventhubs initialized", getEventHubs().size()));

            registerTransactionListenerProcessor(); //Manage transactions.
            logger.debug(format("Channel %s registerTransactionListenerProcessor completed", name));

            this.initialized = true;

            logger.debug(format("Channel %s initialized", name));

            return this;
        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            TransactionException exp = new TransactionException(e);
            logger.error(exp.getMessage(), exp);
            throw exp;
        }

    }

    /**
     * load the peer organizations CA certificates into the channel's trust store so that we
     * can verify signatures from peer messages
     *
     * @throws InvalidArgumentException
     * @throws CryptoException
     */
    private void loadCACertificates() throws InvalidArgumentException, CryptoException {
        logger.debug(format("Channel %s loadCACertificates", name));
        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Unable to load CA certificates. Channel " + name + " does not have a CryptoSuite.");
        }
        if (msps == null) {
            throw new InvalidArgumentException("Unable to load CA certificates. Channel " + name + " does not have any MSPs.");
        }

        List<byte[]> certList;
        for (MSP msp : msps.values()) {
            logger.debug("loading certificates for MSP : " + msp.getID());
            certList = Arrays.asList(msp.getRootCerts());
            if (certList.size() > 0) {
                cryptoSuite.loadCACertificatesAsBytes(certList);
            }
            certList = Arrays.asList(msp.getIntermediateCerts());
            if (certList.size() > 0) {
                cryptoSuite.loadCACertificatesAsBytes(certList);
            }
            // not adding admin certs. Admin certs should be signed by the CA
        }
        logger.debug(format("Channel %s loadCACertificates completed ", name));
    }

    private Block getGenesisBlock(Orderer order) throws TransactionException {
        try {
            if (genesisBlock != null) {
                logger.debug(format("Channel %s getGenesisBlock already present", name));

            } else {

                final long start = System.currentTimeMillis();

                do {

                    SeekSpecified seekSpecified = SeekSpecified.newBuilder()
                            .setNumber(0)
                            .build();
                    SeekPosition seekPosition = SeekPosition.newBuilder()
                            .setSpecified(seekSpecified)
                            .build();

                    SeekSpecified seekStopSpecified = SeekSpecified.newBuilder()
                            .setNumber(0)
                            .build();

                    SeekPosition seekStopPosition = SeekPosition.newBuilder()
                            .setSpecified(seekStopSpecified)
                            .build();

                    SeekInfo seekInfo = SeekInfo.newBuilder()
                            .setStart(seekPosition)
                            .setStop(seekStopPosition)
                            .setBehavior(SeekInfo.SeekBehavior.BLOCK_UNTIL_READY)
                            .build();

                    ChannelHeader deliverChainHeader = createChannelHeader(HeaderType.DELIVER_SEEK_INFO, "4",
                            name, 0, getCurrentFabricTimestamp(), null);

                    String mspid = client.getUserContext().getMSPID();
                    String cert = getEnrollment().getCert();

                    Identities.SerializedIdentity identity = Identities.SerializedIdentity.newBuilder()
                            .setIdBytes(ByteString.copyFromUtf8(cert)).
                                    setMspid(mspid).build();

                    SignatureHeader deliverSignatureHeader = SignatureHeader.newBuilder()
                            .setCreator(identity.toByteString())
                            .setNonce(ByteString.copyFrom(Utils.generateNonce()))
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

                    byte[] deliver_signature = cryptoSuite.sign(getEnrollment().getKey(), deliverPayload_bytes);

                    Envelope deliverEnvelope = Envelope.newBuilder()
                            .setSignature(ByteString.copyFrom(deliver_signature))
                            .setPayload(ByteString.copyFrom(deliverPayload_bytes))
                            .build();

                    DeliverResponse[] deliver = order.sendDeliver(deliverEnvelope);
                    if (deliver.length < 1) {
                        logger.warn(format("Genesis block for channel %s fetch bad deliver missing status block only got blocks:%d", name, deliver.length));
                        //odd so lets try again....
                    } else {

                        DeliverResponse status = deliver[0];
                        logger.debug(format("Channel %s getGenesisBlock deliver status: %d", name, status.getStatusValue()));
                        if (status.getStatusValue() == 404) {
                            logger.warn(format("Bad deliver expected status 200  got  %d, Channel %s", status.getStatusValue(), name));
                            // keep trying...
                        } else if (status.getStatusValue() != 200) {
                            throw new TransactionException(format("Bad deliver expected status 200  got  %d, Channel %s", status.getStatusValue(), name));

                        } else {

                            if (deliver.length < 2) {
                                logger.warn(format("Genesis block for channel %s fetch bad deliver missing genesis block only got %d:", name, deliver.length));
                                //odd try again
                            } else {

                                DeliverResponse blockresp = deliver[1];
                                genesisBlock = blockresp.getBlock();

                            }
                        }
                    }

                    if (genesisBlock == null) {
                        long now = System.currentTimeMillis();

                        long duration = now - start;

                        if (duration > config.getGenesisBlockWaitTime()) {
                            throw new TransactionException(format("Getting genesis block time exceeded %s seconds for channel %s", Long.toString(TimeUnit.MILLISECONDS.toSeconds(duration)), name));
                        }
                        try {
                            Thread.sleep(200);//try again
                        } catch (InterruptedException e) {
                            TransactionException te = new TransactionException("getGenesisBlock thread Sleep", e);
                            logger.warn(te.getMessage(), te);
                        }
                    }
                } while (genesisBlock == null);
            }
        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            TransactionException exp = new TransactionException("getGenesisBlock " + e.getMessage(), e);
            logger.error(exp.getMessage(), exp);
            throw exp;
        }

        if (genesisBlock == null) { //make sure it was really set.
            TransactionException exp = new TransactionException("getGenesisBlock returned null");
            logger.error(exp.getMessage(), exp);
            throw exp;

        }

        logger.debug(format("Channel %s getGenesisBlock done.", name));
        return genesisBlock;
    }

    Map<String, MSP> msps = new HashMap<>();

    boolean isSystemChannel() {
        return systemChannel;
    }

    /**
     * MSPs
     */

    class MSP {
        final String orgName;
        final MspConfig.FabricMSPConfig fabricMSPConfig;
        byte[][] adminCerts;
        byte[][] rootCerts;
        byte[][] intermediateCerts;

        MSP(String orgName, MspConfig.FabricMSPConfig fabricMSPConfig) {
            this.orgName = orgName;
            this.fabricMSPConfig = fabricMSPConfig;
        }

        /**
         * Known as the MSPID internally
         *
         * @return
         */

        String getID() {
            return fabricMSPConfig.getName();

        }

        /**
         * AdminCerts
         *
         * @return array of admin certs in PEM bytes format.
         */
        byte[][] getAdminCerts() {

            if (null == adminCerts) {
                adminCerts = new byte[fabricMSPConfig.getAdminsList().size()][];
                int i = 0;
                for (ByteString cert : fabricMSPConfig.getAdminsList()) {
                    adminCerts[i++] = cert.toByteArray();
                }
            }
            return adminCerts;
        }

        /**
         * RootCerts
         *
         * @return array of admin certs in PEM bytes format.
         */
        byte[][] getRootCerts() {

            if (null == rootCerts) {
                rootCerts = new byte[fabricMSPConfig.getRootCertsList().size()][];
                int i = 0;
                for (ByteString cert : fabricMSPConfig.getRootCertsList()) {
                    rootCerts[i++] = cert.toByteArray();
                }
            }

            return rootCerts;
        }

        /**
         * IntermediateCerts
         *
         * @return array of intermediate certs in PEM bytes format.
         */
        byte[][] getIntermediateCerts() {

            if (null == intermediateCerts) {
                intermediateCerts = new byte[fabricMSPConfig.getIntermediateCertsList().size()][];
                int i = 0;
                for (ByteString cert : fabricMSPConfig.getIntermediateCertsList()) {
                    intermediateCerts[i++] = cert.toByteArray();
                }
            }
            return intermediateCerts;
        }

    }

    /**
     * Anchor holds the info for the anchor peers as parsed from the configuration block
     */
    class Anchor {
        public String hostName;
        public int port;

        Anchor(String hostName, int port) throws InvalidArgumentException {
            this.hostName = hostName;
            this.port = port;
        }
    }

    protected void parseConfigBlock() throws TransactionException {

        try {

            final Block configBlock = getConfigurationBlock();

            logger.debug(format("Channel %s Got config block getting MSP data and anchorPeers data", name));

            Envelope envelope = Envelope.parseFrom(configBlock.getData().getData(0));
            Payload payload = Payload.parseFrom(envelope.getPayload());
            ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
            ConfigGroup channelGroup = configEnvelope.getConfig().getChannelGroup();
            Map<String, MSP> newMSPS = traverseConfigGroupsMSP("", channelGroup, new HashMap<>(20));

            msps = Collections.unmodifiableMap(newMSPS);

            anchorPeers = Collections.unmodifiableSet(traverseConfigGroupsAnchors("", channelGroup, new HashSet<>()));

        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

    }

    private Set<Anchor> traverseConfigGroupsAnchors(String name, ConfigGroup configGroup, Set<Anchor> anchorPeers) throws InvalidProtocolBufferException, InvalidArgumentException {
        ConfigValue anchorsConfig = configGroup.getValuesMap().get("AnchorPeers");
        if (anchorsConfig != null) {
            AnchorPeers anchors = AnchorPeers.parseFrom(anchorsConfig.getValue());
            for (AnchorPeer anchorPeer : anchors.getAnchorPeersList()) {
                String hostName = anchorPeer.getHost();
                int port = anchorPeer.getPort();
                logger.debug(format("parsed from config block: anchor peer %s:%d", hostName, port));
                anchorPeers.add(new Anchor(hostName, port));
            }
        }

        for (Map.Entry<String, ConfigGroup> gm : configGroup.getGroupsMap().entrySet()) {
            traverseConfigGroupsAnchors(gm.getKey(), gm.getValue(), anchorPeers);
        }

        return anchorPeers;
    }

    private Map<String, MSP> traverseConfigGroupsMSP(String name, ConfigGroup configGroup, Map<String, MSP> msps) throws InvalidProtocolBufferException {

        ConfigValue mspv = configGroup.getValuesMap().get("MSP");
        if (null != mspv) {
            if (!msps.containsKey(name)) {

                MspConfig.MSPConfig mspConfig = MspConfig.MSPConfig.parseFrom(mspv.getValue());

                MspConfig.FabricMSPConfig fabricMSPConfig = MspConfig.FabricMSPConfig.parseFrom(mspConfig.getConfig());

                msps.put(name, new MSP(name, fabricMSPConfig));

            }
        }

        for (Map.Entry<String, ConfigGroup> gm : configGroup.getGroupsMap().entrySet()) {
            traverseConfigGroupsMSP(gm.getKey(), gm.getValue(), msps);
        }

        return msps;
    }

    private Block getConfigurationBlock() throws TransactionException {

        logger.debug(format("getConfigurationBlock for channel %s", name));

        try {
            if (orderers.isEmpty()) {
                throw new TransactionException(format("No orderers for channel %s", name));
            }
            Orderer orderer = orderers.iterator().next();

            Block latestBlock = getLatestBlock(orderer);

            BlockMetadata blockMetadata = latestBlock.getMetadata();

            Metadata metaData = Metadata.parseFrom(blockMetadata.getMetadata(1));

            LastConfig lastConfig = LastConfig.parseFrom(metaData.getValue());

            long lastConfigIndex = lastConfig.getIndex();

            logger.debug(format("Last config index is %d", lastConfigIndex));

            Block configBlock = getBlockByNumber(lastConfigIndex);

            //Little extra parsing but make sure this really is a config block for this channel.
            Envelope envelopeRet = Envelope.parseFrom(configBlock.getData().getData(0));
            Payload payload = Payload.parseFrom(envelopeRet.getPayload());
            ChannelHeader channelHeader = ChannelHeader.parseFrom(payload.getHeader().getChannelHeader());
            if (channelHeader.getType() != HeaderType.CONFIG.getNumber()) {
                throw new TransactionException(format("Bad last configuration block type %d, expected %d",
                        channelHeader.getType(), HeaderType.CONFIG.getNumber()));
            }

            if (!name.equals(channelHeader.getChannelId())) {
                throw new TransactionException(format("Bad last configuration block channel id %s, expected %s",
                        channelHeader.getChannelId(), name));
            }

            logger.trace(format("Channel %s getConfigurationBlock returned %s", name, "" + configBlock));
            if (!logger.isTraceEnabled()) {
                logger.debug(format("Channel %s getConfigurationBlock returned", name));
            }

            return configBlock;

        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

    }

    private Block getBlockByNumber(final long number) throws TransactionException {

        logger.trace(format("getConfigurationBlock for channel %s", name));

        try {
            if (orderers.isEmpty()) {
                throw new TransactionException(format("No orderers for channel %s", name));
            }
            Orderer orderer = orderers.iterator().next();

            logger.trace(format("Last config index is %d", number));

            TransactionContext txContext = getTransactionContext();

            SeekSpecified seekSpecified = SeekSpecified.newBuilder().setNumber(number).build();

            SeekPosition seekPosition = SeekPosition.newBuilder()
                    .setSpecified(seekSpecified)
                    .build();

            SeekInfo seekInfo = SeekInfo.newBuilder()
                    .setStart(seekPosition)
                    .setStop(seekPosition)
                    .setBehavior(SeekInfo.SeekBehavior.BLOCK_UNTIL_READY)
                    .build();

            ChannelHeader seekInfoHeader = createChannelHeader(HeaderType.DELIVER_SEEK_INFO,
                    txContext.getTxID(), name, txContext.getEpoch(), getCurrentFabricTimestamp(), null);

            SignatureHeader signatureHeader = SignatureHeader.newBuilder()
                    .setCreator(txContext.getIdentity().toByteString())
                    .setNonce(txContext.getNonce())
                    .build();

            Header seekHeader = Header.newBuilder()
                    .setSignatureHeader(signatureHeader.toByteString())
                    .setChannelHeader(seekInfoHeader.toByteString())
                    .build();

            Payload seekPayload = Payload.newBuilder()
                    .setHeader(seekHeader)
                    .setData(seekInfo.toByteString())
                    .build();

            Envelope envelope = Envelope.newBuilder().setSignature(txContext.signByteString(seekPayload.toByteArray()))
                    .setPayload(seekPayload.toByteString())
                    .build();

            DeliverResponse[] deliver = orderer.sendDeliver(envelope);

            Block configBlock;
            if (deliver.length < 1) {
                throw new TransactionException(format("newest block for channel %s fetch bad deliver missing status block only got blocks:%d", name, deliver.length));

            } else {

                DeliverResponse status = deliver[0];
                if (status.getStatusValue() != 200) {
                    throw new TransactionException(format("Bad newest block expected status 200  got  %d, Channel %s", status.getStatusValue(), name));
                } else {
                    if (deliver.length < 2) {
                        throw new TransactionException(format("newest block for channel %s fetch bad deliver missing genesis block only got %d:", name, deliver.length));
                    } else {

                        DeliverResponse blockresp = deliver[1];
                        configBlock = blockresp.getBlock();

                        int dataCount = configBlock.getData().getDataCount();
                        if (dataCount < 1) {
                            throw new TransactionException(format("Bad config block data count %d", dataCount));
                        }
                    }
                }
            }

            if (configBlock == null) {
                throw new TransactionException(format("newest block for channel %s fetch bad deliver returned null:", name));
            }

            //getChannelConfig -  config block number ::%s  -- numberof tx :: %s', block.header.number, block.data.data.length)

            logger.trace(format("Received latest config block for channel %s, block no:%d, transaction count: %d",
                    name, configBlock.getHeader().getNumber(), configBlock.getData().getDataCount()));

            return configBlock;

        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

    }

    private Block getLatestBlock(Orderer orderer) throws CryptoException, TransactionException {

        logger.debug(format("getConfigurationBlock for channel %s", name));

        SeekPosition seekPosition = SeekPosition.newBuilder()
                .setNewest(Ab.SeekNewest.getDefaultInstance())
                .build();

        TransactionContext txContext = getTransactionContext();

        SeekInfo seekInfo = SeekInfo.newBuilder()
                .setStart(seekPosition)
                .setStop(seekPosition)
                .setBehavior(SeekInfo.SeekBehavior.BLOCK_UNTIL_READY)
                .build();

        ChannelHeader seekInfoHeader = createChannelHeader(HeaderType.DELIVER_SEEK_INFO,
                txContext.getTxID(), name, txContext.getEpoch(), getCurrentFabricTimestamp(), null);

        SignatureHeader signatureHeader = SignatureHeader.newBuilder()
                .setCreator(txContext.getIdentity().toByteString())
                .setNonce(txContext.getNonce())
                .build();

        Header seekHeader = Header.newBuilder()
                .setSignatureHeader(signatureHeader.toByteString())
                .setChannelHeader(seekInfoHeader.toByteString())
                .build();

        Payload seekPayload = Payload.newBuilder()
                .setHeader(seekHeader)
                .setData(seekInfo.toByteString())
                .build();

        Envelope envelope = Envelope.newBuilder().setSignature(txContext.signByteString(seekPayload.toByteArray()))
                .setPayload(seekPayload.toByteString())
                .build();

        DeliverResponse[] deliver = orderer.sendDeliver(envelope);

        Block latestBlock;
        if (deliver.length < 1) {
            throw new TransactionException(format("newest block for channel %s fetch bad deliver missing status block only got blocks:%d", name, deliver.length));

        } else {

            DeliverResponse status = deliver[0];
            logger.debug(format("Channel %s getLatestBlock returned status %s", name, status.getStatusValue()));
            if (status.getStatusValue() != 200) {
                throw new TransactionException(format("Bad newest block expected status 200  got  %d, Channel %s", status.getStatusValue(), name));
            } else {
                if (deliver.length < 2) {
                    throw new TransactionException(format("newest block for channel %s fetch bad deliver missing genesis block only got %d:", name, deliver.length));
                } else {

                    DeliverResponse blockresp = deliver[1];
                    latestBlock = blockresp.getBlock();
                }
            }
        }

        if (latestBlock == null) {
            throw new TransactionException(format("newest block for channel %s fetch bad deliver returned null:", name));
        }

        logger.trace(format("Received latest  block for channel %s, block no:%d", name, latestBlock.getHeader().getNumber()));
        return latestBlock;
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

    public Collection<Orderer> getOrderers() {
        return Collections.unmodifiableCollection(orderers);
    }

    /**
     * createNewInstance
     *
     * @param name
     * @return A new channel
     */
    static Channel createNewInstance(String name, HFClient clientContext) throws InvalidArgumentException {
        return new Channel(name, clientContext);
    }

    static Channel createNewInstance(String name, HFClient hfClient, Orderer orderer, ChannelConfiguration channelConfiguration, byte[]... signers) throws InvalidArgumentException, TransactionException {

        return new Channel(name, hfClient, orderer, channelConfiguration, signers);

    }

    /**
     * Send instantiate request to the channel. Chaincode is created and initialized.
     *
     * @param instantiateProposalRequest send instantiate chaincode proposal request.
     * @return Collections of proposal responses
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<ProposalResponse> sendInstantiationProposal(InstantiateProposalRequest instantiateProposalRequest) throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        return sendInstantiationProposal(instantiateProposalRequest, peers);
    }

    /**
     * Send instantiate request to the channel. Chaincode is created and initialized.
     *
     * @param instantiateProposalRequest
     * @param peers
     * @return
     * @throws IllegalArgumentException
     * @throws ProposalException
     */

    public Collection<ProposalResponse> sendInstantiationProposal(InstantiateProposalRequest instantiateProposalRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
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
            throw new InvalidArgumentException("sendDeploymentProposal on channel not initialized.");
        }

        try {
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
            instantiateProposalbuilder.setTransientMap(instantiateProposalRequest.getTransientMap());

            FabricProposal.Proposal instantiateProposal = instantiateProposalbuilder.build();
            SignedProposal signedProposal = getSignedProposal(instantiateProposal);

            return sendProposalToPeers(peers, signedProposal, transactionContext);
        } catch (Exception e) {
            throw new ProposalException(e);
        }
    }

    private TransactionContext getTransactionContext() {
        return getTransactionContext(client.getUserContext());
    }

    private TransactionContext getTransactionContext(User userContext) {
        return new TransactionContext(this, userContext, cryptoSuite);
    }

    /**
     * Send install chaincode request proposal to the channel.
     *
     * @param installProposalRequest
     * @param peers
     * @return
     * @throws ProposalException
     * @throws InvalidArgumentException
     */

    Collection<ProposalResponse> sendInstallProposal(InstallProposalRequest installProposalRequest, Collection<Peer> peers)
            throws ProposalException, InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
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
            throw new ProposalException("sendInstallProposal on channel not initialized.");
        }

        try {
            TransactionContext transactionContext = getTransactionContext();
            transactionContext.verify(false);  // Install will have no signing cause it's not really targeted to a channel.
            transactionContext.setProposalWaitTime(installProposalRequest.getProposalWaitTime());
            InstallProposalBuilder installProposalbuilder = InstallProposalBuilder.newBuilder();
            installProposalbuilder.context(transactionContext);
            installProposalbuilder.setChaincodeLanguage(installProposalRequest.getChaincodeLanguage());
            installProposalbuilder.chaincodeName(installProposalRequest.getChaincodeName());
            installProposalbuilder.chaincodePath(installProposalRequest.getChaincodePath());
            installProposalbuilder.chaincodeVersion(installProposalRequest.getChaincodeVersion());
            installProposalbuilder.setChaincodeSource(installProposalRequest.getChaincodeSourceLocation());
            installProposalbuilder.setChaincodeInputStream(installProposalRequest.getChaincodeInputStream());

            FabricProposal.Proposal deploymentProposal = installProposalbuilder.build();
            SignedProposal signedProposal = getSignedProposal(deploymentProposal);

            return sendProposalToPeers(peers, signedProposal, transactionContext);
        } catch (Exception e) {
            throw new ProposalException(e);
        }

    }

    /**
     * Send Upgrade proposal proposal to upgrade chaincode to a new version.
     *
     * @param upgradeProposalRequest
     * @return Collection of proposal responses.
     * @throws ProposalException
     * @throws InvalidArgumentException
     */

    public Collection<ProposalResponse> sendUpgradeProposal(UpgradeProposalRequest upgradeProposalRequest) throws ProposalException, InvalidArgumentException {

        return sendUpgradeProposal(upgradeProposalRequest, peers);

    }

    /**
     * Send Upgrade proposal proposal to upgrade chaincode to a new version.
     *
     * @param upgradeProposalRequest
     * @param peers                  the specific peers to send to.
     * @return Collection of proposal responses.
     * @throws ProposalException
     * @throws InvalidArgumentException
     */

    public Collection<ProposalResponse> sendUpgradeProposal(UpgradeProposalRequest upgradeProposalRequest, Collection<Peer> peers)
            throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
        if (null == upgradeProposalRequest) {
            throw new InvalidArgumentException("sendInstallProposal deploymentProposalRequest is null");
        }
        if (null == peers) {
            throw new InvalidArgumentException("sendInstallProposal peers is null");
        }
        if (peers.isEmpty()) {
            throw new InvalidArgumentException("sendInstallProposal peers to send to is empty.");
        }
        if (!isInitialized()) {
            throw new InvalidArgumentException("sendInstallProposal on channel not initialized.");
        }

        try {
            TransactionContext transactionContext = getTransactionContext();
            //transactionContext.verify(false);  // Install will have no signing cause it's not really targeted to a channel.
            transactionContext.setProposalWaitTime(upgradeProposalRequest.getProposalWaitTime());
            UpgradeProposalBuilder upgradeProposalBuilder = UpgradeProposalBuilder.newBuilder();
            upgradeProposalBuilder.context(transactionContext);
            upgradeProposalBuilder.argss(upgradeProposalRequest.getArgs());
            upgradeProposalBuilder.chaincodeName(upgradeProposalRequest.getChaincodeName());
            upgradeProposalBuilder.chaincodePath(upgradeProposalRequest.getChaincodePath());
            upgradeProposalBuilder.chaincodeVersion(upgradeProposalRequest.getChaincodeVersion());
            upgradeProposalBuilder.chaincodEndorsementPolicy(upgradeProposalRequest.getChaincodeEndorsementPolicy());

            SignedProposal signedProposal = getSignedProposal(upgradeProposalBuilder.build());

            return sendProposalToPeers(peers, signedProposal, transactionContext);
        } catch (Exception e) {
            throw new ProposalException(e);
        }
    }

    private SignedProposal getSignedProposal(FabricProposal.Proposal proposal) throws CryptoException {
        byte[] ecdsaSignature = cryptoSuite.sign(getEnrollment().getKey(), proposal.toByteArray());
        SignedProposal.Builder signedProposal = SignedProposal.newBuilder();

        signedProposal.setProposalBytes(proposal.toByteString());

        signedProposal.setSignature(ByteString.copyFrom(ecdsaSignature));
        return signedProposal.build();
    }

    private SignedProposal signTransActionEnvelope(FabricProposal.Proposal deploymentProposal) throws CryptoException {
        byte[] ecdsaSignature = cryptoSuite.sign(getEnrollment().getKey(), deploymentProposal.toByteArray());
        SignedProposal.Builder signedProposal = SignedProposal.newBuilder();

        signedProposal.setProposalBytes(deploymentProposal.toByteString());

        signedProposal.setSignature(ByteString.copyFrom(ecdsaSignature));
        return signedProposal.build();
    }

    /**
     * query this channel for a Block by the block hash.
     * The request is sent to a random peer in the channel.
     *
     * @param blockHash the hash of the Block in the chain
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByHash(byte[] blockHash) throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
        if (blockHash == null) {
            throw new InvalidArgumentException("blockHash parameter is null.");
        }
        if (getPeers().isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have peers associated with it.");
        }
        return queryBlockByHash(getPeers().iterator().next(), blockHash);
    }

    /**
     * query a peer in this channel for a Block by the block hash
     *
     * @param blockHash the hash of the Block in the chain
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByHash(Peer peer, byte[] blockHash) throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
        if (peer == null) {
            throw new InvalidArgumentException("Must give a peer to send request to.");
        }
        if (blockHash == null) {
            throw new InvalidArgumentException("blockHash parameter is null.");
        }
        if (!getPeers().contains(peer)) {
            throw new InvalidArgumentException("Channel " + name + " does not have peer " + peer.getName());
        }

        ProposalResponse proposalResponse;
        BlockInfo responseBlock;
        try {
            logger.debug("queryBlockByHash with hash : " + Hex.encodeHexString(blockHash) + "\n    to peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest();
            querySCCRequest.setFcn(QuerySCCRequest.GETBLOCKBYHASH);
            querySCCRequest.setArgs(new String[] {name});
            querySCCRequest.setArgBytes(new byte[][] {blockHash});

            Collection<ProposalResponse> proposalResponses = sendProposal(querySCCRequest, Collections.singletonList(peer));
            proposalResponse = proposalResponses.iterator().next();

            if (proposalResponse.getStatus().getStatus() != 200) {
                throw new PeerException(format("Unable to query block by hash %s %n.... for channel %s from peer %s \n    with message %s",
                        Hex.encodeHexString(blockHash),
                        name,
                        peer.getName(),
                        proposalResponse.getMessage()));
            }
            responseBlock = new BlockInfo(Block.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (Exception e) {
            String emsg = format("queryBlockByHash hash: %s peer %s channel %s error: %s",
                    Hex.encodeHexString(blockHash), peer.getName(), name, e.getMessage());
            logger.error(emsg, e);
            throw new ProposalException(emsg, e);
        }

        return responseBlock;
    }

    /**
     * query this channel for a Block by the blockNumber.
     * The request is sent to a random peer in the channel.
     *
     * @param blockNumber index of the Block in the chain
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(long blockNumber) throws InvalidArgumentException, ProposalException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (getPeers().isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have peers associated with it.");
        }
        return queryBlockByNumber(getPeers().iterator().next(), blockNumber);
    }

    /**
     * query a peer in this channel for a Block by the blockNumber
     *
     * @param peer        the peer to send the request to
     * @param blockNumber index of the Block in the chain
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(Peer peer, long blockNumber) throws InvalidArgumentException, ProposalException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
        if (peer == null) {
            throw new InvalidArgumentException("Must give a peer to send request to.");
        }
        if (!getPeers().contains(peer)) {
            throw new InvalidArgumentException("Channel " + name + " does not have peer " + peer.getName());
        }

        ProposalResponse proposalResponse;
        BlockInfo responseBlock;
        try {
            logger.debug("queryBlockByNumber with blockNumber " + blockNumber + " to peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest();
            querySCCRequest.setFcn(QuerySCCRequest.GETBLOCKBYNUMBER);
            querySCCRequest.setArgs(new String[] {name, Long.toUnsignedString(blockNumber)});

            Collection<ProposalResponse> proposalResponses = sendProposal(querySCCRequest, Collections.singletonList(peer));
            proposalResponse = proposalResponses.iterator().next();

            if (proposalResponse.getStatus().getStatus() != 200) {
                throw new PeerException(format("Unable to query block by number %d for channel %s from peer %s with message %s",
                        blockNumber,
                        name,
                        peer.getName(),
                        proposalResponse.getMessage()));
            }
            responseBlock = new BlockInfo(Block.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (Exception e) {
            String emsg = format("queryBlockByNumber blockNumber %d peer %s channel %s error %s",
                    blockNumber,
                    peer.getName(),
                    name,
                    e.getMessage());
            logger.error(emsg, e);
            throw new ProposalException(emsg, e);
        }

        return responseBlock;
    }

    /**
     * query this channel for a Block by a TransactionID contained in the block
     * The request is sent to a random peer in the channel
     *
     * @param txID the transactionID to query on
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(String txID) throws InvalidArgumentException, ProposalException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }
        if (getPeers().isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have peers associated with it.");
        }
        return queryBlockByTransactionID(getPeers().iterator().next(), txID);
    }

    /**
     * query a peer in this channel for a Block by a TransactionID contained in the block
     *
     * @param peer the peer to send the request to
     * @param txID the transactionID to query on
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(Peer peer, String txID) throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
        if (peer == null) {
            throw new InvalidArgumentException("Must give a peer to send request to.");
        }
        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }
        if (!peers.contains(peer)) {
            throw new InvalidArgumentException("Channel " + name + " does not have peer " + peer.getName());
        }

        ProposalResponse proposalResponse;
        BlockInfo responseBlock;
        try {
            logger.debug("queryBlockByTransactionID with txID " + txID + " \n    to peer" + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest();
            querySCCRequest.setFcn(QuerySCCRequest.GETBLOCKBYTXID);
            querySCCRequest.setArgs(new String[] {name, txID});

            Collection<ProposalResponse> proposalResponses = sendProposal(querySCCRequest, Collections.singletonList(peer));
            proposalResponse = proposalResponses.iterator().next();

            if (proposalResponse.getStatus().getStatus() != 200) {
                throw new PeerException(format("Unable to query block by TxID %s%n    for channel %s from peer %s with message %s",
                        txID,
                        name,
                        peer.getName(),
                        proposalResponse.getMessage()));
            }
            responseBlock = new BlockInfo(Block.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (Exception e) {
            String emsg = format("QueryBlockByTransactionID TxID %s%n peer %s channel %s error %s",
                    txID,
                    peer.getName(),
                    name,
                    e.getMessage());
            logger.error(emsg, e);
            throw new ProposalException(emsg, e);
        }

        return responseBlock;
    }

    /**
     * query this channel for chain information.
     * The request is sent to a random peer in the channel
     *
     * @return a {@link BlockchainInfo} object containing the chain info requested
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockchainInfo queryBlockchainInfo() throws ProposalException, InvalidArgumentException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (getPeers().isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have peers associated with it.");
        }
        return queryBlockchainInfo(getPeers().iterator().next());
    }

    /**
     * query for chain information
     *
     * @param peer The peer to send the request to
     * @return a {@link BlockchainInfo} object containing the chain info requested
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockchainInfo queryBlockchainInfo(Peer peer) throws ProposalException, InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (peer == null) {
            throw new InvalidArgumentException("Must give a peer to send request to.");
        }
        if (!peers.contains(peer)) {
            throw new InvalidArgumentException("Channel " + name + " does not have peer " + peer.getName());
        }

        BlockchainInfo response;
        try {
            logger.debug("queryBlockchainInfo to peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest();
            querySCCRequest.setFcn(QuerySCCRequest.GETCHAININFO);
            querySCCRequest.setArgs(new String[] {name});

            Collection<ProposalResponse> proposalResponses = sendProposal(querySCCRequest, Collections.singletonList(peer));
            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            if (proposalResponse.getStatus().getStatus() != 200) {
                throw new PeerException(format("Unable to query block channel info for channel %s from peer %s with message %s",
                        name,
                        peer.getName(),
                        proposalResponse.getMessage()));
            }
            response = new BlockchainInfo(Ledger.BlockchainInfo.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (Exception e) {
            String emsg = format("queryBlockchainInfo peer %s channel %s error %s",
                    peer.getName(),
                    name,
                    e.getMessage());
            logger.error(emsg, e);
            throw new ProposalException(emsg, e);
        }

        return response;
    }

    /**
     * Query this channel for a Fabric Transaction given its transactionID.
     * The request is sent to a random peer in the channel.
     *
     * @param txID the ID of the transaction
     * @return a {@link TransactionInfo}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    public TransactionInfo queryTransactionByID(String txID) throws ProposalException, InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }
        if (getPeers().isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have peers associated with it.");
        }
        return queryTransactionByID(getPeers().iterator().next(), txID);
    }

    /**
     * Query for a Fabric Transaction given its transactionID
     *
     * @param txID the ID of the transaction
     * @param peer the peer to send the request to
     * @return a {@link TransactionInfo}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    public TransactionInfo queryTransactionByID(Peer peer, String txID) throws ProposalException, InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (peer == null) {
            throw new InvalidArgumentException("Must give a peer to send request to.");
        }
        if (!peers.contains(peer)) {
            throw new InvalidArgumentException("Channel " + name + " does not have peer " + peer.getName());
        }
        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }

        TransactionInfo transactionInfo;
        try {
            logger.debug("queryTransactionByID with txID " + txID + "\n    from peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest();
            querySCCRequest.setFcn(QuerySCCRequest.GETTRANSACTIONBYID);
            querySCCRequest.setArgs(new String[] {name, txID});

            Collection<ProposalResponse> proposalResponses = sendProposal(querySCCRequest, Collections.singletonList(peer));
            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            if (proposalResponse.getStatus().getStatus() != 200) {
                throw new PeerException(format("Unable to query transaction info for ID %s%n for channel %s from peer %s with message %s",
                        txID,
                        name,
                        peer.getName(),
                        proposalResponse.getMessage()));
            }
            transactionInfo = new TransactionInfo(txID, ProcessedTransaction.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (Exception e) {
            String emsg = format("queryTransactionByID TxID %s%n peer %s channel %s error %s",
                    txID,
                    peer.getName(),
                    name,
                    e.getMessage());
            logger.error(emsg, e);
            throw new ProposalException(emsg, e);
        }

        return transactionInfo;
    }

    Set<String> queryChannels(Peer peer) throws InvalidArgumentException, ProposalException {

        if (peer == null) {
            throw new InvalidArgumentException("Must have peer to query.");
        }

        if (!isSystemChannel()) {
            throw new InvalidArgumentException("queryChannels should only be invoked on system channel.");
        }

        try {

            TransactionContext context = getTransactionContext();

            FabricProposal.Proposal q = QueryPeerChannelsBuilder.newBuilder().context(context).build();

            SignedProposal qProposal = getSignedProposal(q);
            Collection<ProposalResponse> proposalResponses = sendProposalToPeers(Collections.singletonList(peer), qProposal, context);

            if (null == proposalResponses) {
                throw new ProposalException(format("Peer %s channel query return with null for responses", peer.getName()));
            }

            if (proposalResponses.size() != 1) {

                throw new ProposalException(format("Peer %s channel query expected one response but got back %d  responses ", peer.getName(), proposalResponses.size()));
            }

            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            FabricProposalResponse.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) {//not likely but check it.
                throw new ProposalException(format("Peer %s channel query return with empty fabricResponseResponse", peer.getName()));
            }

            if (200 != fabricResponseResponse.getStatus()) {
                throw new ProposalException(format("Peer %s channel query expected 200, actual returned was: %d. "
                        + fabricResponseResponse.getMessage(), peer.getName(), fabricResponseResponse.getStatus()));

            }

            ChannelQueryResponse qr = ChannelQueryResponse.parseFrom(fabricResponseResponse.getPayload());

            Set<String> ret = new HashSet<>(qr.getChannelsCount());

            for (Query.ChannelInfo x : qr.getChannelsList()) {
                ret.add(x.getChannelId());

            }
            return ret;

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    List<ChaincodeInfo> queryInstalledChaincodes(Peer peer) throws InvalidArgumentException, ProposalException {

        if (peer == null) {
            throw new InvalidArgumentException("Must have peer to query.");
        }

        if (!isSystemChannel()) {
            throw new InvalidArgumentException("queryInstalledChaincodes should only be invoked on system channel.");
        }

        try {

            TransactionContext context = getTransactionContext();

            FabricProposal.Proposal q = QueryInstalledChaincodesBuilder.newBuilder().context(context).build();

            SignedProposal qProposal = getSignedProposal(q);
            Collection<ProposalResponse> proposalResponses = sendProposalToPeers(Collections.singletonList(peer), qProposal, context);

            if (null == proposalResponses) {
                throw new ProposalException(format("Peer %s channel query return with null for responses", peer.getName()));
            }

            if (proposalResponses.size() != 1) {

                throw new ProposalException(format("Peer %s channel query expected one response but got back %d  responses ", peer.getName(), proposalResponses.size()));
            }

            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            FabricProposalResponse.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) {//not likely but check it.
                throw new ProposalException(format("Peer %s channel query return with empty fabricResponseResponse", peer.getName()));
            }

            if (200 != fabricResponseResponse.getStatus()) {
                throw new ProposalException(format("Peer %s channel query expected 200, actual returned was: %d. "
                        + fabricResponseResponse.getMessage(), peer.getName(), fabricResponseResponse.getStatus()));

            }

            ChaincodeQueryResponse chaincodeQueryResponse = ChaincodeQueryResponse.parseFrom(fabricResponseResponse.getPayload());

            return chaincodeQueryResponse.getChaincodesList();

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    /**
     * Query peer for chaincode that has been instantiated
     *
     * @param peer The peer to query.
     * @return A list of ChaincodeInfo @see {@link ChaincodeInfo}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public List<ChaincodeInfo> queryInstantiatedChaincodes(Peer peer) throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (peer == null) {
            throw new InvalidArgumentException("Must have peer to query.");
        }

        try {

            TransactionContext context = getTransactionContext();

            FabricProposal.Proposal q = QueryInstantiatedChaincodesBuilder.newBuilder().context(context).build();

            SignedProposal qProposal = getSignedProposal(q);
            Collection<ProposalResponse> proposalResponses = sendProposalToPeers(Collections.singletonList(peer), qProposal, context);

            if (null == proposalResponses) {
                throw new ProposalException(format("Peer %s channel query return with null for responses", peer.getName()));
            }

            if (proposalResponses.size() != 1) {

                throw new ProposalException(format("Peer %s channel query expected one response but got back %d  responses ", peer.getName(), proposalResponses.size()));
            }

            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            FabricProposalResponse.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) {//not likely but check it.
                throw new ProposalException(format("Peer %s channel query return with empty fabricResponseResponse", peer.getName()));
            }

            if (200 != fabricResponseResponse.getStatus()) {
                throw new ProposalException(format("Peer %s channel query expected 200, actual returned was: %d. "
                        + fabricResponseResponse.getMessage(), peer.getName(), fabricResponseResponse.getStatus()));

            }

            ChaincodeQueryResponse chaincodeQueryResponse = ChaincodeQueryResponse.parseFrom(fabricResponseResponse.getPayload());

            return chaincodeQueryResponse.getChaincodesList();

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    /**
     * Send a transaction  proposal.
     *
     * @param transactionProposalRequest The transaction proposal to be sent to all the peers.
     * @return
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Collection<ProposalResponse> sendTransactionProposal(TransactionProposalRequest transactionProposalRequest) throws ProposalException, InvalidArgumentException {

        return sendProposal(transactionProposalRequest, peers);
    }

    /**
     * Send a transaction proposal to specific peers.
     *
     * @param transactionProposalRequest The transaction proposal to be sent to the peers.
     * @param peers
     * @return
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Collection<ProposalResponse> sendTransactionProposal(TransactionProposalRequest transactionProposalRequest, Collection<Peer> peers) throws ProposalException, InvalidArgumentException {

        return sendProposal(transactionProposalRequest, peers);
    }

    /**
     * Send Query proposal
     *
     * @param queryByChaincodeRequest
     * @return Collection proposal responses.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<ProposalResponse> queryByChaincode(QueryByChaincodeRequest queryByChaincodeRequest) throws InvalidArgumentException, ProposalException {
        return sendProposal(queryByChaincodeRequest, peers);
    }

    /**
     * Send Query proposal
     *
     * @param queryByChaincodeRequest
     * @param peers
     * @return
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<ProposalResponse> queryByChaincode(QueryByChaincodeRequest queryByChaincodeRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {
        return sendProposal(queryByChaincodeRequest, peers);
    }

    private Collection<ProposalResponse> sendProposal(TransactionRequest proposalRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (null == proposalRequest) {
            throw new InvalidArgumentException("sendProposal queryProposalRequest is null");
        }
        if (null == peers) {
            throw new InvalidArgumentException("sendProposal peers is null");
        }
        if (peers.isEmpty()) {
            throw new InvalidArgumentException("sendProposal peers to send to is empty.");
        }
        if (!isInitialized()) {
            throw new ProposalException("sendProposal on channel not initialized.");
        }

        if (this.client.getUserContext() == null) {
            throw new ProposalException("sendProposal on channel not initialized.");
        }

        try {
            TransactionContext transactionContext = getTransactionContext();
            transactionContext.verify(proposalRequest.doVerify());
            transactionContext.setProposalWaitTime(proposalRequest.getProposalWaitTime());

            // Protobuf message builder
            ProposalBuilder proposalBuilder = ProposalBuilder.newBuilder();
            proposalBuilder.context(transactionContext);
            proposalBuilder.request(proposalRequest);

            SignedProposal invokeProposal = getSignedProposal(proposalBuilder.build());
            return sendProposalToPeers(peers, invokeProposal, transactionContext);
        } catch (ProposalException e) {
            throw e;

        } catch (Exception e) {
            ProposalException exp = new ProposalException(e);
            logger.error(exp.getMessage(), exp);
            throw exp;
        }
    }

    private Collection<ProposalResponse> sendProposalToPeers(Collection<Peer> peers,
                                                             SignedProposal signedProposal,
                                                             TransactionContext transactionContext) throws PeerException, InvalidArgumentException, ProposalException {

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
            logger.debug(format("Channel %s send proposal to peer %s at url %s",
                    name, peer.getName(), peer.getUrl()));
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
                logger.debug(format("Channel %s got back from peer %s status: %d, message: %s",
                        name, peerFuturePair.peer.getName(), status, message));
            } catch (InterruptedException e) {
                message = "Sending proposal to " + peerFuturePair.peer.getName() + " failed because of interruption";
                status = 500;
                logger.error(message, e);
            } catch (TimeoutException e) {
                message = format("Sending proposal to " + peerFuturePair.peer.getName() + " failed because of timeout(%d milliseconds) expiration",
                        transactionContext.getProposalWaitTime());
                status = 500;
                logger.error(message, e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof Error) {
                    String emsg = "Sending proposal to " + peerFuturePair.peer.getName() + " failed because of " + cause.getMessage();
                    logger.error(emsg, new Exception(cause));//wrapped in exception to get full stack trace.
                    throw (Error) cause;
                } else {
                    if (cause instanceof StatusRuntimeException) {
                        message = format("Sending proposal to " + peerFuturePair.peer.getName() + " failed because of gRPC failure=%s",
                                ((StatusRuntimeException) cause).getStatus());
                    } else {
                        message = format("Sending proposal to " + peerFuturePair.peer.getName() + " failed because of %s", cause.getMessage());
                    }
                    status = 500;
                    logger.error(message, new Exception(cause));//wrapped in exception to get full stack trace.
                }
            }

            ProposalResponse proposalResponse = new ProposalResponse(transactionContext.getTxID(),
                    transactionContext.getChannelID(), status, message);
            proposalResponse.setProposalResponse(fabricResponse);
            proposalResponse.setProposal(signedProposal);
            proposalResponse.setPeer(peerFuturePair.peer);

            if (fabricResponse != null && transactionContext.getVerify()) {
                proposalResponse.verify(cryptoSuite);
            }

            proposalResponses.add(proposalResponse);
        }

        return proposalResponses;
    }

    /////////////////////////////////////////////////////////
    // transactions order

    /**
     * Send transaction to one of the orderers on the channels
     *
     * @param proposalResponses
     * @return
     */
    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses) {

        return sendTransaction(proposalResponses, orderers);

    }

    /**
     * Send transaction to orderer.
     *
     * @param proposalResponses
     * @param orderers
     * @return
     */

    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses, Collection<Orderer> orderers) {
        try {

            if (shutdown) {
                throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
            }

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
                throw new TransactionException("sendTransaction on channel not initialized.");
            }

            if (config.getProposalConsistencyValidation()) {

                if (1 != SDKUtils.getProposalConsistencySets(proposalResponses).size()) {
                    throw new IllegalArgumentException("The proposal responses do not have consistent read write sets");

                }

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
            logger.debug(format("Channel %s sending transaction to orderer(s) with TxID %s ", name, proposalTransactionID));

            boolean success = false;

            BroadcastResponse resp = null;
            for (Orderer orderer : orderers) {

                try {
                    resp = orderer.sendTransaction(transactionEnvelope);
                    if (resp.getStatus() == Status.SUCCESS) {

                        success = true;
                        break;

                    }
                } catch (Exception e) {
                    String emsg = format("Channel %s unsuccessful sendTransaction to orderer. Status %s", name, resp.getStatus());
                    logger.error(emsg);

                }

            }

            if (success) {
                logger.debug(format("Channel %s successful sent to Orderer transaction id: %s", name, proposalTransactionID));
                return sret;
            } else {
                String emsg = format("Channel %s failed to place transaction %s on Orderer. Cause: UNSUCCESSFUL", name, proposalTransactionID);
                CompletableFuture<TransactionEvent> ret = new CompletableFuture<>();
                ret.completeExceptionally(new Exception(emsg));
                return ret;
            }
        } catch (Exception e) {

            CompletableFuture<TransactionEvent> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;

        }

    }

    private Envelope createTransactionEnvelop(Payload transactionPayload) throws CryptoException {

        Envelope.Builder ceb = Envelope.newBuilder();
        ceb.setPayload(transactionPayload.toByteString());

        byte[] ecdsaSignature = cryptoSuite.sign(getEnrollment().getKey(), transactionPayload.toByteArray());
        ceb.setSignature(ByteString.copyFrom(ecdsaSignature));

        logger.debug("Done creating transaction ready for orderer");

        return ceb.build();
    }

    byte[] getChannelConfigurationSignature(ChannelConfiguration channelConfiguration, User signer) throws InvalidArgumentException {

        try {

            Envelope ccEnvelope = Envelope.parseFrom(channelConfiguration.getChannelConfigurationAsBytes());

            final Payload ccPayload = Payload.parseFrom(ccEnvelope.getPayload());

            TransactionContext transactionContext = getTransactionContext(signer);

            final ConfigUpdateEnvelope configUpdateEnv = ConfigUpdateEnvelope.parseFrom(ccPayload.getData());

            final ByteString configUpdate = configUpdateEnv.getConfigUpdate();

            ByteString sigHeaderByteString = getSignatureHeaderAsByteString(signer, transactionContext);

            ByteString signatureByteSting = transactionContext.signByteStrings(new User[] {signer},
                    sigHeaderByteString, configUpdate)[0];

            return ConfigSignature.newBuilder()
                    .setSignatureHeader(sigHeaderByteString)
                    .setSignature(signatureByteSting)
                    .build().toByteArray();

        } catch (Exception e) {

            throw new InvalidArgumentException(e);
        } finally {
            logger.debug("finally done");
        }

    }
    ////////////////  Channel Block monitoring //////////////////////////////////

    /**
     * registerBlockListener - Register a block listener.
     *
     * @param listener
     * @return
     */
    public String registerBlockListener(BlockListener listener) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        return new BL(listener).getHandle();

    }

    /**
     * A queue each eventing hub will write events to.
     */

    private final ChannelEventQue channelEventQue = new ChannelEventQue();

    class ChannelEventQue {

        private final BlockingQueue<BlockEvent> events = new LinkedBlockingQueue<>(); //Thread safe
        private Throwable eventException;

        void eventError(Throwable t) {
            eventException = t;
        }

        boolean addBEvent(BlockEvent event) {
            if (shutdown) {
                return false;
            }

            //For now just support blocks --- other types are also reported as blocks.

            if (event.getEvent().getEventCase() != EventCase.BLOCK) {
                return false;
            }

            Block block = event.getBlock();
            final long num = block.getHeader().getNumber();

            //If being fed by multiple eventhubs make sure we don't add dups here.
            synchronized (this) {

                events.add(event);
            }

            return true;

        }

        BlockEvent getNextEvent() throws EventHubException {
            if (shutdown) {
                throw new EventHubException(format("Channel %s has been shutdown", name));

            }
            BlockEvent ret = null;
            if (eventException != null) {
                throw new EventHubException(eventException);
            }
            try {
                ret = events.take();
            } catch (InterruptedException e) {
                if (shutdown) {
                    throw new EventHubException(eventException);

                } else {
                    logger.warn(e);
                    if (eventException != null) {

                        EventHubException eve = new EventHubException(eventException);
                        logger.error(eve.getMessage(), eve);
                        throw eve;
                    }
                }
            }

            if (eventException != null) {
                throw new EventHubException(eventException);
            }

            if (shutdown) {

                throw new EventHubException(format("Channel %s has been shutdown.", name));

            }

            return ret;
        }

    }

    /**
     * Runs processing events from event hubs.
     */

    Thread eventQueueThread = null;

    private void startEventQue() {

        if (eventQueueThread != null) {
            return;
        }

        executorService.execute(() -> {
            eventQueueThread = Thread.currentThread();

            while (!shutdown) {
                final BlockEvent blockEvent;
                try {
                    blockEvent = channelEventQue.getNextEvent();
                } catch (EventHubException e) {
                    if (!shutdown) {
                        logger.error(e);
                    }

                    continue;
                }
                if (blockEvent == null) {
                    continue;
                }

                try {

                    final String blockchainID = blockEvent.getChannelId();

                    if (!Objects.equals(name, blockchainID)) {
                        continue; // not targeted for this channel
                    }

                    final ArrayList<BL> blcopy = new ArrayList<>(blockListeners.size() + 3);
                    synchronized (blockListeners) {
                        blcopy.addAll(blockListeners.values());
                    }

                    for (BL l : blcopy) {
                        try {
                            executorService.execute(() -> l.listener.received(blockEvent));
                        } catch (Throwable e) { //Don't let one register stop rest.
                            logger.error("Error trying to call block listener on channel " + blockEvent.getChannelId(), e);
                        }
                    }
                } catch (Exception e) {
                    logger.error("Unable to parse event", e);
                    logger.debug("event:\n)");
                    logger.debug(blockEvent.toString());
                }
            }
        });

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

            handle = Utils.generateUUID();
            logger.debug(format("Channel %s blockListener %s starting", name, handle));

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

    private String registerTransactionListenerProcessor() throws InvalidArgumentException {
        logger.debug(format("Channel %s registerTransactionListenerProcessor starting", name));

        // Transaction listener is internal Block listener for transactions

        return registerBlockListener(blockEvent -> {

            if (txListeners.isEmpty()) {
                return;
            }

            for (TransactionEvent transactionEvent : blockEvent.getTransactionEvents()) {

                logger.debug(format("Channel %s got event for transaction %s ", name, transactionEvent.getTransactionID()));

                List<TL> txL = new ArrayList<>(txListeners.size() + 2);
                synchronized (txListeners) {
                    LinkedList<TL> list = txListeners.get(transactionEvent.getTransactionID());
                    if (null != list) {
                        txL.addAll(list);
                    }
                }

                for (TL l : txL) {
                    try {
                        // only if we get events from each eventhub on the channel fire the transactions event.
                        //   if (getEventHubs().containsAll(l.eventReceived(transactionEvent.getEventHub()))) {
                        if (getEventHubs().size() == l.eventReceived(transactionEvent.getEventHub()).size()) {
                            l.fire(transactionEvent);
                        }

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
        final Set<EventHub> seenEventHubs = Collections.synchronizedSet(new HashSet<>());
//        final long createdTime = System.currentTimeMillis();//seconds
//        final long waitTime;

        Set<EventHub> eventReceived(EventHub eventHub) {

            logger.debug(format("Channel %s seen transaction event %s for eventHub %s", name, txID, eventHub.toString()));
            seenEventHubs.add(eventHub);
            return seenEventHubs;
        }

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

        void fire(BlockEvent.TransactionEvent transactionEvent) {

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
                fired.set(true);
                return;
            }

            if (transactionEvent.isValid()) {
                executorService.execute(() -> future.complete(transactionEvent));
            } else {
                executorService.execute(() -> future.completeExceptionally(
                        new TransactionEventException(format("Received invalid transaction event. Transaction ID %s status %s",
                                transactionEvent.getTransactionID(),
                                transactionEvent.getValidationCode()),
                                transactionEvent)));
            }
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
//            executorService.execute(() -> {
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

    CompletableFuture<TransactionEvent> registerTxListener(String txid) {

        CompletableFuture<TransactionEvent> future = new CompletableFuture<>();

        new TL(txid, future);

        return future;

    }

    /**
     * Shutdown the channel with all resources released.
     *
     * @param force force immediate shutdown.
     */

    public synchronized void shutdown(boolean force) {

        if (shutdown) {
            return;
        }

        initialized = false;
        shutdown = true;
        anchorPeers = null;
        executorService = null;

        for (EventHub eh : getEventHubs()) {

            try {
                eh.shutdown();
            } catch (Exception e) {
                // Best effort.
            }

        }
        eventHubs.clear();
        for (Peer peer : getPeers()) {

            try {
                peer.shutdown(force);
            } catch (Exception e) {
                // Best effort.
            }
        }
        peers.clear();

        for (Orderer orderer : getOrderers()) {
            orderer.shutdown(force);
        }

        orderers.clear();

        if (eventQueueThread != null) {
            eventQueueThread.interrupt();
        }
        eventQueueThread = null;
    }

    @Override
    protected void finalize() throws Throwable {
        shutdown(true);
        super.finalize();

    }

}
