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
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.common.Common.LastConfig;
import org.hyperledger.fabric.protos.common.Common.Metadata;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.common.Common.SignatureHeader;
import org.hyperledger.fabric.protos.common.Common.Status;
import org.hyperledger.fabric.protos.common.Configtx.ConfigEnvelope;
import org.hyperledger.fabric.protos.common.Configtx.ConfigGroup;
import org.hyperledger.fabric.protos.common.Configtx.ConfigSignature;
import org.hyperledger.fabric.protos.common.Configtx.ConfigUpdateEnvelope;
import org.hyperledger.fabric.protos.common.Configtx.ConfigValue;
import org.hyperledger.fabric.protos.common.Ledger;
import org.hyperledger.fabric.protos.msp.MspConfig;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.protos.orderer.Ab.SeekInfo;
import org.hyperledger.fabric.protos.orderer.Ab.SeekPosition;
import org.hyperledger.fabric.protos.orderer.Ab.SeekSpecified;
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
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.helper.Utils;
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
import static org.hyperledger.fabric.sdk.User.userContextCheck;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createChannelHeader;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getCurrentFabricTimestamp;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getSignatureHeaderAsByteString;

/**
 * The class representing a channel with which the client SDK interacts.
 * <p>
 */
public class Channel {
    private static final Log logger = LogFactory.getLog(Channel.class);
    private static final boolean IS_DEBUG_LEVEL = logger.isDebugEnabled();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final Config config = Config.getConfig();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;
    private static final String SYSTEM_CHANNEL_NAME = "";

    private static final long ORDERER_RETRY_WAIT_TIME = config.getOrdererRetryWaitTime();
    private static final long CHANNEL_CONFIG_WAIT_TIME = config.getChannelConfigWaitTime();

    // Name of the channel is only meaningful to the client
    private final String name;

    // The peers on this channel to which the client can connect
    private final Collection<Peer> peers = new Vector<>();

    // Temporary variables to control how long to wait for deploy and invoke to complete before
    // emitting events.  This will be removed when the SDK is able to receive events from the
    private int deployWaitTime = 20;
    private int transactionWaitTime = 5;

    // contains the anchor peers parsed from the channel's configBlock
//    private Set<Anchor> anchorPeers;

    // The crypto primitives object
    //   private CryptoSuite cryptoSuite;
    private final Collection<Orderer> orderers = new LinkedList<>();
    HFClient client;
    private boolean initialized = false;
    private boolean shutdown = false;

    /**
     * Get all Event Hubs on this channel.
     *
     * @return Event Hubs
     */
    public Collection<EventHub> getEventHubs() {
        return Collections.unmodifiableCollection(eventHubs);
    }

    private final Collection<EventHub> eventHubs = new LinkedList<>();
    private ExecutorService executorService;
    private Block genesisBlock;
    private final boolean systemChannel;

    private Channel(String name, HFClient hfClient, Orderer orderer, ChannelConfiguration channelConfiguration, byte[][] signers) throws InvalidArgumentException, TransactionException {
        this(name, hfClient, false);

        logger.debug(format("Creating new channel %s on the Fabric", name));

        Channel ordererChannel = orderer.getChannel();

        try {
            addOrderer(orderer);

            //-----------------------------------------
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

            final ConfigUpdateEnvelope configUpdateEnv = ConfigUpdateEnvelope.parseFrom(ccPayload.getData());
            ByteString configUpdate = configUpdateEnv.getConfigUpdate();

            sendUpdateChannel(configUpdate.toByteArray(), signers, orderer);
            //         final ConfigUpdateEnvelope.Builder configUpdateEnvBuilder = configUpdateEnv.toBuilder();

            //---------------------------------------

            //          sendUpdateChannel(channelConfiguration, signers, orderer);

            getGenesisBlock(orderer); // get Genesis block to make sure channel was created.
            if (genesisBlock == null) {
                throw new TransactionException(format("New channel %s error. Genesis bock returned null", name));
            }

            logger.debug(format("Created new channel %s on the Fabric done.", name));
        } catch (TransactionException e) {

            orderer.unsetChannel();
            if (null != ordererChannel) {
                orderer.setChannel(ordererChannel);
            }

            logger.error(format("Channel %s error: %s", name, e.getMessage()), e);
            throw e;
        } catch (Exception e) {
            orderer.unsetChannel();
            if (null != ordererChannel) {
                orderer.setChannel(ordererChannel);
            }
            String msg = format("Channel %s error: %s", name, e.getMessage());

            logger.error(msg, e);
            throw new TransactionException(msg, e);
        }

    }

    /**
     * Update channel with specified channel configuration
     *
     * @param updateChannelConfiguration Updated Channel configuration
     * @param signers                    signers
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public void updateChannelConfiguration(UpdateChannelConfiguration updateChannelConfiguration, byte[]... signers) throws TransactionException, InvalidArgumentException {

        updateChannelConfiguration(updateChannelConfiguration, getRandomOrderer(), signers);

    }

    /**
     * Update channel with specified channel configuration
     *
     * @param updateChannelConfiguration Channel configuration
     * @param signers                    signers
     * @param orderer                    The specific orderer to use.
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public void updateChannelConfiguration(UpdateChannelConfiguration updateChannelConfiguration, Orderer orderer, byte[]... signers) throws TransactionException, InvalidArgumentException {

        checkChannelState();

        checkOrderer(orderer);

        try {
            final long startLastConfigIndex = getLastConfigIndex(orderer);

            sendUpdateChannel(updateChannelConfiguration.getUpdateChannelConfigurationAsBytes(), signers, orderer);

            long currentLastConfigIndex = -1;
            final long nanoTimeStart = System.nanoTime();

            //Try to wait to see the channel got updated but don't fail if we don't see it.
            do {
                currentLastConfigIndex = getLastConfigIndex(orderer);
                if (currentLastConfigIndex == startLastConfigIndex) {

                    final long duration = TimeUnit.MILLISECONDS.convert(System.nanoTime() - nanoTimeStart, TimeUnit.NANOSECONDS);

                    if (duration > CHANNEL_CONFIG_WAIT_TIME) {
                        logger.warn(format("Channel %s did not get updated last config after %d ms", name, duration));
                        //waited long enough ..
                        currentLastConfigIndex = startLastConfigIndex; // just bail don't throw exception.
                    } else {

                        try {
                            Thread.sleep(ORDERER_RETRY_WAIT_TIME); //try again sleep
                        } catch (InterruptedException e) {
                            TransactionException te = new TransactionException("update channel thread Sleep", e);
                            logger.warn(te.getMessage(), te);
                        }
                    }

                }

            } while (currentLastConfigIndex == startLastConfigIndex);

        } catch (TransactionException e) {

            logger.error(format("Channel %s error: %s", name, e.getMessage()), e);
            throw e;
        } catch (Exception e) {
            String msg = format("Channel %s error: %s", name, e.getMessage());

            logger.error(msg, e);
            throw new TransactionException(msg, e);
        }

    }

    private void sendUpdateChannel(byte[] configupdate, byte[][] signers, Orderer orderer) throws TransactionException, InvalidArgumentException {

        logger.debug(format("Channel %s sendUpdateChannel", name));
        checkOrderer(orderer);

        try {

            final long nanoTimeStart = System.nanoTime();
            int statusCode = 0;

            do {

                //Make sure we have fresh transaction context for each try just to be safe.
                TransactionContext transactionContext = getTransactionContext();

                ConfigUpdateEnvelope.Builder configUpdateEnvBuilder = ConfigUpdateEnvelope.newBuilder();

                configUpdateEnvBuilder.setConfigUpdate(ByteString.copyFrom(configupdate));

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

                Envelope payloadEnv = Envelope.newBuilder()
                        .setSignature(payloadSignature)
                        .setPayload(payloadByteString).build();

                BroadcastResponse trxResult = orderer.sendTransaction(payloadEnv);

                statusCode = trxResult.getStatusValue();

                logger.debug(format("Channel %s sendUpdateChannel %d", name, statusCode));
                if (statusCode == 404 || statusCode == 503) {
                    // these we can retry..
                    final long duration = TimeUnit.MILLISECONDS.convert(System.nanoTime() - nanoTimeStart, TimeUnit.NANOSECONDS);

                    if (duration > CHANNEL_CONFIG_WAIT_TIME) {
                        //waited long enough .. throw an exception
                        throw new TransactionException(format("Channel %s update error timed out after %d ms. Status value %d. Status %s", name,
                                duration, statusCode, trxResult.getStatus().name()));
                    }

                    try {
                        Thread.sleep(ORDERER_RETRY_WAIT_TIME); //try again sleep
                    } catch (InterruptedException e) {
                        TransactionException te = new TransactionException("update thread Sleep", e);
                        logger.warn(te.getMessage(), te);
                    }

                } else if (200 != statusCode) {
                    // Can't retry.
                    throw new TransactionException(format("New channel %s error. StatusValue %d. Status %s", name,
                            statusCode, "" + trxResult.getStatus()));
                }

            } while (200 != statusCode); // try again

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
     * @return a new system channel.
     * @throws InvalidArgumentException
     */

    static Channel newSystemChannel(HFClient client) throws InvalidArgumentException {
        return new Channel(SYSTEM_CHANNEL_NAME, client, true);
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
     * @throws InvalidArgumentException
     */

    private Channel(String name, HFClient client, final boolean systemChannel) throws InvalidArgumentException {

        this.systemChannel = systemChannel;

        if (systemChannel) {
            name = SYSTEM_CHANNEL_NAME; //It's special !
            initialized = true;
        } else {
            if (isNullOrEmpty(name)) {
                throw new InvalidArgumentException("Channel name is invalid can not be null or empty.");
            }
        }

        if (null == client) {
            throw new InvalidArgumentException("Channel client is invalid can not be null.");
        }
        this.name = name;
        this.client = client;
        this.executorService = client.getExecutorService();

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
        if (null != peerChannel && peerChannel != this) {
            throw new ProposalException(format("Can not add peer %s to channel %s because it already belongs to channel %s.", peer.getName(), name, peerChannel.getName()));

        }

        if (genesisBlock == null && orderers.isEmpty()) {
            ProposalException e = new ProposalException("Channel missing genesis block and no orderers configured");
            logger.error(e.getMessage(), e);
        }
        try {

            genesisBlock = getGenesisBlock(getRandomOrderer());
            logger.debug(format("Channel %s got genesis block", name));

            final Channel systemChannel = newSystemChannel(client); //channel is not really created and this is targeted to system channel

            TransactionContext transactionContext = systemChannel.getTransactionContext();

            FabricProposal.Proposal joinProposal = JoinPeerProposalBuilder.newBuilder()
                    .context(transactionContext)
                    .genesisBlock(genesisBlock)
                    .build();

            logger.debug("Getting signed proposal.");
            SignedProposal signedProposal = getSignedProposal(transactionContext, joinProposal);
            logger.debug("Got signed proposal.");

            addPeer(peer); //need to add peer.

            Collection<ProposalResponse> resp = sendProposalToPeers(new ArrayList<>(Collections.singletonList(peer)),
                    signedProposal, transactionContext);

            ProposalResponse pro = resp.iterator().next();

            if (pro.getStatus() == ProposalResponse.Status.SUCCESS) {
                logger.info(format("Peer %s joined into channel %s", peer.getName(), name));
            } else {
                peers.remove(peer);
                peer.unsetChannel();
                throw new ProposalException(format("Join peer to channel %s failed.  Status %s, details: %s",
                        name, pro.getStatus().toString(), pro.getMessage()));

            }
        } catch (ProposalException e) {
            peers.remove(peer);
            peer.unsetChannel();
            logger.error(e);
            throw e;
        } catch (Exception e) {
            peers.remove(peer);
            peer.unsetChannel();
            logger.error(e);
            throw new ProposalException(e.getMessage(), e);
        }

        return this;
    }

    /**
     * Add an Orderer to this channel.
     *
     * @param orderer the orderer to add.
     * @return this channel.
     * @throws InvalidArgumentException
     */

    public Channel addOrderer(Orderer orderer) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (null == orderer) {
            throw new InvalidArgumentException("Orderer is invalid can not be null.");
        }

        logger.debug(format("Channel %s adding orderer%s, url: %s", name, orderer.getName(), orderer.getUrl()));

        orderer.setChannel(this);
        orderers.add(orderer);
        return this;
    }

    /**
     * Add an Event Hub to this channel.
     *
     * @param eventHub
     * @return this channel
     * @throws InvalidArgumentException
     */

    public Channel addEventHub(EventHub eventHub) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }
        if (null == eventHub) {
            throw new InvalidArgumentException("EventHub is invalid can not be null.");
        }

        logger.debug(format("Channel %s adding event hub %s, url: %s", name, eventHub.getName(), eventHub.getUrl()));
        eventHub.setChannel(this);
        eventHub.setEventQue(channelEventQue);
        eventHubs.add(eventHub);
        return this;

    }

    /**
     * Get the peers for this channel.
     *
     * @return the peers.
     */
    public Collection<Peer> getPeers() {
        return Collections.unmodifiableCollection(peers);
    }

    /**
     * Get the deploy wait time in seconds.
     *
     * @return number of seconds.
     */
    public int getDeployWaitTime() {
        return deployWaitTime;
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
     * @return this channel.
     * @throws InvalidArgumentException
     * @throws TransactionException
     */

    public Channel initialize() throws InvalidArgumentException, TransactionException {

        logger.debug(format("Channel %s initialize shutdown %b", name, shutdown));

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (isNullOrEmpty(name)) {

            throw new InvalidArgumentException("Can not initialize channel without a valid name.");

        }
        if (client == null) {
            throw new InvalidArgumentException("Can not initialize channel without a client object.");
        }

        userContextCheck(client.getUserContext());

        try {
            parseConfigBlock(); // Parse config block for this channel to get it's information.

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

        if (msps == null) {
            throw new InvalidArgumentException("Unable to load CA certificates. Channel " + name + " does not have any MSPs.");
        }

        List<byte[]> certList;
        for (MSP msp : msps.values()) {
            logger.debug("loading certificates for MSP : " + msp.getID());
            certList = Arrays.asList(msp.getRootCerts());
            if (certList.size() > 0) {
                client.getCryptoSuite().loadCACertificatesAsBytes(certList);
            }
            certList = Arrays.asList(msp.getIntermediateCerts());
            if (certList.size() > 0) {
                client.getCryptoSuite().loadCACertificatesAsBytes(certList);
            }
            // not adding admin certs. Admin certs should be signed by the CA
        }
        logger.debug(format("Channel %s loadCACertificates completed ", name));
    }

    private Block getGenesisBlock(Orderer orderer) throws TransactionException {
        try {
            if (genesisBlock != null) {
                logger.debug(format("Channel %s getGenesisBlock already present", name));

            } else {

                final long start = System.currentTimeMillis();

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

                ArrayList<DeliverResponse> deliverResponses = new ArrayList<>();

                seekBlock(seekInfo, deliverResponses, orderer);

                DeliverResponse blockresp = deliverResponses.get(1);
                Block configBlock = blockresp.getBlock();
                if (configBlock == null) {
                    throw new TransactionException(format("In getGenesisBlock newest block for channel %s fetch bad deliver returned null:", name));
                }

                int dataCount = configBlock.getData().getDataCount();
                if (dataCount < 1) {
                    throw new TransactionException(format("In getGenesisBlock bad config block data count %d", dataCount));
                }

                genesisBlock = blockresp.getBlock();

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

    private Map<String, MSP> msps = new HashMap<>();

    boolean isSystemChannel() {
        return systemChannel;
    }

    public boolean isShutdown() {
        return shutdown;
    }

    public byte[] getUpdateChannelConfigurationSignature(UpdateChannelConfiguration updateChannelConfiguration, User signer) throws InvalidArgumentException {

        userContextCheck(signer);

        if (null == updateChannelConfiguration) {

            throw new InvalidArgumentException("channelConfiguration is null");

        }

        try {

            TransactionContext transactionContext = getTransactionContext(signer);

            final ByteString configUpdate = ByteString.copyFrom(updateChannelConfiguration.getUpdateChannelConfigurationAsBytes());

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

//    /**
//     * Anchor holds the info for the anchor peers as parsed from the configuration block
//     */
//    class Anchor {
//        public String hostName;
//        public int port;
//
//        Anchor(String hostName, int port) throws InvalidArgumentException {
//            this.hostName = hostName;
//            this.port = port;
//        }
//    }

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

//            anchorPeers = Collections.unmodifiableSet(traverseConfigGroupsAnchors("", channelGroup, new HashSet<>()));

        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

    }

//    private Set<Anchor> traverseConfigGroupsAnchors(String name, ConfigGroup configGroup, Set<Anchor> anchorPeers) throws InvalidProtocolBufferException, InvalidArgumentException {
//        ConfigValue anchorsConfig = configGroup.getValuesMap().get("AnchorPeers");
//        if (anchorsConfig != null) {
//            AnchorPeers anchors = AnchorPeers.parseFrom(anchorsConfig.getValue());
//            for (AnchorPeer anchorPeer : anchors.getAnchorPeersList()) {
//                String hostName = anchorPeer.getHost();
//                int port = anchorPeer.getPort();
//                logger.debug(format("parsed from config block: anchor peer %s:%d", hostName, port));
//                anchorPeers.add(new Anchor(hostName, port));
//            }
//        }
//
//        for (Map.Entry<String, ConfigGroup> gm : configGroup.getGroupsMap().entrySet()) {
//            traverseConfigGroupsAnchors(gm.getKey(), gm.getValue(), anchorPeers);
//        }
//
//        return anchorPeers;
//    }

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

    /**
     * Provide the Channel's latest raw Configuration Block.
     *
     * @return Channel configuration block.
     * @throws TransactionException
     */

    private Block getConfigurationBlock() throws TransactionException {

        logger.debug(format("getConfigurationBlock for channel %s", name));

        try {
            Orderer orderer = getRandomOrderer();

            long lastConfigIndex = getLastConfigIndex(orderer);

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

            logger.trace(format("Channel %s getConfigurationBlock returned %s", name, String.valueOf(configBlock)));
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

    /**
     * Channel Configuration bytes. Bytes that can be used with configtxlator tool to upgrade the channel.
     * Convert to Json for editing  with:
     * {@code
     * <p>
     * curl -v   POST --data-binary @fooConfig http://host/protolator/decode/common.Config
     * <p>
     * }
     * See http://hyperledger-fabric.readthedocs.io/en/latest/configtxlator.html
     *
     * @return Channel configuration bytes.
     * @throws TransactionException
     */

    public byte[] getChannelConfigurationBytes() throws TransactionException {
        try {
            final Block configBlock = getConfigurationBlock();

            Envelope envelopeRet = Envelope.parseFrom(configBlock.getData().getData(0));

            Payload payload = Payload.parseFrom(envelopeRet.getPayload());

            ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
            return configEnvelope.getConfig().toByteArray();

        } catch (Exception e) {
            throw new TransactionException(e);
        }

    }

    private long getLastConfigIndex(Orderer orderer) throws CryptoException, TransactionException, InvalidArgumentException, InvalidProtocolBufferException {
        Block latestBlock = getLatestBlock(orderer);

        BlockMetadata blockMetadata = latestBlock.getMetadata();

        Metadata metaData = Metadata.parseFrom(blockMetadata.getMetadata(1));

        LastConfig lastConfig = LastConfig.parseFrom(metaData.getValue());

        return lastConfig.getIndex();
    }

    private Block getBlockByNumber(final long number) throws TransactionException {

        logger.trace(format("getConfigurationBlock for channel %s", name));

        try {

            logger.trace(format("Last config index is %d", number));

            SeekSpecified seekSpecified = SeekSpecified.newBuilder().setNumber(number).build();

            SeekPosition seekPosition = SeekPosition.newBuilder()
                    .setSpecified(seekSpecified)
                    .build();

            SeekInfo seekInfo = SeekInfo.newBuilder()
                    .setStart(seekPosition)
                    .setStop(seekPosition)
                    .setBehavior(SeekInfo.SeekBehavior.BLOCK_UNTIL_READY)
                    .build();

            ArrayList<DeliverResponse> deliverResponses = new ArrayList<>();

            seekBlock(seekInfo, deliverResponses, getRandomOrderer());

            DeliverResponse blockresp = deliverResponses.get(1);

            Block retBlock = blockresp.getBlock();
            if (retBlock == null) {
                throw new TransactionException(format("newest block for channel %s fetch bad deliver returned null:", name));
            }

            int dataCount = retBlock.getData().getDataCount();
            if (dataCount < 1) {
                throw new TransactionException(format("Bad config block data count %d", dataCount));
            }

            logger.trace(format("Received  block for channel %s, block no:%d, transaction count: %d",
                    name, retBlock.getHeader().getNumber(), retBlock.getData().getDataCount()));

            return retBlock;

        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

    }

    private int seekBlock(SeekInfo seekInfo, List<DeliverResponse> deliverResponses, Orderer ordererIn) throws TransactionException {

        logger.trace(format("seekBlock for channel %s", name));
        final long start = System.currentTimeMillis();
        @SuppressWarnings ("UnusedAssignment")
        int statusRC = 404;

        try {

            do {

                statusRC = 404;

                final Orderer orderer = ordererIn != null ? ordererIn : getRandomOrderer();

                TransactionContext txContext = getTransactionContext();

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

                if (deliver.length < 1) {
                    logger.warn(format("Genesis block for channel %s fetch bad deliver missing status block only got blocks:%d", name, deliver.length));
                    //odd so lets try again....
                    statusRC = 404;

                } else {

                    DeliverResponse status = deliver[0];
                    statusRC = status.getStatusValue();

                    if (statusRC == 404 || statusRC == 503) { //404 - block not found.  503 - service not available usually means kafka is not ready but starting.
                        logger.warn(format("Bad deliver expected status 200  got  %d, Channel %s", status.getStatusValue(), name));
                        // keep trying... else
                        statusRC = 404;

                    } else if (statusRC != 200) { // Assume for anything other than 200 we have a non retryable situation
                        throw new TransactionException(format("Bad newest block expected status 200  got  %d, Channel %s", status.getStatusValue(), name));
                    } else {
                        if (deliver.length < 2) {
                            throw new TransactionException(format("Newest block for channel %s fetch bad deliver missing genesis block only got %d:", name, deliver.length));
                        } else {

                            deliverResponses.addAll(Arrays.asList(deliver));
                        }
                    }

                }

                // Not 200 so sleep to try again

                if (200 != statusRC) {
                    long duration = System.currentTimeMillis() - start;

                    if (duration > config.getGenesisBlockWaitTime()) {
                        throw new TransactionException(format("Getting block time exceeded %s seconds for channel %s", Long.toString(TimeUnit.MILLISECONDS.toSeconds(duration)), name));
                    }
                    try {
                        Thread.sleep(ORDERER_RETRY_WAIT_TIME); //try again
                    } catch (InterruptedException e) {
                        TransactionException te = new TransactionException("seekBlock thread Sleep", e);
                        logger.warn(te.getMessage(), te);
                    }
                }

            } while (statusRC != 200);

        } catch (TransactionException e) {
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

        return statusRC;

    }

    private Block getLatestBlock(Orderer orderer) throws TransactionException {

        logger.debug(format("getConfigurationBlock for channel %s", name));

        SeekPosition seekPosition = SeekPosition.newBuilder()
                .setNewest(Ab.SeekNewest.getDefaultInstance())
                .build();

        SeekInfo seekInfo = SeekInfo.newBuilder()
                .setStart(seekPosition)
                .setStop(seekPosition)
                .setBehavior(SeekInfo.SeekBehavior.BLOCK_UNTIL_READY)
                .build();

        ArrayList<DeliverResponse> deliverResponses = new ArrayList<>();

        seekBlock(seekInfo, deliverResponses, orderer);

        DeliverResponse blockresp = deliverResponses.get(1);

        Block latestBlock = blockresp.getBlock();

        if (latestBlock == null) {
            throw new TransactionException(format("newest block for channel %s fetch bad deliver returned null:", name));
        }

        logger.trace(format("Received latest  block for channel %s, block no:%d", name, latestBlock.getHeader().getNumber()));
        return latestBlock;
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

        return sendInstantiationProposal(instantiateProposalRequest, peers);
    }

    /**
     * Send instantiate request to the channel. Chaincode is created and initialized.
     *
     * @param instantiateProposalRequest
     * @param peers
     * @return responses from peers.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Collection<ProposalResponse> sendInstantiationProposal(InstantiateProposalRequest instantiateProposalRequest,
                                                                  Collection<Peer> peers) throws InvalidArgumentException, ProposalException {
        checkChannelState();
        if (null == instantiateProposalRequest) {
            throw new InvalidArgumentException("InstantiateProposalRequest is null");
        }

        instantiateProposalRequest.setSubmitted();

        checkPeers(peers);

        try {
            TransactionContext transactionContext = getTransactionContext(instantiateProposalRequest.getUserContext());
            transactionContext.setProposalWaitTime(instantiateProposalRequest.getProposalWaitTime());
            InstantiateProposalBuilder instantiateProposalbuilder = InstantiateProposalBuilder.newBuilder();
            instantiateProposalbuilder.context(transactionContext);
            instantiateProposalbuilder.argss(instantiateProposalRequest.getArgs());
            instantiateProposalbuilder.chaincodeName(instantiateProposalRequest.getChaincodeName());
            instantiateProposalbuilder.chaincodePath(instantiateProposalRequest.getChaincodePath());
            instantiateProposalbuilder.chaincodeVersion(instantiateProposalRequest.getChaincodeVersion());
            instantiateProposalbuilder.chaincodEndorsementPolicy(instantiateProposalRequest.getChaincodeEndorsementPolicy());
            instantiateProposalbuilder.setTransientMap(instantiateProposalRequest.getTransientMap());

            FabricProposal.Proposal instantiateProposal = instantiateProposalbuilder.build();
            SignedProposal signedProposal = getSignedProposal(transactionContext, instantiateProposal);

            return sendProposalToPeers(peers, signedProposal, transactionContext);
        } catch (Exception e) {
            throw new ProposalException(e);
        }
    }

    private TransactionContext getTransactionContext() throws InvalidArgumentException {
        return getTransactionContext(client.getUserContext());
    }

    private TransactionContext getTransactionContext(User userContext) throws InvalidArgumentException {
        userContext = userContext != null ? userContext : client.getUserContext();

        userContextCheck(userContext);

        return new TransactionContext(this, userContext, client.getCryptoSuite());
    }

    /**
     * Send install chaincode request proposal to all the channels on the peer.
     *
     * @param installProposalRequest
     * @return
     * @throws ProposalException
     * @throws InvalidArgumentException
     */

    Collection<ProposalResponse> sendInstallProposal(InstallProposalRequest installProposalRequest)
            throws ProposalException, InvalidArgumentException {
        return sendInstallProposal(installProposalRequest, peers);

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

        checkChannelState();
        checkPeers(peers);
        if (null == installProposalRequest) {
            throw new InvalidArgumentException("InstallProposalRequest is null");
        }

        try {
            TransactionContext transactionContext = getTransactionContext(installProposalRequest.getUserContext());
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
            SignedProposal signedProposal = getSignedProposal(transactionContext, deploymentProposal);

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

        checkChannelState();
        checkPeers(peers);

        if (null == upgradeProposalRequest) {
            throw new InvalidArgumentException("Upgradeproposal is null");
        }

        try {
            TransactionContext transactionContext = getTransactionContext(upgradeProposalRequest.getUserContext());
            //transactionContext.verify(false);  // Install will have no signing cause it's not really targeted to a channel.
            transactionContext.setProposalWaitTime(upgradeProposalRequest.getProposalWaitTime());
            UpgradeProposalBuilder upgradeProposalBuilder = UpgradeProposalBuilder.newBuilder();
            upgradeProposalBuilder.context(transactionContext);
            upgradeProposalBuilder.argss(upgradeProposalRequest.getArgs());
            upgradeProposalBuilder.chaincodeName(upgradeProposalRequest.getChaincodeName());
            upgradeProposalBuilder.chaincodePath(upgradeProposalRequest.getChaincodePath());
            upgradeProposalBuilder.chaincodeVersion(upgradeProposalRequest.getChaincodeVersion());
            upgradeProposalBuilder.chaincodEndorsementPolicy(upgradeProposalRequest.getChaincodeEndorsementPolicy());

            SignedProposal signedProposal = getSignedProposal(transactionContext, upgradeProposalBuilder.build());

            return sendProposalToPeers(peers, signedProposal, transactionContext);
        } catch (Exception e) {
            throw new ProposalException(e);
        }
    }

    private SignedProposal getSignedProposal(TransactionContext transactionContext, FabricProposal.Proposal proposal) throws CryptoException {

        return SignedProposal.newBuilder()
                .setProposalBytes(proposal.toByteString())
                .setSignature(transactionContext.signByteString(proposal.toByteArray()))
                .build();

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

        checkChannelState();

        if (blockHash == null) {
            throw new InvalidArgumentException("blockHash parameter is null.");
        }
        return queryBlockByHash(getRandomPeer(), blockHash);
    }

    private void checkChannelState() throws InvalidArgumentException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (!initialized) {
            throw new InvalidArgumentException(format("Channel %s has not been initialized.", name));
        }

        userContextCheck(client.getUserContext());

    }

    /**
     * Query a peer in this channel for a Block by the block hash.
     *
     * @param peer      the Peer to query.
     * @param blockHash the hash of the Block in the chain.
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException if the channel is shutdown or any of the arguments are not valid.
     * @throws ProposalException        if an error occurred processing the query.
     */
    public BlockInfo queryBlockByHash(Peer peer, byte[] blockHash) throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeer(peer);

        if (blockHash == null) {
            throw new InvalidArgumentException("blockHash parameter is null.");
        }

        ProposalResponse proposalResponse;
        BlockInfo responseBlock;
        try {
            logger.debug("queryBlockByHash with hash : " + Hex.encodeHexString(blockHash) + "\n    to peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(client.getUserContext());
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
        return queryBlockByNumber(getRandomPeer(), blockNumber);
    }

    private Peer getRandomPeer() throws InvalidArgumentException {

        if (getPeers().isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have any peers associated with it.");
        }

        return getPeers().iterator().next(); //TODO make this random

    }

    private Orderer getRandomOrderer() throws InvalidArgumentException {

        if (getOrderers().isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have any orderers associated with it.");
        }

        return getOrderers().iterator().next(); //TODO make this random

    }

    private void checkPeer(Peer peer) throws InvalidArgumentException {

        if (peer == null) {
            throw new InvalidArgumentException("Peer value is null.");
        }
        if (isSystemChannel()) {
            return; // System owns no peers
        }
        if (!getPeers().contains(peer)) {
            throw new InvalidArgumentException("Channel " + name + " does not have peer " + peer.getName());
        }
        if (peer.getChannel() != this) {
            throw new InvalidArgumentException("Peer " + peer.getName() + " not set for channel " + name);
        }

    }

    private void checkOrderer(Orderer orderer) throws InvalidArgumentException {

        if (orderer == null) {
            throw new InvalidArgumentException("Orderer value is null.");
        }
        if (isSystemChannel()) {
            return; // System owns no Orderers
        }
        if (!getOrderers().contains(orderer)) {
            throw new InvalidArgumentException("Channel " + name + " does not have orderer " + orderer.getName());
        }
        if (orderer.getChannel() != this) {
            throw new InvalidArgumentException("Orderer " + orderer.getName() + " not set for channel " + name);
        }

    }

    private void checkPeers(Collection<Peer> peers) throws InvalidArgumentException {

        if (peers == null) {
            throw new InvalidArgumentException("Collection of peers is null.");
        }

        if (peers.isEmpty()) {
            throw new InvalidArgumentException("Collection of peers is empty.");
        }

        for (Peer peer : peers) {
            checkPeer(peer);
        }
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

        checkChannelState();
        checkPeer(peer);

        ProposalResponse proposalResponse;
        BlockInfo responseBlock;
        try {
            logger.debug("queryBlockByNumber with blockNumber " + blockNumber + " to peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(client.getUserContext());
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

        return queryBlockByTransactionID(getRandomPeer(), txID);
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

        checkChannelState();
        checkPeer(peer);

        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }

        ProposalResponse proposalResponse;
        BlockInfo responseBlock;
        try {
            logger.debug("queryBlockByTransactionID with txID " + txID + " \n    to peer" + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(client.getUserContext());
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

        return queryBlockchainInfo(getRandomPeer());
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

        checkChannelState();
        checkPeer(peer);

        BlockchainInfo response;
        try {
            logger.debug("queryBlockchainInfo to peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(client.getUserContext());
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

        return queryTransactionByID(getRandomPeer(), txID);
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

        checkChannelState();
        checkPeer(peer);

        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }

        TransactionInfo transactionInfo;
        try {
            logger.debug("queryTransactionByID with txID " + txID + "\n    from peer " + peer.getName() + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(client.getUserContext());
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

        checkPeer(peer);

        if (!isSystemChannel()) {
            throw new InvalidArgumentException("queryChannels should only be invoked on system channel.");
        }

        try {

            TransactionContext context = getTransactionContext();

            FabricProposal.Proposal q = QueryPeerChannelsBuilder.newBuilder().context(context).build();

            SignedProposal qProposal = getSignedProposal(context, q);
            Collection<ProposalResponse> proposalResponses = sendProposalToPeers(Collections.singletonList(peer), qProposal, context);

            if (null == proposalResponses) {
                throw new ProposalException(format("Peer %s channel query return with null for responses", peer.getName()));
            }

            if (proposalResponses.size() != 1) {

                throw new ProposalException(format("Peer %s channel query expected one response but got back %d  responses ", peer.getName(), proposalResponses.size()));
            }

            ProposalResponse proposalResponse = proposalResponses.iterator().next();
            if (proposalResponse.getStatus() != ChaincodeResponse.Status.SUCCESS) {
                throw new ProposalException(format("Failed exception message is %s, status is %d", proposalResponse.getMessage(), proposalResponse.getStatus().getStatus()));

            }

            FabricProposalResponse.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) { //not likely but check it.
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

        checkPeer(peer);

        if (!isSystemChannel()) {
            throw new InvalidArgumentException("queryInstalledChaincodes should only be invoked on system channel.");
        }

        try {

            TransactionContext context = getTransactionContext();

            FabricProposal.Proposal q = QueryInstalledChaincodesBuilder.newBuilder().context(context).build();

            SignedProposal qProposal = getSignedProposal(context, q);
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

            if (null == fabricResponseResponse) { //not likely but check it.
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

        checkChannelState();
        checkPeer(peer);

        try {

            TransactionContext context = getTransactionContext();

            FabricProposal.Proposal q = QueryInstantiatedChaincodesBuilder.newBuilder().context(context).build();

            SignedProposal qProposal = getSignedProposal(context, q);
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

            if (null == fabricResponseResponse) { //not likely but check it.
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
     * @return responses from peers.
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
     * @return responses from peers.
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
     * @return responses from peers.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<ProposalResponse> queryByChaincode(QueryByChaincodeRequest queryByChaincodeRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {
        return sendProposal(queryByChaincodeRequest, peers);
    }

    private Collection<ProposalResponse> sendProposal(TransactionRequest proposalRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeers(peers);

        if (null == proposalRequest) {
            throw new InvalidArgumentException("sendProposal queryProposalRequest is null");
        }

        proposalRequest.setSubmitted();

        try {
            TransactionContext transactionContext = getTransactionContext(proposalRequest.getUserContext());
            transactionContext.verify(proposalRequest.doVerify());
            transactionContext.setProposalWaitTime(proposalRequest.getProposalWaitTime());

            // Protobuf message builder
            ProposalBuilder proposalBuilder = ProposalBuilder.newBuilder();
            proposalBuilder.context(transactionContext);
            proposalBuilder.request(proposalRequest);

            SignedProposal invokeProposal = getSignedProposal(transactionContext, proposalBuilder.build());
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
                                                             TransactionContext transactionContext) throws InvalidArgumentException, ProposalException {
        checkPeers(peers);

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

            if (null != diagnosticFileDumper) {
                logger.trace(format("Sending to channel %s, peer: %s, proposal: %s", name, peer.getName(),
                        diagnosticFileDumper.createDiagnosticProtobufFile(signedProposal.toByteArray())));

            }

            Future<FabricProposalResponse.ProposalResponse> proposalResponseListenableFuture;
            try {
                proposalResponseListenableFuture = peer.sendProposalAsync(signedProposal);
            } catch (Exception e) {
                proposalResponseListenableFuture = new CompletableFuture<>();
                ((CompletableFuture) proposalResponseListenableFuture).completeExceptionally(e);

            }
            peerFuturePairs.add(new Pair(peer, proposalResponseListenableFuture));

        }

        Collection<ProposalResponse> proposalResponses = new ArrayList<>();
        for (Pair peerFuturePair : peerFuturePairs) {

            FabricProposalResponse.ProposalResponse fabricResponse = null;
            String message;
            int status = 500;
            final String peerName = peerFuturePair.peer.getName();
            try {
                fabricResponse = peerFuturePair.future.get(transactionContext.getProposalWaitTime(), TimeUnit.MILLISECONDS);
                message = fabricResponse.getResponse().getMessage();
                status = fabricResponse.getResponse().getStatus();
                logger.debug(format("Channel %s got back from peer %s status: %d, message: %s",
                        name, peerName, status, message));
                if (null != diagnosticFileDumper) {
                    logger.trace(format("Got back from channel %s, peer: %s, proposal response: %s", name, peerName,
                            diagnosticFileDumper.createDiagnosticProtobufFile(fabricResponse.toByteArray())));

                }
            } catch (InterruptedException e) {
                message = "Sending proposal to " + peerName + " failed because of interruption";
                logger.error(message, e);
            } catch (TimeoutException e) {
                message = format("Sending proposal to " + peerName + " failed because of timeout(%d milliseconds) expiration",
                        transactionContext.getProposalWaitTime());
                logger.error(message, e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof Error) {
                    String emsg = "Sending proposal to " + peerName + " failed because of " + cause.getMessage();
                    logger.error(emsg, new Exception(cause)); //wrapped in exception to get full stack trace.
                    throw (Error) cause;
                } else {
                    if (cause instanceof StatusRuntimeException) {
                        message = format("Sending proposal to " + peerName + " failed because of: gRPC failure=%s",
                                ((StatusRuntimeException) cause).getStatus());
                    } else {
                        message = format("Sending proposal to " + peerName + " failed because of: %s", cause.getMessage());
                    }
                    logger.error(message, new Exception(cause)); //wrapped in exception to get full stack trace.
                }
            }

            ProposalResponse proposalResponse = new ProposalResponse(transactionContext.getTxID(),
                    transactionContext.getChannelID(), status, message);
            proposalResponse.setProposalResponse(fabricResponse);
            proposalResponse.setProposal(signedProposal);
            proposalResponse.setPeer(peerFuturePair.peer);

            if (fabricResponse != null && transactionContext.getVerify()) {
                proposalResponse.verify(client.getCryptoSuite());
            }

            proposalResponses.add(proposalResponse);
        }

        return proposalResponses;
    }

    /////////////////////////////////////////////////////////
    // transactions order

    /**
     * Send transaction to one of the orderers on the channel using a specific user context.
     *
     * @param proposalResponses The proposal responses to be sent to the orderer.
     * @param userContext       The usercontext used for signing transaction.
     * @return a future allowing access to the result of the transaction invocation once complete.
     */
    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses, User userContext) {

        return sendTransaction(proposalResponses, orderers, userContext);

    }

    /**
     * Send transaction to one of the orderers on the channel using the usercontext set on the client.
     *
     * @param proposalResponses .
     * @return a future allowing access to the result of the transaction invocation once complete.
     */
    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses) {

        return sendTransaction(proposalResponses, orderers);

    }

    /**
     * Send transaction to one of the specified orderers using the usercontext set on the client..
     *
     * @param proposalResponses The proposal responses to be sent to the orderer
     * @param orderers          The orderers to send the transaction to.
     * @return a future allowing access to the result of the transaction invocation once complete.
     */

    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses, Collection<Orderer> orderers) {

        return sendTransaction(proposalResponses, orderers, client.getUserContext());
    }

    /**
     * Send transaction to one of a specified set of orderers with the specified user context.
     *
     * @param proposalResponses
     * @param orderers
     * @return Future allowing access to the result of the transaction invocation.
     */

    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses, Collection<Orderer> orderers, User userContext) {
        try {

            checkChannelState();
            userContextCheck(userContext);

            if (null == proposalResponses) {

                throw new InvalidArgumentException("sendTransaction proposalResponses was null");
            }

            if (null == orderers) {
                throw new InvalidArgumentException("sendTransaction Orderers is null");
            }
            if (orderers.isEmpty()) {
                throw new InvalidArgumentException("sendTransaction Orderers to send to is empty.");
            }

            if (config.getProposalConsistencyValidation()) {

                HashSet<ProposalResponse> invalid = new HashSet<>();

                int consistencyGroups = SDKUtils.getProposalConsistencySets(proposalResponses, invalid).size();

                if (consistencyGroups != 1 || !invalid.isEmpty()) {
                    throw new IllegalArgumentException(format(
                            "The proposal responses have %d inconsistent groups with %d that are invalid."
                                    + " Expected all to be consistent and none to be invalid.",
                            consistencyGroups, invalid.size()));

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

            Envelope transactionEnvelope = createTransactionEnvelope(transactionPayload, userContext);

            CompletableFuture<TransactionEvent> sret = registerTxListener(proposalTransactionID);
            logger.debug(format("Channel %s sending transaction to orderer(s) with TxID %s ", name, proposalTransactionID));

            boolean success = false;

            BroadcastResponse resp = null;
            for (Orderer orderer : orderers) {

                try {

                    if (null != diagnosticFileDumper) {
                        logger.trace(format("Sending to channel %s, orderer: %s, transaction: %s", name, orderer.getName(),
                                diagnosticFileDumper.createDiagnosticProtobufFile(transactionEnvelope.toByteArray())));

                    }

                    resp = orderer.sendTransaction(transactionEnvelope);
                    if (resp.getStatus() == Status.SUCCESS) {

                        success = true;
                        break;

                    }
                } catch (Exception e) {
                    String emsg = format("Channel %s unsuccessful sendTransaction to orderer", name);
                    if (resp != null) {
                        emsg = format("Channel %s unsuccessful sendTransaction to orderer. Status %s", name, resp.getStatus());
                    }

                    logger.error(emsg, e);

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

    private Envelope createTransactionEnvelope(Payload transactionPayload, User user) throws CryptoException {

        return Envelope.newBuilder()
                .setPayload(transactionPayload.toByteString())
                .setSignature(ByteString.copyFrom(client.getCryptoSuite().sign(user.getEnrollment().getKey(), transactionPayload.toByteArray())))
                .build();

    }

    byte[] getChannelConfigurationSignature(ChannelConfiguration channelConfiguration, User signer) throws InvalidArgumentException {

        userContextCheck(signer);

        if (null == channelConfiguration) {

            throw new InvalidArgumentException("channelConfiguration is null");

        }

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
     * Register a block listener.
     *
     * @param listener
     * @return the UUID handle of the registered block listener.
     * @throws InvalidArgumentException if the channel is shutdown.
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

//            Block block = event.seekBlock();
//            final long num = block.getHeader().getNumber();

            // May be fed by multiple eventhubs but BlockingQueue.add() is thread-safe
            events.add(event);

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
                    if (l.size() == 0) {
                        txListeners.remove(txID);
                    }
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

    private CompletableFuture<TransactionEvent> registerTxListener(String txid) {

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
//        anchorPeers = null;
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
