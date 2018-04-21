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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

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
import org.hyperledger.fabric.protos.peer.Query;
import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.protos.peer.Query.ChaincodeQueryResponse;
import org.hyperledger.fabric.protos.peer.Query.ChannelQueryResponse;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.EventHubException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.transaction.GetConfigBlockBuilder;
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
import static org.hyperledger.fabric.sdk.Channel.TransactionOptions.createTransactionOptions;
import static org.hyperledger.fabric.sdk.User.userContextCheck;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createSeekInfoEnvelope;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getSignatureHeaderAsByteString;

/**
 * The class representing a channel with which the client SDK interacts.
 * <p>
 */
public class Channel implements Serializable {
    private static final long serialVersionUID = -3266164166893832538L;
    private static final Log logger = LogFactory.getLog(Channel.class);
    private static final boolean IS_DEBUG_LEVEL = logger.isDebugEnabled();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final Config config = Config.getConfig();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;
    private static final String SYSTEM_CHANNEL_NAME = "";

    private static final long ORDERER_RETRY_WAIT_TIME = config.getOrdererRetryWaitTime();
    private static final long CHANNEL_CONFIG_WAIT_TIME = config.getChannelConfigWaitTime();
    private static final Random RANDOM = new Random();
    private static final String BLOCK_LISTENER_TAG = "BLOCK_LISTENER_HANDLE";
    // final Set<Peer> eventingPeers = Collections.synchronizedSet(new HashSet<>());
    private static final long DELTA_SWEEP = config.getTransactionListenerCleanUpTimeout();
    private static final String CHAINCODE_EVENTS_TAG = "CHAINCODE_EVENTS_HANDLE";
    final Collection<Orderer> orderers = new LinkedList<>();
    final Collection<EventHub> eventHubs = new LinkedList<>();
    // Name of the channel is only meaningful to the client
    private final String name;
    // The peers on this channel to which the client can connect
    private final Collection<Peer> peers = Collections.synchronizedSet(new HashSet<>());
    private final Map<Peer, PeerOptions> peerOptionsMap = Collections.synchronizedMap(new HashMap<>());
    private final Map<PeerRole, Set<Peer>> peerRoleSetMap = Collections.synchronizedMap(new HashMap<>());
    private final boolean systemChannel;
    private final LinkedHashMap<String, ChaincodeEventListenerEntry> chainCodeListeners = new LinkedHashMap<>();
    transient HFClient client;
    /**
     * Runs processing events from event hubs.
     */

    transient Thread eventQueueThread = null;
    private transient volatile boolean initialized = false;
    private transient boolean shutdown = false;
    private transient Block genesisBlock;
    private transient Map<String, MSP> msps = new HashMap<>();
    /**
     * A queue each eventing hub will write events to.
     */

    private transient ChannelEventQue channelEventQue = new ChannelEventQue();
    private transient LinkedHashMap<String, BL> blockListeners = new LinkedHashMap<>();
    private transient LinkedHashMap<String, LinkedList<TL>> txListeners = new LinkedHashMap<>();
    //Cleans up any transaction listeners that will probably never complete.
    private transient ScheduledFuture<?> sweeper = null;
    private transient String blh = null;

    {
        for (Peer.PeerRole peerRole : EnumSet.allOf(PeerRole.class)) {

            peerRoleSetMap.put(peerRole, Collections.synchronizedSet(new HashSet<>()));

        }
    }

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
            //         final ConfigUpdateEnvelope.Builder configUpdateEnvBuilder = configUpdateEnv.toBuilder();`

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
        logger.debug(format("Creating channel: %s, client context %s", isSystemChannel() ? "SYSTEM_CHANNEL" : name, client.getUserContext().getName()));

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

    private static void checkHandle(final String tag, final String handle) throws InvalidArgumentException {

        if (isNullOrEmpty(handle)) {
            throw new InvalidArgumentException("Handle is invalid.");
        }
        if (!handle.startsWith(tag) || !handle.endsWith(tag)) {
            throw new InvalidArgumentException("Handle is wrong type.");
        }

    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {

        in.defaultReadObject();
        initialized = false;
        shutdown = false;
        msps = new HashMap<>();
        txListeners = new LinkedHashMap<>();
        channelEventQue = new ChannelEventQue();
        blockListeners = new LinkedHashMap<>();

        for (EventHub eventHub : getEventHubs()) {
            eventHub.setEventQue(channelEventQue);
        }

    }

    /**
     * Get all Event Hubs on this channel.
     *
     * @return Event Hubs
     */
    public Collection<EventHub> getEventHubs() {
        return Collections.unmodifiableCollection(eventHubs);
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
            logger.trace(format("startLastConfigIndex: %d. Channel config wait time is: %d",
                    startLastConfigIndex, CHANNEL_CONFIG_WAIT_TIME));

            sendUpdateChannel(updateChannelConfiguration.getUpdateChannelConfigurationAsBytes(), signers, orderer);

            long currentLastConfigIndex = -1;
            final long nanoTimeStart = System.nanoTime();

            //Try to wait to see the channel got updated but don't fail if we don't see it.
            do {
                currentLastConfigIndex = getLastConfigIndex(orderer);
                if (currentLastConfigIndex == startLastConfigIndex) {

                    final long duration = TimeUnit.MILLISECONDS.convert(System.nanoTime() - nanoTimeStart, TimeUnit.NANOSECONDS);

                    if (duration > CHANNEL_CONFIG_WAIT_TIME) {
                        logger.warn(format("Channel %s did not get updated last config after %d ms, Config wait time: %d ms. startLastConfigIndex: %d, currentLastConfigIndex: %d ",
                                name, duration, CHANNEL_CONFIG_WAIT_TIME, startLastConfigIndex, currentLastConfigIndex));
                        //waited long enough ..
                        currentLastConfigIndex = startLastConfigIndex - 1L; // just bail don't throw exception.
                    } else {

                        try {
                            Thread.sleep(ORDERER_RETRY_WAIT_TIME); //try again sleep
                        } catch (InterruptedException e) {
                            TransactionException te = new TransactionException("update channel thread Sleep", e);
                            logger.warn(te.getMessage(), te);
                        }
                    }

                }

                logger.trace(format("currentLastConfigIndex: %d", currentLastConfigIndex));

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
                        transactionContext.getTxID(), name, transactionContext.getEpoch(), transactionContext.getFabricTimestamp(), null, null);

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
                        String info = trxResult.getInfo();
                        if (null == info) {
                            info = "";

                        }

                        throw new TransactionException(format("Channel %s update error timed out after %d ms. Status value %d. Status %s. %s", name,
                                duration, statusCode, trxResult.getStatus().name(), info));
                    }

                    try {
                        Thread.sleep(ORDERER_RETRY_WAIT_TIME); //try again sleep
                    } catch (InterruptedException e) {
                        TransactionException te = new TransactionException("update thread Sleep", e);
                        logger.warn(te.getMessage(), te);
                    }

                } else if (200 != statusCode) {
                    // Can't retry.

                    String info = trxResult.getInfo();
                    if (null == info) {
                        info = "";
                    }

                    throw new TransactionException(format("New channel %s error. StatusValue %d. Status %s. %s", name,
                            statusCode, "" + trxResult.getStatus(), info));
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
     * Is channel initialized.
     *
     * @return true if the channel has been initialized.
     */

    public boolean isInitialized() {
        return initialized;
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

        return addPeer(peer, PeerOptions.createPeerOptions());

    }

    /**
     * Add a peer to the channel
     *
     * @param peer        The Peer to add.
     * @param peerOptions see {@link PeerRole}
     * @return Channel The current channel added.
     * @throws InvalidArgumentException
     */
    public Channel addPeer(Peer peer, PeerOptions peerOptions) throws InvalidArgumentException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (initialized) {
            throw new InvalidArgumentException(format("Channel %s has been initialized.", name));
        }

        if (null == peer) {
            throw new InvalidArgumentException("Peer is invalid can not be null.");
        }

        if (peer.getChannel() != null && peer.getChannel() != this) {
            throw new InvalidArgumentException(format("Peer already connected to channel %s", peer.getChannel().getName()));
        }

        if (null == peerOptions) {
            throw new InvalidArgumentException("Peer is invalid can not be null.");
        }
        peer.setChannel(this);

        peers.add(peer);
        peerOptionsMap.put(peer, peerOptions.clone());

        for (Map.Entry<PeerRole, Set<Peer>> peerRole : peerRoleSetMap.entrySet()) {
            if (peerOptions.getPeerRoles().contains(peerRole.getKey())) {
                peerRole.getValue().add(peer);
            }
        }
        return this;
    }

    /**
     * Join the peer to the channel. The peer is added with all roles see {@link PeerOptions}
     *
     * @param peer the peer to join the channel.
     * @return
     * @throws ProposalException
     */

    public Channel joinPeer(Peer peer) throws ProposalException {
        return joinPeer(peer, PeerOptions.createPeerOptions());
    }

    private Collection<Peer> getEventingPeers() {

        return Collections.unmodifiableCollection(peerRoleSetMap.get(PeerRole.EVENT_SOURCE));
    }

    private Collection<Peer> getEndorsingPeers() {

        return Collections.unmodifiableCollection(peerRoleSetMap.get(PeerRole.ENDORSING_PEER));
    }

    private Collection<Peer> getChaincodePeers() {

        return Collections.unmodifiableCollection(getPeers(EnumSet.of(PeerRole.CHAINCODE_QUERY, PeerRole.ENDORSING_PEER)));
    }

    private Collection<Peer> getChaincodeQueryPeers() {

        return Collections.unmodifiableCollection(peerRoleSetMap.get(PeerRole.CHAINCODE_QUERY));
    }

    private Collection<Peer> getLedgerQueryPeers() {

        return Collections.unmodifiableCollection(peerRoleSetMap.get(PeerRole.LEDGER_QUERY));
    }

    /**
     * @param peer        the peer to join the channel.
     * @param peerOptions see {@link PeerOptions}
     * @return
     * @throws ProposalException
     */

    public Channel joinPeer(Peer peer, PeerOptions peerOptions) throws ProposalException {

        try {
            return joinPeer(getRandomOrderer(), peer, peerOptions);
        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(e);

        }

    }

    /**
     * Join peer to channel
     *
     * @param orderer     The orderer to get the genesis block.
     * @param peer        the peer to join the channel.
     * @param peerOptions see {@link PeerOptions}
     * @return
     * @throws ProposalException
     */

    public Channel joinPeer(Orderer orderer, Peer peer, PeerOptions peerOptions) throws ProposalException {

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

            genesisBlock = getGenesisBlock(orderer);
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

            addPeer(peer, peerOptions); //need to add peer.

            Collection<ProposalResponse> resp = sendProposalToPeers(new ArrayList<>(Collections.singletonList(peer)),
                    signedProposal, transactionContext);

            ProposalResponse pro = resp.iterator().next();

            if (pro.getStatus() == ProposalResponse.Status.SUCCESS) {
                logger.info(format("Peer %s joined into channel %s", peer.getName(), name));
            } else {
                removePeerInternal(peer);
                throw new ProposalException(format("Join peer to channel %s failed.  Status %s, details: %s",
                        name, pro.getStatus().toString(), pro.getMessage()));

            }
        } catch (ProposalException e) {
            removePeerInternal(peer);
            logger.error(e);
            throw e;
        } catch (Exception e) {
            peers.remove(peer);
            logger.error(e);
            throw new ProposalException(e.getMessage(), e);
        }

        return this;
    }

    private Block getConfigBlock(List<Peer> peers) throws ProposalException {

        //   logger.debug(format("getConfigBlock for channel %s with peer %s, url: %s", name, peer.getName(), peer.getUrl()));

        if (shutdown) {
            throw new ProposalException(format("Channel %s has been shutdown.", name));
        }

        if (peers.isEmpty()) {
            throw new ProposalException("No peers go get config block");
        }

        TransactionContext transactionContext = null;
        SignedProposal signedProposal = null;
        try {
            transactionContext = getTransactionContext();
            transactionContext.verify(false); // can't verify till we get the config block.

            FabricProposal.Proposal proposal = GetConfigBlockBuilder.newBuilder()
                    .context(transactionContext)
                    .channelId(name)
                    .build();

            logger.debug("Getting signed proposal.");
            signedProposal = getSignedProposal(transactionContext, proposal);
            logger.debug("Got signed proposal.");
        } catch (Exception e) {
            throw new ProposalException(e);
        }
        ProposalException lastException = new ProposalException(format("getConfigBlock for channel %s failed.", name));

        for (Peer peer : peers) {
            try {

                Collection<ProposalResponse> resp = sendProposalToPeers(new ArrayList<>(Collections.singletonList(peer)),
                        signedProposal, transactionContext);

                if (!resp.isEmpty()) {

                    ProposalResponse pro = resp.iterator().next();

                    if (pro.getStatus() == ProposalResponse.Status.SUCCESS) {
                        logger.trace(format("getConfigBlock from peer %s on channel %s success", peer.getName(), name));
                        return Block.parseFrom(pro.getProposalResponse().getResponse().getPayload().toByteArray());
                    } else {
                        lastException = new ProposalException(format("getConfigBlock for channel %s failed with peer %s.  Status %s, details: %s",
                                name, peer.getName(), pro.getStatus().toString(), pro.getMessage()));
                        logger.warn(lastException.getMessage());

                    }
                } else {
                    logger.warn(format("Got empty proposals from %s", peer));
                }
            } catch (Exception e) {
                lastException = new ProposalException(format("getConfigBlock for channel %s failed with peer %s.", name, peer.getName()), e);
                logger.warn(lastException.getMessage());
            }
        }

        throw lastException;

    }

    /**
     * Removes the peer connection from the channel.
     * This does NOT unjoin the peer from from the channel.
     * Fabric does not support that at this time -- maybe some day, but not today
     *
     * @param peer
     */
    public void removePeer(Peer peer) throws InvalidArgumentException {
        if (initialized) {
            throw new InvalidArgumentException(format("Can not remove peer from channel %s already initialized.", name));
        }
        if (shutdown) {
            throw new InvalidArgumentException(format("Can not remove peer from channel %s already shutdown.", name));
        }

        checkPeer(peer);
        removePeerInternal(peer);

    }

    private void removePeerInternal(Peer peer) {

        peers.remove(peer);
        peerOptionsMap.remove(peer);

        for (Set<Peer> peerRoleSet : peerRoleSetMap.values()) {
            peerRoleSet.remove(peer);
        }
        peer.unsetChannel();
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

    public PeerOptions getPeersOptions(Peer peer) {
        PeerOptions ret = peerOptionsMap.get(peer);
        if (ret != null) {
            ret = ret.clone();
        }
        return ret;

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
     * Get the peers for this channel.
     *
     * @return the peers.
     */
    public Collection<Peer> getPeers(EnumSet<PeerRole> roles) {

        Set<Peer> ret = new HashSet<>(getPeers().size());

        for (PeerRole peerRole : roles) {
            ret.addAll(peerRoleSetMap.get(peerRole));
        }

        return Collections.unmodifiableCollection(ret);
    }

    /**
     * Set peerOptions in the channel that has not be initialized yet.
     *
     * @param peer        the peer to set options on.
     * @param peerOptions see {@link PeerOptions}
     * @return old options.
     */

    PeerOptions setPeerOptions(Peer peer, PeerOptions peerOptions) throws InvalidArgumentException {
        if (initialized) {
            throw new InvalidArgumentException(format("Channel %s already initialized.", name));
        }

        checkPeer(peer);
        PeerOptions ret = getPeersOptions(peer);
        removePeerInternal(peer);
        addPeer(peer, peerOptions);

        return ret;

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
            loadCACertificates();  // put all MSP certs into cryptoSuite if this fails here we'll try again later.
        } catch (Exception e) {
            logger.warn(format("Channel %s could not load peer CA certificates from any peers.", name));
        }

        try {

            logger.debug(format("Eventque started %s", "" + eventQueueThread));

            for (EventHub eh : eventHubs) { //Connect all event hubs
                eh.connect(getTransactionContext());
            }

            for (Peer peer : getEventingPeers()) {
                peer.initiateEventing(getTransactionContext(), getPeersOptions(peer));
            }

            logger.debug(format("%d eventhubs initialized", getEventHubs().size()));

            registerTransactionListenerProcessor(); //Manage transactions.
            logger.debug(format("Channel %s registerTransactionListenerProcessor completed", name));
            startEventQue(); //Run the event for event messages from event hubs.

            this.initialized = true;

            logger.debug(format("Channel %s initialized", name));

            return this;
//        } catch (TransactionException e) {
//            logger.error(e.getMessage(), e);
//            throw e;

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
    protected synchronized void loadCACertificates() throws InvalidArgumentException, CryptoException, TransactionException {

        if (msps != null && !msps.isEmpty()) {
            return;
        }
        logger.debug(format("Channel %s loadCACertificates", name));

        parseConfigBlock();

        if (msps == null || msps.isEmpty()) {
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

    boolean isSystemChannel() {
        return systemChannel;
    }

    /**
     * Is the channel shutdown.
     *
     * @return return true if the channel is shutdown.
     */
    public boolean isShutdown() {
        return shutdown;
    }

    /**
     * Get signed byes of the update channel.
     *
     * @param updateChannelConfiguration
     * @param signer
     * @return
     * @throws InvalidArgumentException
     */
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

    ChannelEventQue getChannelEventQue() {
        return channelEventQue;
    }

    ExecutorService getExecutorService() {
        return client.getExecutorService();
    }

    protected void parseConfigBlock() throws TransactionException {

        Map<String, MSP> lmsps = msps;

        if (lmsps != null && !lmsps.isEmpty()) {
            return;

        }

        try {

            Block parseFrom = getConfigBlock(getShuffledPeers());

            // final Block configBlock = getConfigurationBlock();

            logger.debug(format("Channel %s Got config block getting MSP data and anchorPeers data", name));

            Envelope envelope = Envelope.parseFrom(parseFrom.getData().getData(0));
            Payload payload = Payload.parseFrom(envelope.getPayload());
            ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
            ConfigGroup channelGroup = configEnvelope.getConfig().getChannelGroup();
            Map<String, MSP> newMSPS = traverseConfigGroupsMSP("", channelGroup, new HashMap<>(20));

            msps = Collections.unmodifiableMap(newMSPS);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

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

            if (null != diagnosticFileDumper) {
                logger.trace(format("Channel %s getConfigurationBlock returned %s", name,
                        diagnosticFileDumper.createDiagnosticFile(String.valueOf(configBlock).getBytes())));
            }

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
            final Block configBlock = getConfigBlock(getShuffledPeers());

            Envelope envelopeRet = Envelope.parseFrom(configBlock.getData().getData(0));

            Payload payload = Payload.parseFrom(envelopeRet.getPayload());

            ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
            return configEnvelope.getConfig().toByteArray();

        } catch (Exception e) {
            throw new TransactionException(e);
        }

    }

    private long getLastConfigIndex(Orderer orderer) throws TransactionException, InvalidProtocolBufferException {
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

                DeliverResponse[] deliver = orderer.sendDeliver(createSeekInfoEnvelope(txContext, seekInfo, orderer.getClientTLSCertificateDigest()));

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
     * Send instantiate request to the channel. Chaincode is created and initialized.
     *
     * @param instantiateProposalRequest send instantiate chaincode proposal request.
     * @return Collections of proposal responses
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<ProposalResponse> sendInstantiationProposal(InstantiateProposalRequest instantiateProposalRequest) throws InvalidArgumentException, ProposalException {

        return sendInstantiationProposal(instantiateProposalRequest, getChaincodePeers());
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
            instantiateProposalbuilder.chaincodeType(instantiateProposalRequest.getChaincodeLanguage());
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
        return sendInstallProposal(installProposalRequest, getChaincodePeers());

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
            installProposalbuilder.setChaincodeMetaInfLocation(installProposalRequest.getChaincodeMetaInfLocation());

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

        return sendUpgradeProposal(upgradeProposalRequest, getChaincodePeers());

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
     * query this channel for a Block by the block hash.
     * The request is retried on each peer on the channel till successful.
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param blockHash the hash of the Block in the chain
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByHash(byte[] blockHash) throws InvalidArgumentException, ProposalException {
        return queryBlockByHash(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), blockHash);
    }

    /**
     * query this channel for a Block by the block hash.
     * The request is tried on multiple peers.
     *
     * @param blockHash   the hash of the Block in the chain
     * @param userContext the user context.
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByHash(byte[] blockHash, User userContext) throws InvalidArgumentException, ProposalException {
        return queryBlockByHash(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), blockHash, userContext);
    }

    /**
     * Query a peer in this channel for a Block by the block hash.
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peer      the Peer to query.
     * @param blockHash the hash of the Block in the chain.
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException if the channel is shutdown or any of the arguments are not valid.
     * @throws ProposalException        if an error occurred processing the query.
     */
    public BlockInfo queryBlockByHash(Peer peer, byte[] blockHash) throws InvalidArgumentException, ProposalException {
        return queryBlockByHash(Collections.singleton(peer), blockHash);
    }

    /**
     * Query a peer in this channel for a Block by the block hash.
     * Each peer is tried until successful response.
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peers     the Peers to query.
     * @param blockHash the hash of the Block in the chain.
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException if the channel is shutdown or any of the arguments are not valid.
     * @throws ProposalException        if an error occurred processing the query.
     */
    public BlockInfo queryBlockByHash(Collection<Peer> peers, byte[] blockHash) throws InvalidArgumentException, ProposalException {

        return queryBlockByHash(peers, blockHash, client.getUserContext());

    }

    /**
     * Query a peer in this channel for a Block by the block hash.
     *
     * @param peers       the Peers to query.
     * @param blockHash   the hash of the Block in the chain.
     * @param userContext the user context
     * @return the {@link BlockInfo} with the given block Hash
     * @throws InvalidArgumentException if the channel is shutdown or any of the arguments are not valid.
     * @throws ProposalException        if an error occurred processing the query.
     */
    public BlockInfo queryBlockByHash(Collection<Peer> peers, byte[] blockHash, User userContext) throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeers(peers);
        userContextCheck(userContext);

        if (blockHash == null) {
            throw new InvalidArgumentException("blockHash parameter is null.");
        }

        try {

            logger.trace("queryBlockByHash with hash : " + Hex.encodeHexString(blockHash) + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(userContext);
            querySCCRequest.setFcn(QuerySCCRequest.GETBLOCKBYHASH);
            querySCCRequest.setArgs(name);
            querySCCRequest.setArgBytes(new byte[][] {blockHash});

            ProposalResponse proposalResponse = sendProposalSerially(querySCCRequest, peers);

            return new BlockInfo(Block.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (InvalidProtocolBufferException e) {
            ProposalException proposalException = new ProposalException(e);
            logger.error(proposalException);
            throw proposalException;
        }
    }

    private Peer getRandomLedgerQueryPeer() throws InvalidArgumentException {
        final ArrayList<Peer> ledgerQueryPeers = new ArrayList<>(new HashSet<>(getLedgerQueryPeers())); //copy to avoid unlikely changes
        if (ledgerQueryPeers.isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have any ledger querying peers associated with it.");
        }

        return ledgerQueryPeers.get(RANDOM.nextInt(ledgerQueryPeers.size()));

    }

    private Peer getRandomPeer() throws InvalidArgumentException {

        final ArrayList<Peer> randPicks = new ArrayList<>(getPeers()); //copy to avoid unlikely changes

        if (randPicks.isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have any peers associated with it.");
        }

        return randPicks.get(RANDOM.nextInt(randPicks.size()));
    }

    private List<Peer> getShuffledPeers() {

        ArrayList<Peer> peers = new ArrayList<>(getPeers());
        Collections.shuffle(peers);
        return peers;
    }

    private List<Peer> getShuffledPeers(EnumSet<PeerRole> roles) {

        ArrayList<Peer> peers = new ArrayList<>(getPeers(roles));
        Collections.shuffle(peers);
        return peers;
    }

    private Orderer getRandomOrderer() throws InvalidArgumentException {

        final ArrayList<Orderer> randPicks = new ArrayList<>(new HashSet<>(getOrderers())); //copy to avoid unlikely changes

        if (randPicks.isEmpty()) {
            throw new InvalidArgumentException("Channel " + name + " does not have any orderers associated with it.");
        }

        return randPicks.get(RANDOM.nextInt(randPicks.size()));

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
     * query this channel for a Block by the blockNumber.
     * The request is retried on all peers till successful
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>.
     *
     * @param blockNumber index of the Block in the chain
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(long blockNumber) throws InvalidArgumentException, ProposalException {
        return queryBlockByNumber(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), blockNumber);
    }

    /**
     * query this channel for a Block by the blockNumber.
     * The request is sent to a random peer in the channel.
     *
     * @param blockNumber index of the Block in the chain
     * @param userContext the user context to be used.
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(long blockNumber, User userContext) throws InvalidArgumentException, ProposalException {
        return queryBlockByNumber(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), blockNumber, userContext);
    }

    /**
     * Query a peer in this channel for a Block by the blockNumber
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peer        the peer to send the request to
     * @param blockNumber index of the Block in the chain
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(Peer peer, long blockNumber) throws InvalidArgumentException, ProposalException {

        return queryBlockByNumber(Collections.singleton(peer), blockNumber);

    }

    /**
     * query a peer in this channel for a Block by the blockNumber
     *
     * @param peer        the peer to send the request to
     * @param blockNumber index of the Block in the chain
     * @param userContext the user context.
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(Peer peer, long blockNumber, User userContext) throws InvalidArgumentException, ProposalException {

        return queryBlockByNumber(Collections.singleton(peer), blockNumber, userContext);

    }

    /**
     * query a peer in this channel for a Block by the blockNumber
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peers       the peers to try and send the request to
     * @param blockNumber index of the Block in the chain
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(Collection<Peer> peers, long blockNumber) throws InvalidArgumentException, ProposalException {
        return queryBlockByNumber(peers, blockNumber, client.getUserContext());

    }

    /**
     * query a peer in this channel for a Block by the blockNumber
     *
     * @param peers       the peers to try and send the request to
     * @param blockNumber index of the Block in the chain
     * @param userContext the user context to use.
     * @return the {@link BlockInfo} with the given blockNumber
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByNumber(Collection<Peer> peers, long blockNumber, User userContext) throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeers(peers);
        userContextCheck(userContext);

        try {
            logger.debug("queryBlockByNumber with blockNumber " + blockNumber + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(userContext);
            querySCCRequest.setFcn(QuerySCCRequest.GETBLOCKBYNUMBER);
            querySCCRequest.setArgs(name, Long.toUnsignedString(blockNumber));

            ProposalResponse proposalResponse = sendProposalSerially(querySCCRequest, peers);

            return new BlockInfo(Block.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (InvalidProtocolBufferException e) {
            logger.error(e);
            throw new ProposalException(e);
        }
    }

    /**
     * query this channel for a Block by a TransactionID contained in the block
     * The request is tried on on each peer till successful.
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param txID the transactionID to query on
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(String txID) throws InvalidArgumentException, ProposalException {

        return queryBlockByTransactionID(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), txID);
    }

    /**
     * query this channel for a Block by a TransactionID contained in the block
     * The request is sent to a random peer in the channel
     *
     * @param txID        the transactionID to query on
     * @param userContext the user context.
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(String txID, User userContext) throws InvalidArgumentException, ProposalException {

        return queryBlockByTransactionID(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), txID, userContext);
    }

    /**
     * query a peer in this channel for a Block by a TransactionID contained in the block
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peer the peer to send the request to
     * @param txID the transactionID to query on
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(Peer peer, String txID) throws InvalidArgumentException, ProposalException {
        return queryBlockByTransactionID(Collections.singleton(peer), txID);
    }

    /**
     * query a peer in this channel for a Block by a TransactionID contained in the block
     *
     * @param peer        the peer to send the request to
     * @param txID        the transactionID to query on
     * @param userContext the user context.
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(Peer peer, String txID, User userContext) throws InvalidArgumentException, ProposalException {
        return queryBlockByTransactionID(Collections.singleton(peer), txID, userContext);
    }

    /**
     * query a peer in this channel for a Block by a TransactionID contained in the block
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peers the peers to try to send the request to.
     * @param txID  the transactionID to query on
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(Collection<Peer> peers, String txID) throws InvalidArgumentException, ProposalException {
        return queryBlockByTransactionID(peers, txID, client.getUserContext());
    }

    /**
     * query a peer in this channel for a Block by a TransactionID contained in the block
     *
     * @param peers       the peer to try to send the request to
     * @param txID        the transactionID to query on
     * @param userContext the user context.
     * @return the {@link BlockInfo} for the Block containing the transaction
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockInfo queryBlockByTransactionID(Collection<Peer> peers, String txID, User userContext) throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeers(peers);
        User.userContextCheck(userContext);

        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }

        try {
            logger.debug("queryBlockByTransactionID with txID " + txID + " \n    " + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(userContext);
            querySCCRequest.setFcn(QuerySCCRequest.GETBLOCKBYTXID);
            querySCCRequest.setArgs(name, txID);

            ProposalResponse proposalResponse = sendProposalSerially(querySCCRequest, peers);

            return new BlockInfo(Block.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (InvalidProtocolBufferException e) {

            throw new ProposalException(e);
        }

    }

    /**
     * query this channel for chain information.
     * The request is sent to a random peer in the channel
     * <p>
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @return a {@link BlockchainInfo} object containing the chain info requested
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockchainInfo queryBlockchainInfo() throws ProposalException, InvalidArgumentException {

        return queryBlockchainInfo(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), client.getUserContext());
    }

    /**
     * query this channel for chain information.
     * The request is sent to a random peer in the channel
     *
     * @param userContext the user context to use.
     * @return a {@link BlockchainInfo} object containing the chain info requested
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockchainInfo queryBlockchainInfo(User userContext) throws ProposalException, InvalidArgumentException {

        return queryBlockchainInfo(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), userContext);
    }

    /**
     * query for chain information
     * <p>
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peer The peer to send the request to
     * @return a {@link BlockchainInfo} object containing the chain info requested
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockchainInfo queryBlockchainInfo(Peer peer) throws ProposalException, InvalidArgumentException {

        return queryBlockchainInfo(Collections.singleton(peer), client.getUserContext());

    }

    /**
     * query for chain information
     *
     * @param peer        The peer to send the request to
     * @param userContext the user context to use.
     * @return a {@link BlockchainInfo} object containing the chain info requested
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockchainInfo queryBlockchainInfo(Peer peer, User userContext) throws ProposalException, InvalidArgumentException {

        return queryBlockchainInfo(Collections.singleton(peer), userContext);

    }

    /**
     * query for chain information
     *
     * @param peers       The peers to try send the request.
     * @param userContext the user context.
     * @return a {@link BlockchainInfo} object containing the chain info requested
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public BlockchainInfo queryBlockchainInfo(Collection<Peer> peers, User userContext) throws ProposalException, InvalidArgumentException {

        checkChannelState();
        checkPeers(peers);
        User.userContextCheck(userContext);

        try {
            logger.debug("queryBlockchainInfo to peer " + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(userContext);
            querySCCRequest.setFcn(QuerySCCRequest.GETCHAININFO);
            querySCCRequest.setArgs(name);

            ProposalResponse proposalResponse = sendProposalSerially(querySCCRequest, peers);

            return new BlockchainInfo(Ledger.BlockchainInfo.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (Exception e) {
            logger.error(e);
            throw new ProposalException(e);
        }
    }

    /**
     * Query this channel for a Fabric Transaction given its transactionID.
     * The request is sent to a random peer in the channel.
     * <p>
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param txID the ID of the transaction
     * @return a {@link TransactionInfo}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    public TransactionInfo queryTransactionByID(String txID) throws ProposalException, InvalidArgumentException {
        return queryTransactionByID(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), txID, client.getUserContext());
    }

    /**
     * Query this channel for a Fabric Transaction given its transactionID.
     * The request is sent to a random peer in the channel.
     * <p>
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param txID        the ID of the transaction
     * @param userContext the user context used.
     * @return a {@link TransactionInfo}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    public TransactionInfo queryTransactionByID(String txID, User userContext) throws ProposalException, InvalidArgumentException {
        return queryTransactionByID(getShuffledPeers(EnumSet.of(PeerRole.LEDGER_QUERY)), txID, userContext);
    }

    /**
     * Query for a Fabric Transaction given its transactionID
     * <p>
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param txID the ID of the transaction
     * @param peer the peer to send the request to
     * @return a {@link TransactionInfo}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    public TransactionInfo queryTransactionByID(Peer peer, String txID) throws ProposalException, InvalidArgumentException {
        return queryTransactionByID(Collections.singleton(peer), txID, client.getUserContext());
    }

    /**
     * Query for a Fabric Transaction given its transactionID
     *
     * @param peer        the peer to send the request to
     * @param txID        the ID of the transaction
     * @param userContext the user context
     * @return a {@link TransactionInfo}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    public TransactionInfo queryTransactionByID(Peer peer, String txID, User userContext) throws ProposalException, InvalidArgumentException {
        return queryTransactionByID(Collections.singleton(peer), txID, userContext);
    }

    /**
     * Query for a Fabric Transaction given its transactionID
     *
     * @param txID        the ID of the transaction
     * @param peers       the peers to try to send the request.
     * @param userContext the user context
     * @return a {@link TransactionInfo}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    public TransactionInfo queryTransactionByID(Collection<Peer> peers, String txID, User userContext) throws ProposalException, InvalidArgumentException {

        checkChannelState();
        checkPeers(peers);
        User.userContextCheck(userContext);

        if (txID == null) {
            throw new InvalidArgumentException("TxID parameter is null.");
        }

        TransactionInfo transactionInfo;
        try {
            logger.debug("queryTransactionByID with txID " + txID + "\n    from peer " + " on channel " + name);
            QuerySCCRequest querySCCRequest = new QuerySCCRequest(userContext);
            querySCCRequest.setFcn(QuerySCCRequest.GETTRANSACTIONBYID);
            querySCCRequest.setArgs(name, txID);

            ProposalResponse proposalResponse = sendProposalSerially(querySCCRequest, peers);

            return new TransactionInfo(txID, ProcessedTransaction.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
        } catch (Exception e) {

            logger.error(e);

            throw new ProposalException(e);
        }
    }

    /////////////////////////////////////////////////////////
    // transactions order

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
     * <p>
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     * </P>
     *
     * @param peer The peer to query.
     * @return A list of ChaincodeInfo @see {@link ChaincodeInfo}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public List<ChaincodeInfo> queryInstantiatedChaincodes(Peer peer) throws InvalidArgumentException, ProposalException {
        return queryInstantiatedChaincodes(peer, client.getUserContext());

    }

    /**
     * Query peer for chaincode that has been instantiated
     *
     * @param peer        The peer to query.
     * @param userContext the user context.
     * @return A list of ChaincodeInfo @see {@link ChaincodeInfo}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public List<ChaincodeInfo> queryInstantiatedChaincodes(Peer peer, User userContext) throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeer(peer);
        User.userContextCheck(userContext);

        try {

            TransactionContext context = getTransactionContext(userContext);

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

        return sendProposal(transactionProposalRequest, getEndorsingPeers());
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
        return queryByChaincode(queryByChaincodeRequest, getChaincodeQueryPeers());
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
    ////////////////  Channel Block monitoring //////////////////////////////////

    private ProposalResponse sendProposalSerially(TransactionRequest proposalRequest, Collection<Peer> peers) throws
            ProposalException {

        ProposalException lastException = new ProposalException("ProposalRequest failed.");

        for (Peer peer : peers) {

            try {

                Collection<ProposalResponse> proposalResponses = sendProposal(proposalRequest, Collections.singletonList(peer));

                if (proposalResponses.isEmpty()) {
                    logger.warn(format("Proposal request to peer %s failed", peer));
                }
                ProposalResponse proposalResponse = proposalResponses.iterator().next();
                ChaincodeResponse.Status status = proposalResponse.getStatus();

                if (status.getStatus() < 400) {
                    return proposalResponse;

                } else if (status.getStatus() > 499) { // server error may work on other peer.

                    lastException = new ProposalException(format("Channel %s got exception on peer %s %d. %s ",
                            name,
                            peer,
                            status.getStatus(),
                            proposalResponse.getMessage()));

                } else { // 400 to 499

                    throw new ProposalException(format("Channel %s got exception on peer %s %d. %s ",
                            name,
                            peer,
                            status.getStatus(),
                            proposalResponse.getMessage()));
                }

            } catch (Exception e) {

                lastException = new ProposalException(format("Channel %s failed proposal on peer %s  %s",
                        name,
                        peer.getName(),

                        e.getMessage()), e);
                logger.warn(lastException.getMessage());
            }

        }

        throw lastException;

    }

    private Collection<ProposalResponse> sendProposal(TransactionRequest proposalRequest, Collection<Peer> peers) throws
            InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeers(peers);

        if (null == proposalRequest) {
            throw new InvalidArgumentException("The proposalRequest is null");
        }

        if (Utils.isNullOrEmpty(proposalRequest.getFcn())) {
            throw new InvalidArgumentException("The proposalRequest's fcn is null or empty.");
        }

        if (proposalRequest.getChaincodeID() == null) {
            throw new InvalidArgumentException("The proposalRequest's chaincode ID is null");
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

        if (transactionContext.getVerify()) {
            try {
                loadCACertificates();
            } catch (Exception e) {
                throw new ProposalException(e);
            }
        }

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

    public static class NOfEvents {

        public NOfEvents setN(int n) {
            if (n < 1) {

                throw new IllegalArgumentException(format("N was %d but needs to be greater than 0.  ", n));

            }
            this.n = n;
            return this;
        }

        boolean ready = false;
        boolean started = false;

        private long n = Long.MAX_VALUE; //all

        private HashSet<EventHub> eventHubs = new HashSet<>();
        private HashSet<Peer> peers = new HashSet<>();
        private HashSet<NOfEvents> nOfEvents = new HashSet<>();

        public NOfEvents addPeers(Peer... peers) {
            if (peers == null || peers.length == 0) {
                throw new IllegalArgumentException("Peers added must be not null or empty.");
            }
            this.peers.addAll(Arrays.asList(peers));

            return this;

        }

        public NOfEvents addPeers(Collection<Peer> peers) {
            addPeers(peers.toArray(new Peer[peers.size()]));
            return this;
        }

        public NOfEvents addEventHubs(EventHub... eventHubs) {
            if (eventHubs == null || eventHubs.length == 0) {
                throw new IllegalArgumentException("EventHubs added must be not null or empty.");
            }
            this.eventHubs.addAll(Arrays.asList(eventHubs));

            return this;

        }

        public NOfEvents addEventHubs(Collection<EventHub> eventHubs) {
            addEventHubs(eventHubs.toArray(new EventHub[eventHubs.size()]));
            return this;
        }

        public NOfEvents addNOfs(NOfEvents... nOfEvents) {
            if (nOfEvents == null || nOfEvents.length == 0) {
                throw new IllegalArgumentException("nofEvents added must be not null or empty.");
            }

            for (NOfEvents n : nOfEvents) {
                if (nofNoEvents == n) {
                    throw new IllegalArgumentException("nofNoEvents may not be added as an event.");
                }
                if (inHayStack(n)) {
                    throw new IllegalArgumentException("nofEvents already was added..");
                }
                this.nOfEvents.add(new NOfEvents(n));
            }

            return this;
        }

        private boolean inHayStack(NOfEvents needle) {
            if (this == needle) {
                return true;
            }
            for (NOfEvents straw : nOfEvents) {
                if (straw.inHayStack(needle)) {
                    return true;
                }
            }
            return false;
        }

        public NOfEvents addNOfs(Collection<NOfEvents> nofs) {
            addNOfs(nofs.toArray(new NOfEvents[nofs.size()]));
            return this;
        }

        synchronized Collection<Peer> unSeenPeers() {

            Set<Peer> unseen = new HashSet(16);
            unseen.addAll(peers);
            for (NOfEvents nOfEvents : nOfEvents) {
                unseen.addAll(nofNoEvents.unSeenPeers());
            }
            return unseen;
        }

        synchronized Collection<EventHub> unSeenEventHubs() {

            Set<EventHub> unseen = new HashSet(16);
            unseen.addAll(eventHubs);
            for (NOfEvents nOfEvents : nOfEvents) {
                unseen.addAll(nofNoEvents.unSeenEventHubs());
            }
            return unseen;
        }

        synchronized boolean seen(EventHub eventHub) {
            if (!started) {
                started = true;
                n = Long.min(eventHubs.size() + peers.size() + nOfEvents.size(), n);
            }
            if (!ready) {
                if (eventHubs.remove(eventHub)) {

                    if (--n == 0) {
                        ready = true;
                    }
                }
                if (!ready) {
                    for (Iterator<NOfEvents> ni = nOfEvents.iterator(); ni.hasNext();
                            ) { // for check style
                        NOfEvents e = ni.next();
                        if (e.seen(eventHub)) {
                            ni.remove();

                            if (--n == 0) {
                                ready = true;
                                break;
                            }
                        }
                    }
                }
            }
            if (ready) {

                eventHubs.clear();
                peers.clear();
                nOfEvents.clear();

            }
            return ready;
        }

        synchronized boolean seen(Peer peer) {
            if (!started) {
                started = true;
                n = Long.min(eventHubs.size() + peers.size() + nOfEvents.size(), n);
            }
            if (!ready) {

                if (peers.remove(peer)) {
                    if (--n == 0) {
                        ready = true;
                    }
                }
                if (!ready) {

                    for (Iterator<NOfEvents> ni = nOfEvents.iterator(); ni.hasNext();
                            ) { // for check style
                        NOfEvents e = ni.next();
                        if (e.seen(peer)) {
                            ni.remove();

                            if (--n == 0) {
                                ready = true;
                                break;
                            }
                        }
                    }
                }
            }
            if (ready) {

                eventHubs.clear();
                peers.clear();
                nOfEvents.clear();
            }
            return ready;
        }

        NOfEvents(NOfEvents nof) { // Deep Copy.
            if (nofNoEvents == nof) {
                throw new IllegalArgumentException("nofNoEvents may not be copied.");
            }
            ready = false; // no use in one set to ready.
            started = false;
            this.n = nof.n;
            this.peers = new HashSet<>(nof.peers);
            this.eventHubs = new HashSet<>(nof.eventHubs);
            for (NOfEvents nofc : nof.nOfEvents) {
                this.nOfEvents.add(new NOfEvents(nofc));

            }
        }

        private NOfEvents() {

        }

        public static NOfEvents createNofEvents() {
            return new NOfEvents();
        }

        public static NOfEvents nofNoEvents = new NOfEvents() {
            @Override
            public NOfEvents addNOfs(NOfEvents... nOfEvents) {
                throw new IllegalArgumentException("Can not add any events.");
            }

            @Override
            public NOfEvents addEventHubs(EventHub... eventHub) {
                throw new IllegalArgumentException("Can not add any events.");
            }

            @Override
            public NOfEvents addPeers(Peer... peers) {
                throw new IllegalArgumentException("Can not add any events.");
            }

            @Override
            public NOfEvents setN(int n) {
                throw new IllegalArgumentException("Can not set N");
            }

            @Override
            public NOfEvents addEventHubs(Collection<EventHub> eventHubs) {
                throw new IllegalArgumentException("Can not add any events.");
            }

            @Override
            public NOfEvents addPeers(Collection<Peer> peers) {
                throw new IllegalArgumentException("Can not add any events.");
            }
        };

        static {
            nofNoEvents.ready = true;
        }

        public static NOfEvents createNoEvents() {
            return nofNoEvents;

        }

    }

    /**
     * Send transaction to one of a specified set of orderers with the specified user context.
     * IF there are no event hubs or eventing peers this future returns immediately completed
     * indicating that orderer has accepted the transaction only.
     *
     * @param proposalResponses
     * @param orderers
     * @return Future allowing access to the result of the transaction invocation.
     */

    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses, Collection<Orderer> orderers, User userContext) {
        return sendTransaction(proposalResponses, createTransactionOptions().orderers(orderers).userContext(userContext));
    }

    public static class TransactionOptions {
        List<Orderer> orderers;
        boolean shuffleOrders = true;
        NOfEvents nOfEvents;
        User userContext;
        boolean failFast = true;

        /**
         * Fail fast when there is an invalid transaction received on the eventhub or eventing peer being observed.
         * The default value is true.
         *
         * @param failFast fail fast.
         * @return This TransactionOptions
         */
        public TransactionOptions failFast(boolean failFast) {
            this.failFast = failFast;
            return this;
        }

        /**
         * The user context that is to be used. The default is the user context on the client.
         *
         * @param userContext
         * @return This TransactionOptions
         */
        public TransactionOptions userContext(User userContext) {
            this.userContext = userContext;
            return this;
        }

        /**
         * The orders to try on this transaction. Each order is tried in turn for a successful submission.
         * The default is try all orderers on the chain.
         *
         * @param orderers the orderers to try.
         * @return This TransactionOptions
         */
        public TransactionOptions orderers(Orderer... orderers) {
            this.orderers = new ArrayList(Arrays.asList(orderers)); //convert make sure we have a copy.
            return this;
        }

        /**
         * Shuffle the order the Orderers are tried. The default is true.
         *
         * @param shuffleOrders
         * @return This TransactionOptions
         */
        public TransactionOptions shuffleOrders(boolean shuffleOrders) {
            this.shuffleOrders = shuffleOrders;
            return this;
        }

        /**
         * Events reporting Eventing Peers and EventHubs to complete the transaction.
         * This maybe set to NOfEvents.nofNoEvents that will complete the future as soon as a successful submission
         * to an Orderer, but the completed Transaction event in that case will be null.
         *
         * @param nOfEvents
         * @return This TransactionOptions
         */
        public TransactionOptions nOfEvents(NOfEvents nOfEvents) {
            this.nOfEvents = nOfEvents == NOfEvents.nofNoEvents ? nOfEvents : new NOfEvents(nOfEvents);
            return this;
        }

        /**
         * Create transaction options.
         *
         * @return return transaction options.
         */
        public static TransactionOptions createTransactionOptions() {
            return new TransactionOptions();
        }

        /**
         * The orders to try on this transaction. Each order is tried in turn for a successful submission.
         * The default is try all orderers on the chain.
         *
         * @param orderers the orderers to try.
         * @return This TransactionOptions
         */
        public TransactionOptions orderers(Collection<Orderer> orderers) {
            return orderers(orderers.toArray(new Orderer[orderers.size()]));
        }
    }

    /**
     * Send transaction to one of a specified set of orderers with the specified user context.
     * IF there are no event hubs or eventing peers this future returns immediately completed
     * indicating that orderer has accepted the transaction only.
     *
     * @param proposalResponses
     * @param transactionOptions
     * @return Future allowing access to the result of the transaction invocation.
     */

    public CompletableFuture<TransactionEvent> sendTransaction(Collection<ProposalResponse> proposalResponses,
                                                               TransactionOptions transactionOptions) {
        try {

            if (null == transactionOptions) {
                throw new InvalidArgumentException("Parameter transactionOptions can't be null");
            }
            checkChannelState();
            User userContext = transactionOptions.userContext != null ? transactionOptions.userContext : client.getUserContext();
            userContextCheck(userContext);
            if (null == proposalResponses) {
                throw new InvalidArgumentException("sendTransaction proposalResponses was null");
            }

            List<Orderer> orderers = transactionOptions.orderers != null ? transactionOptions.orderers :
                    new ArrayList<>(getOrderers());

            // make certain we have our own copy
            final List<Orderer> shuffeledOrderers = new ArrayList<>(orderers);

            if (transactionOptions.shuffleOrders) {
                Collections.shuffle(shuffeledOrderers);
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

            NOfEvents nOfEvents = transactionOptions.nOfEvents;

            if (nOfEvents == null) {
                nOfEvents = NOfEvents.createNofEvents();
                Collection<Peer> eventingPeers = getEventingPeers();
                boolean anyAdded = false;
                if (!eventingPeers.isEmpty()) {
                    anyAdded = true;
                    nOfEvents.addPeers(eventingPeers);
                }
                Collection<EventHub> eventHubs = getEventHubs();
                if (!eventHubs.isEmpty()) {
                    anyAdded = true;
                    nOfEvents.addEventHubs(getEventHubs());
                }

                if (!anyAdded) {
                    nOfEvents = NOfEvents.createNoEvents();
                }

            } else if (nOfEvents != NOfEvents.nofNoEvents) {
                StringBuilder issues = new StringBuilder(100);
                Collection<Peer> eventingPeers = getEventingPeers();
                nOfEvents.unSeenPeers().forEach(peer -> {
                    if (peer.getChannel() != this) {
                        issues.append(format("Peer %s added to NOFEvents does not belong this channel. ", peer.getName()));

                    } else if (!eventingPeers.contains(peer)) {
                        issues.append(format("Peer %s added to NOFEvents is not a eventing Peer in this channel. ", peer.getName()));
                    }

                });
                nOfEvents.unSeenEventHubs().forEach(eventHub -> {
                    if (!eventHubs.contains(eventHub)) {
                        issues.append(format("Eventhub %s added to NOFEvents does not belong this channel. ", eventHub.getName()));
                    }

                });

                if (nOfEvents.unSeenEventHubs().isEmpty() && nOfEvents.unSeenPeers().isEmpty()) {
                    issues.append("NofEvents had no Eventhubs added or Peer eventing services.");
                }
                String foundIssues = issues.toString();
                if (!foundIssues.isEmpty()) {
                    throw new InvalidArgumentException(foundIssues);
                }
            }

            final boolean replyonly = nOfEvents == NOfEvents.nofNoEvents || (getEventHubs().isEmpty() && getEventingPeers().isEmpty());

            CompletableFuture<TransactionEvent> sret;
            if (replyonly) { //If there are no eventhubs to complete the future, complete it
                // immediately but give no transaction event
                logger.debug(format("Completing transaction id %s immediately no event hubs or peer eventing services found in channel %s.", proposalTransactionID, name));
                sret = new CompletableFuture<>();
            } else {
                sret = registerTxListener(proposalTransactionID, nOfEvents, transactionOptions.failFast);
            }

            logger.debug(format("Channel %s sending transaction to orderer(s) with TxID %s ", name, proposalTransactionID));
            boolean success = false;
            Exception lException = null; // Save last exception to report to user .. others are just logged.

            BroadcastResponse resp = null;
            Orderer failed = null;
            for (Orderer orderer : shuffeledOrderers) {
                if (failed != null) {
                    logger.warn(format("Channel %s  %s failed. Now trying %s.", name, failed, orderer));
                }
                failed = orderer;
                try {

                    if (null != diagnosticFileDumper) {
                        logger.trace(format("Sending to channel %s, orderer: %s, transaction: %s", name, orderer.getName(),
                                diagnosticFileDumper.createDiagnosticProtobufFile(transactionEnvelope.toByteArray())));
                    }

                    resp = orderer.sendTransaction(transactionEnvelope);
                    lException = null; // no longer last exception .. maybe just failed.
                    if (resp.getStatus() == Status.SUCCESS) {
                        success = true;
                        break;
                    } else {
                        logger.warn(format("Channel %s %s failed. Status returned %s", name, orderer, getRespData(resp)));
                    }
                } catch (Exception e) {
                    String emsg = format("Channel %s unsuccessful sendTransaction to orderer %s (%s)",
                            name, orderer.getName(), orderer.getUrl());
                    if (resp != null) {

                        emsg = format("Channel %s unsuccessful sendTransaction to orderer %s (%s).  %s",
                                name, orderer.getName(), orderer.getUrl(), getRespData(resp));
                    }

                    logger.error(emsg);
                    lException = new Exception(emsg, e);

                }

            }

            if (success) {
                logger.debug(format("Channel %s successful sent to Orderer transaction id: %s",
                        name, proposalTransactionID));
                if (replyonly) {
                    sret.complete(null); // just say we're done.
                }
                return sret;
            } else {

                String emsg = format("Channel %s failed to place transaction %s on Orderer. Cause: UNSUCCESSFUL. %s",
                        name, proposalTransactionID, getRespData(resp));

                unregisterTxListener(proposalTransactionID);

                CompletableFuture<TransactionEvent> ret = new CompletableFuture<>();
                ret.completeExceptionally(lException != null ? new Exception(emsg, lException) : new Exception(emsg));
                return ret;
            }
        } catch (Exception e) {

            CompletableFuture<TransactionEvent> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;

        }

    }

    /**
     * Build response details
     *
     * @param resp
     * @return
     */
    private String getRespData(BroadcastResponse resp) {

        StringBuilder respdata = new StringBuilder(400);
        if (resp != null) {
            Status status = resp.getStatus();
            if (null != status) {
                respdata.append(status.name());
                respdata.append("-");
                respdata.append(status.getNumber());
            }

            String info = resp.getInfo();
            if (null != info && !info.isEmpty()) {
                if (respdata.length() > 0) {
                    respdata.append(", ");
                }

                respdata.append("Additional information: ").append(info);

            }

        }

        return respdata.toString();

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

    /**
     * Register a block listener.
     *
     * @param listener function with single argument with type {@link BlockEvent}
     * @return The handle of the registered block listener.
     * @throws InvalidArgumentException if the channel is shutdown.
     */
    public String registerBlockListener(BlockListener listener) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        return new BL(listener).getHandle();

    }

    /**
     * Unregister a block listener.
     *
     * @param handle of Block listener to remove.
     * @return false if not found.
     * @throws InvalidArgumentException if the channel is shutdown or invalid arguments.
     */
    public boolean unregisterBlockListener(String handle) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        checkHandle(BLOCK_LISTENER_TAG, handle);

        synchronized (blockListeners) {

            return null != blockListeners.remove(handle);

        }
    }
    //////////  Transaction monitoring  /////////////////////////////

    private void startEventQue() {

        if (eventQueueThread != null) {
            return;
        }

        client.getExecutorService().execute(() -> {
            eventQueueThread = Thread.currentThread();

            while (!shutdown) {
                if (!initialized) {
                    try {
                        logger.debug("not intialized:" + initialized);
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        logger.warn(e);
                    }
                    continue; //wait on sending events till the channel is initialized.
                }
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
                    logger.warn("GOT null block event.");
                    continue;
                }

                try {

                    final String blockchainID = blockEvent.getChannelId();
                    final String from =
                            format("Channel %s eventqueue got block event with block number: %d for channel: %s, from %s",
                                    name, blockEvent.getBlockNumber(), blockchainID, blockEvent.getPeer() != null ? ("Peer: " + blockEvent.getPeer().getName()) :
                                            ("Eventhub: " + blockEvent.getEventHub().getName()));

                    logger.trace(from);

                    if (!Objects.equals(name, blockchainID)) {
                        logger.warn(format("Channel %s eventqueue got block event NOT FOR ME  channelId %s  from %s", name, blockchainID, from));
                        continue; // not targeted for this channel
                    }

                    final ArrayList<BL> blcopy = new ArrayList<>(blockListeners.size() + 3);
                    synchronized (blockListeners) {
                        blcopy.addAll(blockListeners.values());
                    }

                    for (BL l : blcopy) {
                        try {
                            logger.trace(format("Sending block event '%s' to block listener %s", from, l.handle));
                            client.getExecutorService().execute(() -> l.listener.received(blockEvent));
                        } catch (Throwable e) { //Don't let one register stop rest.
                            logger.error(format("Error calling block listener %s on channel: %s event: %s ", l.handle, name, from), e);
                        }
                    }
                } catch (Exception e) {
                    logger.error("Unable to parse event", e);
                    logger.debug("event:\n)");
                    logger.debug(blockEvent.toString());
                }
            }
        });

    }

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
                        if (l.eventReceived(transactionEvent)) {
                            l.fire(transactionEvent);
                        }

                    } catch (Throwable e) {
                        logger.error(e); // Don't let one register stop rest.
                    }
                }
            }
        });
    }

    void runSweeper() {

        if (shutdown || DELTA_SWEEP < 1) {
            return;
        }

        if (sweeper == null) {

            sweeper = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = Executors.defaultThreadFactory().newThread(r);
                t.setDaemon(true);
                return t;
            }).scheduleAtFixedRate(() -> {
                try {

                    if (txListeners != null) {

                        synchronized (txListeners) {

                            for (Iterator<Map.Entry<String, LinkedList<TL>>> it = txListeners.entrySet().iterator(); it.hasNext();
                                    ) {

                                Map.Entry<String, LinkedList<TL>> es = it.next();

                                LinkedList<TL> tlLinkedList = es.getValue();
                                tlLinkedList.removeIf(TL::sweepMe);
                                if (tlLinkedList.isEmpty()) {
                                    it.remove();
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Sweeper got error:" + e.getMessage(), e);
                }

            }, 0, DELTA_SWEEP, TimeUnit.MILLISECONDS);
        }

    }

    /**
     * Register a transactionId that to get notification on when the event is seen in the block chain.
     *
     * @param txid
     * @param nOfEvents
     * @return
     */

    private CompletableFuture<TransactionEvent> registerTxListener(String txid, NOfEvents nOfEvents, boolean failFast) {

        CompletableFuture<TransactionEvent> future = new CompletableFuture<>();

        new TL(txid, future, nOfEvents, failFast);

        return future;

    }

    /**
     * Unregister a transactionId
     *
     * @param txid
     */
    private void unregisterTxListener(String txid) {

        synchronized (txListeners) {

            txListeners.remove(txid);
        }

    }

    /**
     * Register a chaincode event listener. Both chaincodeId pattern AND eventName pattern must match to invoke
     * the chaincodeEventListener
     *
     * @param chaincodeId            Java pattern for chaincode identifier also know as chaincode name. If ma
     * @param eventName              Java pattern to match the event name.
     * @param chaincodeEventListener The listener to be invoked if both chaincodeId and eventName pattern matches.
     * @return Handle to be used to unregister the event listener {@link #unregisterChaincodeEventListener(String)}
     * @throws InvalidArgumentException
     */

    public String registerChaincodeEventListener(Pattern chaincodeId, Pattern eventName, ChaincodeEventListener chaincodeEventListener) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (chaincodeId == null) {
            throw new InvalidArgumentException("The chaincodeId argument may not be null.");
        }

        if (eventName == null) {
            throw new InvalidArgumentException("The eventName argument may not be null.");
        }

        if (chaincodeEventListener == null) {
            throw new InvalidArgumentException("The chaincodeEventListener argument may not be null.");
        }

        ChaincodeEventListenerEntry chaincodeEventListenerEntry = new ChaincodeEventListenerEntry(chaincodeId, eventName, chaincodeEventListener);
        synchronized (this) {
            if (null == blh) {
                blh = registerChaincodeListenerProcessor();
            }
        }
        return chaincodeEventListenerEntry.handle;

    }

    /**
     * Unregister an existing chaincode event listener.
     *
     * @param handle Chaincode event listener handle to be unregistered.
     * @return True if the chaincode handler was found and removed.
     * @throws InvalidArgumentException
     */

    public boolean unregisterChaincodeEventListener(String handle) throws InvalidArgumentException {
        boolean ret;

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        checkHandle(CHAINCODE_EVENTS_TAG, handle);

        synchronized (chainCodeListeners) {
            ret = null != chainCodeListeners.remove(handle);

        }

        synchronized (this) {
            if (null != blh && chainCodeListeners.isEmpty()) {

                unregisterBlockListener(blh);
                blh = null;
            }
        }

        return ret;

    }

    ////////////////////////////////////////////////////////////////////////
    ////////////////  Chaincode Events..  //////////////////////////////////

    private String registerChaincodeListenerProcessor() throws InvalidArgumentException {
        logger.debug(format("Channel %s registerChaincodeListenerProcessor starting", name));

        // Chaincode event listener is internal Block listener for chaincode events.

        return registerBlockListener(blockEvent -> {

            if (chainCodeListeners.isEmpty()) {
                return;
            }

            LinkedList<ChaincodeEvent> chaincodeEvents = new LinkedList<>();

            //Find the chaincode events in the transactions.

            for (TransactionEvent transactionEvent : blockEvent.getTransactionEvents()) {

                logger.debug(format("Channel %s got event for transaction %s ", name, transactionEvent.getTransactionID()));

                for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo info : transactionEvent.getTransactionActionInfos()) {

                    ChaincodeEvent event = info.getEvent();
                    if (null != event) {
                        chaincodeEvents.add(event);
                    }

                }

            }

            if (!chaincodeEvents.isEmpty()) {

                class MatchPair {
                    final ChaincodeEventListenerEntry eventListener;
                    final ChaincodeEvent event;

                    MatchPair(ChaincodeEventListenerEntry eventListener, ChaincodeEvent event) {
                        this.eventListener = eventListener;
                        this.event = event;
                    }
                }

                List<MatchPair> matches = new LinkedList<MatchPair>(); //Find matches.

                synchronized (chainCodeListeners) {

                    for (ChaincodeEventListenerEntry chaincodeEventListenerEntry : chainCodeListeners.values()) {

                        for (ChaincodeEvent chaincodeEvent : chaincodeEvents) {

                            if (chaincodeEventListenerEntry.isMatch(chaincodeEvent)) {

                                matches.add(new MatchPair(chaincodeEventListenerEntry, chaincodeEvent));
                            }

                        }

                    }
                }

                //fire events
                for (MatchPair match : matches) {

                    ChaincodeEventListenerEntry chaincodeEventListenerEntry = match.eventListener;
                    ChaincodeEvent ce = match.event;
                    chaincodeEventListenerEntry.fire(blockEvent, ce);

                }

            }

        });
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
        if (chainCodeListeners != null) {
            chainCodeListeners.clear();

        }

        if (blockListeners != null) {
            blockListeners.clear();
        }

        if (client != null) {
            client.removeChannel(this);
        }

        client = null;

        for (EventHub eh : eventHubs) {

            try {
                eh.shutdown();
            } catch (Exception e) {
                // Best effort.
            }

        }
        eventHubs.clear();
        for (Peer peer : new ArrayList<>(getPeers())) {

            try {
                removePeerInternal(peer);
                peer.shutdown(force);
            } catch (Exception e) {
                // Best effort.
            }
        }
        peers.clear(); // make sure.

        //Make sure
        for (Set<Peer> peerRoleSet : peerRoleSetMap.values()) {
            peerRoleSet.clear();
        }

        for (Orderer orderer : getOrderers()) {
            orderer.shutdown(force);
        }

        orderers.clear();

        if (null != eventQueueThread) {

            if (eventQueueThread != null) {
                eventQueueThread.interrupt();
            }
            eventQueueThread = null;
        }
        ScheduledFuture<?> lsweeper = sweeper;
        sweeper = null;

        if (null != lsweeper) {
            lsweeper.cancel(true);
        }
    }

    /**
     * Serialize channel to a file using Java serialization.
     * Deserialized channel will NOT be in an initialized state.
     *
     * @param file file
     * @throws IOException
     * @throws InvalidArgumentException
     */

    public void serializeChannel(File file) throws IOException, InvalidArgumentException {

        if (null == file) {
            throw new InvalidArgumentException("File parameter may not be null");
        }

        Files.write(Paths.get(file.getAbsolutePath()), serializeChannel(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);

    }

    /**
     * Serialize channel to a byte array using Java serialization.
     * Deserialized channel will NOT be in an initialized state.
     *
     * @throws InvalidArgumentException
     * @throws IOException
     */
    public byte[] serializeChannel() throws IOException, InvalidArgumentException {

        if (isShutdown()) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", getName()));
        }

        ObjectOutputStream out = null;

        try {
            ByteArrayOutputStream bai = new ByteArrayOutputStream();
            out = new ObjectOutputStream(bai);
            out.writeObject(this);
            out.flush();
            return bai.toByteArray();
        } finally {
            if (null != out) {
                try {
                    out.close();
                } catch (IOException e) {
                    logger.error(e); // best effort.
                }
            }
        }

    }

    @Override
    protected void finalize() throws Throwable {
        shutdown(true);
        super.finalize();

    }

    /**
     * Options for the peer.
     * These options are channel based.
     */
    public static class PeerOptions implements Cloneable, Serializable {
        private static final long serialVersionUID = -6906605662806520793L;

        protected EnumSet<PeerRole> peerRoles;
        protected Boolean newest = true;
        protected Long startEvents;
        protected Long stopEvents = Long.MAX_VALUE;
        protected boolean registerEventsForFilteredBlocks = false;

        /**
         * Is the peer eventing service registered for filtered blocks
         *
         * @return true if filtered blocks will be returned by the peer eventing service.
         */
        public boolean isRegisterEventsForFilteredBlocks() {
            return registerEventsForFilteredBlocks;
        }

        /**
         * Register the peer eventing services to return filtered blocks.
         *
         * @return the PeerOptions instance.
         */

        public PeerOptions registerEventsForFilteredBlocks() {
            registerEventsForFilteredBlocks = true;
            return this;
        }

        /**
         * Register the peer eventing services to return full event blocks.
         *
         * @return the PeerOptions instance.
         */

        public PeerOptions registerEventsForBlocks() {
            registerEventsForFilteredBlocks = false;
            return this;
        }

        /**
         * Get newest block on startup of peer eventing service.
         *
         * @return
         */
        public Boolean getNewest() {
            return newest;
        }

        /**
         * The block number to start getting events from on start up of the peer eventing service..
         *
         * @return the start number
         */

        public Long getStartEvents() {
            return startEvents;
        }

        /**
         * The stopping block number when the peer eventing service will stop sending blocks.
         *
         * @return the stop block number.
         */

        public Long getStopEvents() {
            return stopEvents;
        }

        protected PeerOptions() {

        }

        /**
         * Create an instance of PeerOptions.
         *
         * @return the PeerOptions instance.
         */

        public static PeerOptions createPeerOptions() {
            return new PeerOptions();
        }

        /**
         * Return the roles the peer has.
         *
         * @return the roles {@link PeerRole}
         */

        public EnumSet<PeerRole> getPeerRoles() {
            if (peerRoles == null) {
                return PeerRole.ALL;
            }
            return peerRoles;
        }

        /**
         * Set the roles this peer will have on the chain it will added or joined.
         *
         * @param peerRoles {@link PeerRole}
         * @return This PeerOptions.
         */

        public PeerOptions setPeerRoles(EnumSet<PeerRole> peerRoles) {
            this.peerRoles = peerRoles;
            return this;
        }

        /**
         * Add to the roles this peer will have on the chain it will added or joined.
         *
         * @param peerRole see {@link PeerRole}
         * @return This PeerOptions.
         */

        public PeerOptions addPeerRole(PeerRole peerRole) {

            if (peerRoles == null) {
                peerRoles = EnumSet.noneOf(PeerRole.class);

            }
            peerRoles.add(peerRole);
            return this;
        }

        /**
         * Set the block number the eventing peer will start relieving events.
         *
         * @param start The staring block number.
         * @return This PeerOptions.
         */
        public PeerOptions startEvents(long start) {
            startEvents = start;
            newest = null;

            return this;
        }

        /**
         * This is the default. It will start retrieving events with the newest. Note this is not the
         * next block that is added to the chain  but the current block on the chain.
         *
         * @return This PeerOptions.
         */

        public PeerOptions startEventsNewest() {
            startEvents = null;
            newest = true;

            return this;
        }

        /**
         * The block number to stop sending events.
         *
         * @param stop the number to stop sending events.
         * @return This PeerOptions.
         */
        public PeerOptions stopEvents(long stop) {
            stopEvents = stop;
            return this;
        }

        /**
         * Clone.
         *
         * @return return a duplicate of this instance.
         */

        public PeerOptions clone() {
            try {
                return (PeerOptions) super.clone();
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException(e);
            }

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

            if (!event.isBlockEvent()) {
                return false;
            }

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

    class BL {

        final BlockListener listener;
        final String handle;

        BL(BlockListener listener) {

            handle = BLOCK_LISTENER_TAG + Utils.generateUUID() + BLOCK_LISTENER_TAG;
            logger.debug(format("Channel %s blockListener %s starting", name, handle));

            this.listener = listener;
            synchronized (blockListeners) {

                blockListeners.put(handle, this);

            }

        }

        public String getHandle() {
            return handle;
        }
    }

    private class TL {
        final String txID;
        final long createTime = System.currentTimeMillis();
        final AtomicBoolean fired = new AtomicBoolean(false);
        final CompletableFuture<TransactionEvent> future;
        final boolean failFast;
        final Set<Peer> peers;
        final Set<EventHub> eventHubs;
        private final NOfEvents nOfEvents;
        long sweepTime = System.currentTimeMillis() + (long) (DELTA_SWEEP * 1.5);

        TL(String txID, CompletableFuture<TransactionEvent> future, NOfEvents nOfEvents, boolean failFast) {
            this.txID = txID;
            this.future = future;
            this.nOfEvents = new NOfEvents(nOfEvents);
            peers = new HashSet<>(nOfEvents.unSeenPeers());
            eventHubs = new HashSet<>(nOfEvents.unSeenEventHubs());
            this.failFast = failFast;
            addListener();
        }

        /**
         * Record transactions event.
         *
         * @param transactionEvent
         * @return True if transactions have been seen on all eventing peers and eventhubs.
         */
        boolean eventReceived(TransactionEvent transactionEvent) {
            sweepTime = System.currentTimeMillis() + DELTA_SWEEP; //seen activity keep it active.

            final Peer peer = transactionEvent.getPeer();
            final EventHub eventHub = transactionEvent.getEventHub();

            if (peer != null && !peers.contains(peer)) {
                return false;
            }
            if (eventHub != null && !eventHubs.contains(eventHub)) {
                return false;
            }

            if (failFast && !transactionEvent.isValid()) {
                return true;
            }

            if (peer != null) {
                nOfEvents.seen(peer);
                logger.debug(format("Channel %s seen transaction event %s for peer %s", name, txID, peer.getName()));
            } else if (null != eventHub) {
                logger.debug(format("Channel %s seen transaction event %s for eventHub %s", name, txID, eventHub.toString()));
                nOfEvents.seen(eventHub);
            } else {
                logger.error(format("Channel %s seen transaction event %s with no associated peer or eventhub", name, txID));
            }

            boolean isEmpty;
            synchronized (this) {
                isEmpty = nOfEvents.ready;
            }
            return isEmpty;
        }

        private void addListener() {
            runSweeper();
            synchronized (txListeners) {
                LinkedList<TL> tl = txListeners.computeIfAbsent(txID, k -> new LinkedList<>());
                tl.add(this);
            }
        }

        boolean sweepMe() { // Sweeps DO NOT fire future. user needs to put timeout on their futures for timeouts.

            final boolean ret = sweepTime < System.currentTimeMillis() || fired.get() || future.isDone();

            if (IS_DEBUG_LEVEL && ret) {

                StringBuilder sb = new StringBuilder(10000);
                sb.append("Non reporting event hubs:");
                String sep = "";
                for (EventHub eh : nOfEvents.unSeenEventHubs()) {
                    sb.append(sep).append(eh.getName());
                    sep = ",";

                }
                if (sb.length() != 0) {
                    sb.append(". ");

                }
                sep = "Non reporting peers: ";
                for (Peer peer : nOfEvents.unSeenPeers()) {
                    sb.append(sep).append(peer.getName());
                    sep = ",";
                }

                logger.debug(format("Force removing transaction listener after %d ms for transaction %s. %s" +
                                ". sweep timeout: %b, fired: %b, future done:%b",
                        System.currentTimeMillis() - createTime, txID, sb.toString(),
                        sweepTime < System.currentTimeMillis(), fired.get(), future.isDone()));

            }

            return ret;

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
                logger.debug(format("Completing future for channel %s and transaction id: %s", name, txID));
                client.getExecutorService().execute(() -> future.complete(transactionEvent));
            } else {
                logger.debug(format("Completing future as exception for channel %s and transaction id: %s, validation code: %02X",
                        name, txID, transactionEvent.getValidationCode()));
                client.getExecutorService().execute(() -> future.completeExceptionally(
                        new TransactionEventException(format("Received invalid transaction event. Transaction ID %s status %s",
                                transactionEvent.getTransactionID(),
                                transactionEvent.getValidationCode()),
                                transactionEvent)));
            }
        }

    }

    private class ChaincodeEventListenerEntry {

        private final Pattern chaincodeIdPattern;
        private final Pattern eventNamePattern;
        private final ChaincodeEventListener chaincodeEventListener;
        private final String handle;

        ChaincodeEventListenerEntry(Pattern chaincodeIdPattern, Pattern eventNamePattern, ChaincodeEventListener chaincodeEventListener) {
            this.chaincodeIdPattern = chaincodeIdPattern;
            this.eventNamePattern = eventNamePattern;
            this.chaincodeEventListener = chaincodeEventListener;
            this.handle = CHAINCODE_EVENTS_TAG + Utils.generateUUID() + CHAINCODE_EVENTS_TAG;

            synchronized (chainCodeListeners) {

                chainCodeListeners.put(handle, this);

            }
        }

        boolean isMatch(ChaincodeEvent chaincodeEvent) {

            return chaincodeIdPattern.matcher(chaincodeEvent.getChaincodeId()).matches() && eventNamePattern.matcher(chaincodeEvent.getEventName()).matches();

        }

        void fire(BlockEvent blockEvent, ChaincodeEvent ce) {

            client.getExecutorService().execute(() -> chaincodeEventListener.received(handle, blockEvent, ce));

        }
    }

}
