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
import java.lang.reflect.Constructor;
import java.net.URI;
import java.net.URISyntaxException;
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
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
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
import org.hyperledger.fabric.protos.common.Configtx;
import org.hyperledger.fabric.protos.common.Configtx.ConfigEnvelope;
import org.hyperledger.fabric.protos.common.Configtx.ConfigGroup;
import org.hyperledger.fabric.protos.common.Configtx.ConfigSignature;
import org.hyperledger.fabric.protos.common.Configtx.ConfigUpdateEnvelope;
import org.hyperledger.fabric.protos.common.Configtx.ConfigValue;
import org.hyperledger.fabric.protos.common.Ledger;
import org.hyperledger.fabric.protos.discovery.Protocol;
import org.hyperledger.fabric.protos.msp.MspConfigPackage;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.protos.orderer.Ab.SeekInfo;
import org.hyperledger.fabric.protos.orderer.Ab.SeekPosition;
import org.hyperledger.fabric.protos.orderer.Ab.SeekSpecified;
import org.hyperledger.fabric.protos.peer.Configuration;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.Query;
import org.hyperledger.fabric.protos.peer.TransactionPackage;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.ServiceDiscovery.SDChaindcode;
import org.hyperledger.fabric.sdk.ServiceDiscovery.SDEndorser;
import org.hyperledger.fabric.sdk.ServiceDiscovery.SDEndorserState;
import org.hyperledger.fabric.sdk.ServiceDiscovery.SDNetwork;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.EventingException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.ServiceDiscoveryException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.certgen.TLSCertificateBuilder;
import org.hyperledger.fabric.sdk.security.certgen.TLSCertificateKeyPair;
import org.hyperledger.fabric.sdk.transaction.GetConfigBlockBuilder;
import org.hyperledger.fabric.sdk.transaction.InstallProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.InstantiateProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.JoinPeerProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleCheckCommitReadinessBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleCommitChaincodeDefinitionProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleInstallProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleQueryChaincodeDefinitionBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleQueryChaincodeDefinitionsBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleQueryInstalledChaincodeBuilder;
import org.hyperledger.fabric.sdk.transaction.LifecycleQueryInstalledChaincodesBuilder;
import org.hyperledger.fabric.sdk.transaction.ProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.ProtoUtils;
import org.hyperledger.fabric.sdk.transaction.QueryCollectionsConfigBuilder;
import org.hyperledger.fabric.sdk.transaction.QueryInstalledChaincodesBuilder;
import org.hyperledger.fabric.sdk.transaction.QueryInstantiatedChaincodesBuilder;
import org.hyperledger.fabric.sdk.transaction.QueryPeerChannelsBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;
import org.hyperledger.fabric.sdk.transaction.UpgradeProposalBuilder;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.Channel.TransactionOptions.createTransactionOptions;
import static org.hyperledger.fabric.sdk.User.userContextCheck;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;
import static org.hyperledger.fabric.sdk.helper.Utils.toHexString;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createSeekInfoEnvelope;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getSignatureHeaderAsByteString;

/**
 * The class representing a channel with which the client SDK interacts.
 * <p>
 */
public class Channel implements Serializable {
    private static final long serialVersionUID = -3266164166893832538L;
    private static final Config config = Config.getConfig();
    private static final Log logger = LogFactory.getLog(Channel.class);
    private static final boolean IS_DEBUG_LEVEL = logger.isDebugEnabled();
    private static final boolean IS_WARN_LEVEL = logger.isWarnEnabled();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

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
    final Collection<Orderer> orderers = Collections.synchronizedCollection(new LinkedList<>());
    private transient Map<String, Orderer> ordererEndpointMap = Collections.synchronizedMap(new HashMap<>());
    // Name of the channel is only meaningful to the client
    private final String name;
    private transient String toString;

    // The peers on this channel to which the client can connect
    private final Collection<Peer> peers = Collections.synchronizedSet(new HashSet<>());
    private final Map<Peer, PeerOptions> peerOptionsMap = Collections.synchronizedMap(new HashMap<>());
    private transient Map<String, Peer> peerEndpointMap = Collections.synchronizedMap(new HashMap<>());
    private final Map<String, Collection<Peer>> peerMSPIDMap = new HashMap<>();
    private final Map<String, Collection<Orderer>> ordererMSPIDMap = new HashMap<>();
    private final Map<PeerRole, Set<Peer>> peerRoleSetMap = Collections.synchronizedMap(new HashMap<>());
    private transient String chaincodeEventUpgradeListenerHandle;
    private transient String transactionListenerProcessorHandle;
    private final boolean systemChannel;
    private transient LinkedHashMap<String, ChaincodeEventListenerEntry> chainCodeListeners = new LinkedHashMap<>();
    transient HFClient client;
    private Set<String> discoveryEndpoints = Collections.synchronizedSet(new HashSet<>());
    /**
     * Runs processing events from peer service.
     */

    transient Thread eventQueueThread = null;
    private transient volatile boolean initialized = false;
    private transient volatile boolean shutdown = false;
    private transient Block genesisBlock;
    private transient Map<String, MSP> msps = new HashMap<>();
    /**
     * A queue each peer eventing service writes to.
     */

    private transient ChannelEventQue channelEventQue = new ChannelEventQue();
    private transient LinkedHashMap<String, BL> blockListeners = new LinkedHashMap<>();
    private transient LinkedHashMap<String, LinkedList<TL>> txListeners = new LinkedHashMap<>();
    //Cleans up any transaction listeners that will probably never complete.
    private transient ScheduledFuture<?> sweeper = null;
    private transient ScheduledExecutorService sweeperExecutorService;
    private transient String blh = null;
    private transient ServiceDiscovery serviceDiscovery;
    private static final boolean asLocalhost = config.discoverAsLocalhost();

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

            sendUpdateChannel(client.getUserContext(), configUpdate.toByteArray(), signers, orderer);
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
        toString = "Channel{id: " + config.getNextID() + ", name: " + name + "}";
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

    @Override
    public String toString() {
        return toString;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {

        in.defaultReadObject();
        toString = "Channel{id: " + config.getNextID() + ", name: " + name + "}";
        initialized = false;
        lastChaincodeUpgradeEventBlock = 0;
        shutdown = false;
        msps = new HashMap<>();
        txListeners = new LinkedHashMap<>();
        channelEventQue = new ChannelEventQue();
        blockListeners = new LinkedHashMap<>();
        peerEndpointMap = Collections.synchronizedMap(new HashMap<>());

        setSDPeerAddition(new SDOPeerDefaultAddition(getServiceDiscoveryProperties()));
        // sdOrdererAddition = DEFAULT_ORDERER_ADDITION;
        endorsementSelector = ServiceDiscovery.DEFAULT_ENDORSEMENT_SELECTION;
        chainCodeListeners = new LinkedHashMap<>();
        for (Peer peer : peers) {
            peerEndpointMap.put(peer.getEndpoint(), peer);
        }

        ordererEndpointMap = Collections.synchronizedMap(new HashMap<>());
        for (Orderer orderer : orderers) {
            ordererEndpointMap.put(orderer.getEndpoint(), orderer);
        }
    }

    /**
     * Update channel with specified channel configuration.
     *
     * <P></P>Note This is not a thread safe operation
     * @param updateChannelConfiguration Updated Channel configuration
     * @param signers                    signers
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public void updateChannelConfiguration(UpdateChannelConfiguration updateChannelConfiguration, byte[]... signers) throws TransactionException, InvalidArgumentException {

        updateChannelConfiguration(client.getUserContext(), updateChannelConfiguration, getRandomOrderer(), signers);

    }

    /**
     * Update channel with specified channel configuration
     * <P></P>Note This is not a thread safe operation
     *
     * @param updateChannelConfiguration Channel configuration
     * @param signers                    signers
     * @param orderer                    The specific orderer to use.
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public void updateChannelConfiguration(UpdateChannelConfiguration updateChannelConfiguration, Orderer orderer, byte[]... signers) throws TransactionException, InvalidArgumentException {
        updateChannelConfiguration(client.getUserContext(), updateChannelConfiguration, orderer, signers);
    }

    /**
     * Update channel with specified channel configuration
     *
     * @param userContext                The specific user to use.
     * @param updateChannelConfiguration Channel configuration
     * @param signers                    signers
     * @param orderer                    The specific orderer to use.
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public void updateChannelConfiguration(User userContext, UpdateChannelConfiguration updateChannelConfiguration, Orderer orderer, byte[]... signers) throws TransactionException, InvalidArgumentException {

        checkChannelState();

        checkOrderer(orderer);

        User.userContextCheck(userContext);

        try {
            final long startLastConfigIndex = getLastConfigIndex(newTransactionContext(userContext), orderer);
            logger.trace(format("startLastConfigIndex: %d. Channel config wait time is: %d",
                    startLastConfigIndex, CHANNEL_CONFIG_WAIT_TIME));

            sendUpdateChannel(userContext, updateChannelConfiguration.getUpdateChannelConfigurationAsBytes(), signers, orderer);

            long currentLastConfigIndex = -1;
            final long nanoTimeStart = System.nanoTime();

            //Try to wait to see the channel got updated but don't fail if we don't see it.
            do {
                currentLastConfigIndex = getLastConfigIndex(newTransactionContext(userContext), orderer);
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

    private void sendUpdateChannel(User userContext, byte[] configupdate, byte[][] signers, Orderer orderer) throws TransactionException, InvalidArgumentException {

        logger.debug(format("Channel %s sendUpdateChannel", name));
        checkOrderer(orderer);

        try {

            final long nanoTimeStart = System.nanoTime();
            int statusCode = 0;

            do {

                //Make sure we have fresh transaction context for each try just to be safe.
                TransactionContext transactionContext = newTransactionContext(userContext);

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

        return addPeer(peer, createPeerOptions());

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

        if (null == peer) {
            throw new InvalidArgumentException("Peer is invalid can not be null.");
        }

        if (peer.getChannel() != null && peer.getChannel() != this) {
            throw new InvalidArgumentException(format("Peer already connected to channel %s", peer.getChannel().getName()));
        }

        if (null == peerOptions) {
            throw new InvalidArgumentException("peerOptions is invalid can not be null.");
        }

        logger.debug(format("%s adding peer: %s, peerOptions: %s", toString(), peer, "" + peerOptions));
        peer.setChannel(this);

        peers.add(peer);
        peerOptionsMap.put(peer, peerOptions.clone());
        peerEndpointMap.put(peer.getEndpoint(), peer);
        addPeerMSPIDMap(peer);

        if (peerOptions.getPeerRoles().contains(PeerRole.SERVICE_DISCOVERY)) {

            final Properties properties = peer.getProperties();
            if ((properties == null) || properties.isEmpty() || (isNullOrEmpty(properties.getProperty("clientCertFile")) &&
                    !properties.containsKey("clientCertBytes"))) {
                TLSCertificateBuilder tlsCertificateBuilder = new TLSCertificateBuilder();
                TLSCertificateKeyPair tlsCertificateKeyPair = tlsCertificateBuilder.clientCert();
                peer.setTLSCertificateKeyPair(tlsCertificateKeyPair);
            }
            discoveryEndpoints.add(peer.getEndpoint());
        }

        for (Map.Entry<PeerRole, Set<Peer>> peerRole : peerRoleSetMap.entrySet()) {
            if (peerOptions.getPeerRoles().contains(peerRole.getKey())) {
                peerRole.getValue().add(peer);

            }
        }

        if (isInitialized() && peerOptions.getPeerRoles().contains(PeerRole.EVENT_SOURCE)) {
            try {
                peer.initiateEventing(newTransactionContext(), getPeersOptions(peer));
            } catch (TransactionException e) {
                logger.error(format("Error channel %s enabling eventing on peer %s", toString(), peer));
            }

        }
        return this;
    }

    private void addPeerMSPIDMap(final Peer peer) {
        Properties properties = peer.getProperties();

        if (null != properties) {
            final String mspid = properties.getProperty(Peer.PEER_ORGANIZATION_MSPID_PROPERTY);
            if (!isNullOrEmpty(mspid)) {
                logger.debug(format("Channel %s mapping peer %s to mspid %s", name, peer, mspid));
                synchronized (peerMSPIDMap) {
                    peerMSPIDMap.computeIfAbsent(mspid, k -> new HashSet<>()).add(peer);
                }
            }
        }
    }

    private void removePeerMSPIDMap(final Peer peer) {
        Properties properties = peer.getProperties();

        if (null != properties) {
            final String mspid = properties.getProperty(Peer.PEER_ORGANIZATION_MSPID_PROPERTY);
            if (!isNullOrEmpty(mspid)) {
                logger.debug(format("Channel %s removing mapping peer %s to mspid %s", name, peer, mspid));
                synchronized (peerMSPIDMap) {
                    final Collection<Peer> peers = peerMSPIDMap.get(mspid);
                    if (peers != null) {
                        peers.remove(peer);
                        if (peers.isEmpty()) {
                            peerMSPIDMap.remove(mspid);
                        }

                    }
                }
            }
        }
    }

    /**
     * Get peers that belong to an organization from the organization's MSPID
     * These values may not be available till after the channel is initialized.
     *
     * @param mspid The organizaiions MSPID
     * @return A collection of Peers that belong to the organization with that mspid.
     * @throws InvalidArgumentException
     */

    public Collection<Peer> getPeersForOrganization(String mspid) throws InvalidArgumentException {

        if (isNullOrEmpty(mspid)) {
            throw new InvalidArgumentException("The mspid parameter may not be null or empty string.");
        }
        synchronized (peerMSPIDMap) {

            final Collection<Peer> peers = peerMSPIDMap.get(mspid);
            if (peers == null) {
                return Collections.emptySet();
            } else {
                return new LinkedList<>(peers); // return a copy.
            }
        }
    }

    /**
     * Collection of strings which are the MSPIDs of all the peer organization added.
     * These values may not be available till after the channel is initialized.
     *
     * @return The collection of mspids
     */

    public Collection<String> getPeersOrganizationMSPIDs() {
        synchronized (peerMSPIDMap) {
            return new LinkedList<>(peerMSPIDMap.keySet());
        }
    }

    /**
     * Join the peer to the channel. The peer is added with all roles see {@link PeerOptions}
     *
     * @param peer the peer to join the channel.
     * @return
     * @throws ProposalException
     */

    public Channel joinPeer(Peer peer) throws ProposalException {
        return joinPeer(peer, createPeerOptions());
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

    private Collection<Peer> getServiceDiscoveryPeers() {

        return Collections.unmodifiableCollection(peerRoleSetMap.get(PeerRole.SERVICE_DISCOVERY));
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

        logger.info(format("%s joining %s.", toString(), peer));

        if (genesisBlock == null && orderers.isEmpty()) {
            ProposalException e = new ProposalException("Channel missing genesis block and no orderers configured");
            logger.error(e.getMessage(), e);
        }
        try {

            genesisBlock = getGenesisBlock(orderer);
            logger.debug(format("Channel %s got genesis block", name));

            final Channel systemChannel = newSystemChannel(client); //channel is not really created and this is targeted to system channel

            TransactionContext transactionContext = systemChannel.newTransactionContext();

            ProposalPackage.Proposal joinProposal = JoinPeerProposalBuilder.newBuilder()
                    .context(transactionContext)
                    .genesisBlock(genesisBlock)
                    .build();

            logger.debug("Getting signed proposal.");
            ProposalPackage.SignedProposal signedProposal = getSignedProposal(transactionContext, joinProposal);
            logger.debug("Got signed proposal.");

            addPeer(peer, peerOptions); //need to add peer.

            Collection<ProposalResponse> resp = sendProposalToPeers(new ArrayList<>(Collections.singletonList(peer)),
                    signedProposal, transactionContext);

            ProposalResponse pro = resp.iterator().next();

            if (pro.getStatus() == ProposalResponse.Status.SUCCESS) {
                logger.info(format("Peer %s joined into channel %s", peer, toString()));
            } else {
                removePeerInternal(peer);
                throw new ProposalException(format("Join peer to channel %s failed.  Status %s, details: %s",
                        name, pro.getStatus().toString(), pro.getMessage()));

            }
        } catch (ProposalException e) {
            logger.error(format("%s removing peer %s due to exception %s", toString(), peer, e.getMessage()));
            removePeerInternal(peer);
            logger.error(e);
            throw e;
        } catch (Exception e) {
            logger.error(format("%s removing peer %s due to exception %s", toString(), peer, e.getMessage()));
            peers.remove(peer);
            removePeerMSPIDMap(peer);
            logger.error(e);
            throw new ProposalException(e.getMessage(), e);
        }

        return this;
    }

    private Block getConfigBlock(List<Peer> peers) throws ProposalException, InvalidArgumentException {
        return getConfigBlock(newTransactionContext(), peers);
    }

    private Block getConfigBlock(TransactionContext transactionContext, List<Peer> peers) throws ProposalException {

        if (shutdown) {
            throw new ProposalException(format("Channel %s has been shutdown.", name));
        }

        if (peers.isEmpty()) {
            throw new ProposalException("No peers go get config block");
        }

        ProposalPackage.SignedProposal signedProposal = null;
        try {

            transactionContext.verify(false); // can't verify till we get the config block.

            ProposalPackage.Proposal proposal = GetConfigBlockBuilder.newBuilder()
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
                        logger.trace(format("getConfigBlock from peer %s on channel %s success", peer, name));
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
        if (shutdown) {
            throw new InvalidArgumentException(format("Can not remove peer from channel %s already shutdown.", name));
        }
        logger.debug(format("removePeer %s from channel %s", peer, toString()));

        checkPeer(peer);
        removePeerInternal(peer);
        peer.shutdown(true);

    }

    private void removePeerInternal(Peer peer) {
        logger.debug(format("RemovePeerInternal %s from channel %s", peer, toString()));

        peers.remove(peer);
        peerOptionsMap.remove(peer);
        peerEndpointMap.remove(peer.getEndpoint());
        removePeerMSPIDMap(peer);

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

        logger.debug(format("Channel %s adding %s", toString(), orderer.toString()));

        orderer.setChannel(this);
        ordererEndpointMap.put(orderer.getEndpoint(), orderer);
        orderers.add(orderer);
        final Properties properties = orderer.getProperties();
        if (properties != null) {
            final String mspid = properties.getProperty(Orderer.ORDERER_ORGANIZATION_MSPID_PROPERTY);
            if (!isNullOrEmpty(mspid)) {
                synchronized (ordererMSPIDMap) {
                    ordererMSPIDMap.computeIfAbsent(mspid, k -> new HashSet<>()).add(orderer);
                }
            }
        }

        return this;
    }

    public void removeOrderer(Orderer orderer) throws InvalidArgumentException {

        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (null == orderer) {
            throw new InvalidArgumentException("Orderer is invalid can not be null.");
        }

        logger.debug(format("Channel %s removing %s", toString(), orderer.toString()));

        ordererEndpointMap.remove(orderer.getEndpoint());
        orderers.remove(orderer);
        orderer.shutdown(true);
        final Properties properties = orderer.getProperties();
        if (properties != null) {
            final String mspid = properties.getProperty(Orderer.ORDERER_ORGANIZATION_MSPID_PROPERTY);
            if (!isNullOrEmpty(mspid)) {
                synchronized (ordererMSPIDMap) {
                    final Collection<Orderer> orderers = ordererMSPIDMap.get(mspid);
                    orderers.remove(orderer);
                    if (orderers.isEmpty()) {
                        ordererMSPIDMap.remove(mspid);
                    }
                }
            }
        }

    }

    /**
     * Get orderers that belong to an organization from the organization's MSPID
     * These values may not be available till after the channel is initialized.
     *
     * @param mspid The organizaiions MSPID
     * @return A collection of Orderers that belong to the organization with that mspid.
     * @throws InvalidArgumentException
     */

    public Collection<Orderer> getOrderersForOrganization(String mspid) throws InvalidArgumentException {

        if (isNullOrEmpty(mspid)) {
            throw new InvalidArgumentException("The mspid parameter may not be null or empty string.");
        }
        synchronized (ordererMSPIDMap) {

            final Collection<Orderer> orderers = ordererMSPIDMap.get(mspid);
            if (orderers == null) {
                return Collections.emptySet();
            } else {
                return new LinkedList<>(orderers); // return a copy.
            }
        }
    }

    /**
     * Collection of strings which are the MSPIDs of all the orderer organization added.
     * These values may not be available till after the channel is initialized.
     *
     * @return The collection of mspids
     */

    public Collection<String> getOrderersOrganizationMSPIDs() {
        synchronized (ordererMSPIDMap) {
            return new LinkedList<>(ordererMSPIDMap.keySet());
        }
    }

    public PeerOptions getPeersOptions(Peer peer) {
        PeerOptions ret = peerOptionsMap.get(peer);
        if (ret != null) {
            ret = ret.clone();
        }
        return ret;

    }

    /**
     * Get the peers for this channel.
     *
     * @return the peers.
     */
    public Collection<Peer> getPeers() {
        return Collections.unmodifiableCollection(new ArrayList<>(peers));
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

    transient volatile long lastChaincodeUpgradeEventBlock = 0;

    private synchronized boolean isChaincodeUpgradeEvent(final long blockNumber) {
        boolean ret = false;
        if (blockNumber > lastChaincodeUpgradeEventBlock) {
            lastChaincodeUpgradeEventBlock = blockNumber;
            ret = true;
        }
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

        if (isInitialized()) {
            return this;
        }

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

        if (null == sdOrdererAddition) {

            setSDOrdererAddition(new SDOrdererDefaultAddition(getServiceDiscoveryProperties()));
        }

        if (null == sdPeerAddition) {

            setSDPeerAddition(new SDOPeerDefaultAddition(getServiceDiscoveryProperties()));

        }

        if (peers.isEmpty()) {
            logger.warn(format("Channel %s has no peers during initialization.", name));

        } else {
            try {
                loadCACertificates(false);  // put all MSP certs into cryptoSuite if this fails here we'll try again later.
            } catch (Exception e) {
                logger.warn(format("Channel %s could not load peer CA certificates from any peers.", name));
            }
        }
        Collection<Peer> serviceDiscoveryPeers = getServiceDiscoveryPeers();
        if (!serviceDiscoveryPeers.isEmpty()) {

            logger.trace("Starting service discovery.");

            this.serviceDiscovery = new ServiceDiscovery(this, serviceDiscoveryPeers, newTransactionContext());
            serviceDiscovery.fullNetworkDiscovery(true);
            serviceDiscovery.run();
            logger.trace("Completed. service discovery.");
        }

        try {

            logger.debug(format("Eventque started %s", "" + eventQueueThread));

            for (Peer peer : getEventingPeers()) {
                peer.initiateEventing(newTransactionContext(), getPeersOptions(peer));
            }

            transactionListenerProcessorHandle = registerTransactionListenerProcessor(); //Manage transactions.
            logger.debug(format("Channel %s registerTransactionListenerProcessor completed", name));

            if (serviceDiscovery != null) {
                chaincodeEventUpgradeListenerHandle = registerChaincodeEventListener(Pattern.compile("^lscc$"), Pattern.compile("^upgrade$"), (handle, blockEvent, chaincodeEvent) -> {
                    logger.debug(format("Channel %s got upgrade chaincode event", name));
                    if (!isShutdown() && isChaincodeUpgradeEvent(blockEvent.getBlockNumber())) {
                        getExecutorService().execute(() -> serviceDiscovery.fullNetworkDiscovery(true));
                    }
                });
            }

            startEventQue(); //Run the event for event messages from event hubs.
            logger.info(format("Channel %s eventThread started shutdown: %b  thread: %s ", toString(), shutdown, eventQueueThread == null ? "null" : eventQueueThread.getName()));

            this.initialized = true;

            logger.debug(format("Channel %s initialized", name));

            return this;

        } catch (Exception e) {
            TransactionException exp = new TransactionException(e);
            logger.error(exp.getMessage(), exp);
            throw exp;
        }

    }

    void sdUpdate(SDNetwork sdNetwork) throws InvalidArgumentException, ServiceDiscoveryException {

        if (shutdown) {
            return;
        }
        logger.debug(format("Channel %s doing channel update for service discovery.", name));
        List<Orderer> remove = new ArrayList<>();
        for (Orderer orderer : getOrderers()) {
            if (!sdNetwork.getOrdererEndpoints().contains(orderer.getEndpoint())) {
                remove.add(orderer);
            }
        }

        remove.forEach(orderer -> {
            try {
                removeOrderer(orderer);
            } catch (InvalidArgumentException e) {
                logger.error(e);
            }
        });

        for (ServiceDiscovery.SDOrderer sdOrderer : sdNetwork.getSDOrderers()) {
            Orderer orderer = ordererEndpointMap.get(sdOrderer.getEndPoint());
            if (shutdown) {
                return;
            }
            if (null == orderer) {
                logger.debug(format("Channel %s doing channel update adding new orderer mspid: %s, endpoint: %s", name, sdOrderer.getMspid(), sdOrderer.getEndPoint()));

                sdOrdererAddition.addOrderer(new SDOrdererAdditionInfo() {

                    @Override
                    public String getEndpoint() {
                        return sdOrderer.getEndPoint();
                    }

                    @Override
                    public String getMspId() {
                        return sdOrderer.getMspid();
                    }

                    @Override
                    public Channel getChannel() {
                        return Channel.this;
                    }

                    @Override
                    public HFClient getClient() {
                        return Channel.this.client;
                    }

                    @Override
                    public byte[][] getTLSCerts() {
                        final Collection<byte[]> tlsCerts = sdOrderer.getTlsCerts();

                        return tlsCerts.toArray(new byte[tlsCerts.size()][]);
                    }

                    @Override
                    public byte[][] getTLSIntermediateCerts() {
                        final Collection<byte[]> tlsCerts = sdOrderer.getTlsIntermediateCerts();

                        return tlsCerts.toArray(new byte[tlsCerts.size()][]);
                    }

                    @Override
                    public Map<String, Orderer> getEndpointMap() {
                        return Collections.unmodifiableMap(Channel.this.ordererEndpointMap);
                    }

                    @Override
                    public Properties getProperties() {
                        return sdOrderer.getProperties();
                    }

                    @Override
                    public boolean isTLS() {
                        return sdOrderer.isTLS();
                    }
                });
            }

        }

        remove.clear();
        List<Peer> removePeers = new ArrayList<>();

        for (Peer peer : getPeers()) {
            if (!sdNetwork.getPeerEndpoints().contains(peer.getEndpoint())) {
                if (!discoveryEndpoints.contains(peer.getEndpoint())) { // never remove discovery endpoints.
                    logger.debug(format("Channel %s doing channel update remove unfound peer endpoint %s ", name, peer.getEndpoint()));
                    removePeers.add(peer);
                }

            }
        }

        removePeers.forEach(peer -> {
            try {

                removePeer(peer);
            } catch (InvalidArgumentException e) {
                logger.error(e);
            }
        });

        for (SDEndorser sdEndorser : sdNetwork.getEndorsers()) {
            final String sdEndorserMspid = sdEndorser.getMspid();
            Peer peer = peerEndpointMap.get(sdEndorser.getEndpoint());
            if (null == peer) {
                if (shutdown) {
                    return;
                }

                logger.debug(format("Channel %s doing channel update found new peer mspid: %s, endpoint: %s", name, sdEndorserMspid, sdEndorser.getEndpoint()));

                sdPeerAddition.addPeer(new SDPeerAdditionInfo() {

                    @Override
                    public String getMspId() {
                        return sdEndorserMspid;
                    }

                    @Override
                    public String getEndpoint() {
                        return sdEndorser.getEndpoint();
                    }

                    @Override
                    public Channel getChannel() {
                        return Channel.this;
                    }

                    @Override
                    public HFClient getClient() {
                        return Channel.this.client;
                    }

                    @Override
                    public byte[][] getTLSCerts() {

                        final Collection<byte[]> tlsCerts = sdEndorser.getTLSCerts();
                        return tlsCerts.toArray(new byte[tlsCerts.size()][]);
                    }

                    @Override
                    public byte[][] getTLSIntermediateCerts() {
                        final Collection<byte[]> tlsCerts = sdEndorser.getTLSIntermediateCerts();

                        return tlsCerts.toArray(new byte[tlsCerts.size()][]);
                    }

                    @Override
                    public Map<String, Peer> getEndpointMap() {
                        return Collections.unmodifiableMap(Channel.this.peerEndpointMap);
                    }

                    @Override
                    public String getName() {
                        return sdEndorser.getName();
                    }

                    @Override
                    public Properties getProperties() {
                        Properties properties = new Properties();
                        if (asLocalhost) {
                            properties.put("hostnameOverride",
                                    sdEndorser.getName().substring(0, sdEndorser.getName().lastIndexOf(':')));
                        }
                        return properties;
                    }

                    @Override
                    public boolean isTLS() {
                        return sdEndorser.isTLS();
                    }
                });
            } else if (discoveryEndpoints.contains(sdEndorser.getEndpoint())) {

                //hackfest here....  if the user didn't supply msspid retro fit for disovery peers
                if (peer.getProperties() == null || isNullOrEmpty(peer.getProperties().getProperty(Peer.PEER_ORGANIZATION_MSPID_PROPERTY))) {

                    synchronized (peerMSPIDMap) {
                        peerMSPIDMap.computeIfAbsent(sdEndorserMspid, k -> new HashSet<>()).add(peer);
                    }
                    Properties properties = peer.getProperties();
                    if (properties == null) {
                        properties = new Properties();
                    }
                    properties.put(Peer.PEER_ORGANIZATION_MSPID_PROPERTY, sdEndorserMspid);
                    peer.setProperties(properties);

                }

            }

        }
    }

    public Properties getServiceDiscoveryProperties() {
        return serviceDiscoveryProperties;
    }

    public void setServiceDiscoveryProperties(Properties serviceDiscoveryProperties) {
        this.serviceDiscoveryProperties = serviceDiscoveryProperties;
    }

    public interface SDPeerAdditionInfo {
        String getName();

        String getMspId();

        String getEndpoint();

        Channel getChannel();

        HFClient getClient();

        byte[][] getTLSCerts();

        byte[][] getTLSIntermediateCerts();

        default byte[] getAllTLSCerts() throws ServiceDiscoveryException {
            try {
                return Channel.combineCerts(Arrays.asList(getTLSCerts()), Arrays.asList(getTLSIntermediateCerts()));
            } catch (IOException e) {
                throw new ServiceDiscoveryException(e);
            }
        }

        Map<String, Peer> getEndpointMap();

        Properties getProperties();

        boolean isTLS();
    }

    public interface SDPeerAddition {

        Peer addPeer(SDPeerAdditionInfo sdPeerAddition) throws InvalidArgumentException, ServiceDiscoveryException;

    }

    transient SDPeerAddition sdPeerAddition = null;

    /**
     * Set service discovery orderer addition override.
     * <p>
     * Any service discovery properties {@link #setServiceDiscoveryProperties(Properties)} should be set before calling this.
     *
     * @param sdOrdererAddition
     * @return
     */

    public SDOrdererAddition setSDOrdererAddition(SDOrdererAddition sdOrdererAddition) {
        SDOrdererAddition ret = this.sdOrdererAddition;

        this.sdOrdererAddition = sdOrdererAddition;

        if (null == ret) {
            ret = new SDOrdererDefaultAddition(getServiceDiscoveryProperties());
        }

        return ret;

    }

    /**
     * Get current service discovery orderer addition override.
     * <p>
     * Any service discovery properties {@link #setServiceDiscoveryProperties(Properties)} should be set before calling this.
     *
     * @return SDOrdererAddition
     */

    public SDOrdererAddition getSDOrdererAddition() {

        if (null == sdOrdererAddition) {
            sdOrdererAddition = new SDOrdererDefaultAddition(getServiceDiscoveryProperties());
        }

        return sdOrdererAddition;

    }

    @SafeVarargs
    private static byte[] combineCerts(Collection<byte[]>... certCollections) throws IOException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            for (Collection<byte[]> certCollection : certCollections) {
                for (byte[] cert : certCollection) {
                    outputStream.write(cert);
                    outputStream.write('\n');
                }
            }

            return outputStream.toByteArray();
        }
    }

    public interface SDOrdererAdditionInfo {

        String getEndpoint();

        Properties getProperties();

        String getMspId();

        Channel getChannel();

        HFClient getClient();

        byte[][] getTLSCerts();

        byte[][] getTLSIntermediateCerts();

        default byte[] getAllTLSCerts() throws ServiceDiscoveryException {
            try {
                return Channel.combineCerts(Arrays.asList(getTLSCerts()), Arrays.asList(getTLSIntermediateCerts()));
            } catch (IOException e) {
                throw new ServiceDiscoveryException(e);
            }
        }

        Map<String, Orderer> getEndpointMap();

        boolean isTLS();
    }

    public interface SDOrdererAddition {

        Orderer addOrderer(SDOrdererAdditionInfo sdOrdererAdditionInfo) throws InvalidArgumentException, ServiceDiscoveryException;

    }

    private transient SDOrdererAddition sdOrdererAddition = null;

    private Properties serviceDiscoveryProperties = new Properties();

    public static class SDOrdererDefaultAddition implements SDOrdererAddition {
        protected final Properties config;

        public SDOrdererDefaultAddition(Properties config) {
            this.config = config == null ? new Properties() : (Properties) config.clone();

        }

        @Override
        public Orderer addOrderer(SDOrdererAdditionInfo sdOrdererAdditionInfo) throws InvalidArgumentException, ServiceDiscoveryException {

            Properties properties = sdOrdererAdditionInfo.getProperties();
            final String endpoint = sdOrdererAdditionInfo.getEndpoint();
            final String mspid = sdOrdererAdditionInfo.getMspId();

            String protocol = (String) findClientProp(config, "protocol", mspid, endpoint, sdOrdererAdditionInfo.isTLS() ? "grpcs:" : "grpc:");

            String clientCertFile = (String) findClientProp(config, NetworkConfig.CLIENT_CERT_FILE, mspid, endpoint, null);

            if (null != clientCertFile) {
                properties.put(NetworkConfig.CLIENT_CERT_FILE, clientCertFile);
            }

            String clientKeyFile = (String) findClientProp(config, NetworkConfig.CLIENT_KEY_FILE, mspid, endpoint, null);
            if (null != clientKeyFile) {
                properties.put(NetworkConfig.CLIENT_KEY_FILE, clientKeyFile);
            }

            byte[] clientCertBytes = (byte[]) findClientProp(config, NetworkConfig.CLIENT_CERT_BYTES, mspid, endpoint, null);
            if (null != clientCertBytes) {
                properties.put(NetworkConfig.CLIENT_CERT_BYTES, clientCertBytes);
            }

            byte[] clientKeyBytes = (byte[]) findClientProp(config, NetworkConfig.CLIENT_KEY_BYTES, mspid, endpoint, null);
            if (null != clientKeyBytes) {
                properties.put(NetworkConfig.CLIENT_KEY_BYTES, clientKeyBytes);
            }

            String hostnameOverride = (String) findClientProp(config, "hostnameOverride", mspid, endpoint, null);
            if (null != hostnameOverride) {
                properties.put("hostnameOverride", hostnameOverride);
            }

            byte[] pemBytes = sdOrdererAdditionInfo.getAllTLSCerts();
            if (pemBytes.length > 0) {
                properties.put("pemBytes", pemBytes);
            }

            properties.put(Orderer.ORDERER_ORGANIZATION_MSPID_PROPERTY, sdOrdererAdditionInfo.getMspId());

            Orderer orderer = sdOrdererAdditionInfo.getClient().newOrderer(endpoint,
                    protocol + "//" + endpoint,
                    properties);
            sdOrdererAdditionInfo.getChannel().addOrderer(orderer);

            return orderer;
        }
    }

    public static class SDOPeerDefaultAddition implements SDPeerAddition {
        protected final Properties config;

        public SDOPeerDefaultAddition(Properties config) {
            this.config = config == null ? new Properties() : (Properties) config.clone();

        }

        @Override
        public Peer addPeer(SDPeerAdditionInfo sdPeerAddition) throws InvalidArgumentException, ServiceDiscoveryException {

            Properties properties = sdPeerAddition.getProperties();
            final String name = sdPeerAddition.getName();
            final String endpoint = sdPeerAddition.getEndpoint();
            final String mspid = sdPeerAddition.getMspId();

            String protocol = (String) findClientProp(config, "protocol", mspid, endpoint, sdPeerAddition.isTLS() ? "grpcs:" : "grpc:");

            Peer peer = sdPeerAddition.getEndpointMap().get(endpoint); // maybe there already.
            if (null != peer) {
                return peer;

            }

            String clientCertFile = (String) findClientProp(config, NetworkConfig.CLIENT_CERT_FILE, mspid, endpoint, null);

            byte[] clientCertBytes = (byte[]) findClientProp(config, NetworkConfig.CLIENT_CERT_BYTES, mspid, endpoint, null);
            if (null != clientCertBytes) {
                properties.put(NetworkConfig.CLIENT_CERT_BYTES, clientCertBytes);
            } else if (null != clientCertFile) {
                properties.put(NetworkConfig.CLIENT_CERT_FILE, clientCertFile);
            }

            properties.put(Peer.PEER_ORGANIZATION_MSPID_PROPERTY, sdPeerAddition.getMspId());

            byte[] clientKeyBytes = (byte[]) findClientProp(config, NetworkConfig.CLIENT_KEY_BYTES, mspid, endpoint, null);
            String clientKeyFile = (String) findClientProp(config, NetworkConfig.CLIENT_KEY_FILE, mspid, endpoint, null);
            if (null != clientKeyBytes) {
                properties.put(NetworkConfig.CLIENT_KEY_BYTES, clientKeyBytes);
            } else if (null != clientKeyFile) {
                properties.put(NetworkConfig.CLIENT_KEY_FILE, clientKeyFile);
            }

            String hostnameOverride = (String) findClientProp(config, "hostnameOverride", mspid, endpoint, null);
            if (null != hostnameOverride) {
                properties.put("hostnameOverride", hostnameOverride);
            }

            byte[] pemBytes = sdPeerAddition.getAllTLSCerts();
            if (pemBytes.length > 0) {
                properties.put("pemBytes", pemBytes);
            }

            peer = sdPeerAddition.getClient().newPeer(name,
                    protocol + "//" + endpoint,
                    properties);

            sdPeerAddition.getChannel().addPeer(peer, createPeerOptions().setPeerRoles(
                    EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.EVENT_SOURCE, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.SERVICE_DISCOVERY))); //application can decide on roles.

            return peer;
        }
    }

    static Object findClientProp(Properties config, final String prop, final String mspid, final String endpoint, String def) {
        final String[] split = endpoint.split(":");
        final String endpointHost = split[0];

        Object ret = config.getOrDefault("org.hyperledger.fabric.sdk.discovery.default." + prop, def);
        ret = config.getOrDefault("org.hyperledger.fabric.sdk.discovery.mspid." + prop + "." + mspid, ret);
        ret = config.getOrDefault("org.hyperledger.fabric.sdk.discovery.endpoint." + prop + "." + endpointHost, ret);
        ret = config.getOrDefault("org.hyperledger.fabric.sdk.discovery.endpoint." + prop + "." + endpoint, ret);
        return ret;
    }

    /**
     * Set service discovery peer addition override.
     * <p>
     * Any service discovery properties {@link #setServiceDiscoveryProperties(Properties)} should be set before calling this.
     *
     * @param sdPeerAddition
     * @return
     */

    public SDPeerAddition setSDPeerAddition(SDPeerAddition sdPeerAddition) {
        SDPeerAddition ret = this.sdPeerAddition;

        this.sdPeerAddition = sdPeerAddition;

        if (ret == null) {
            ret = new SDOPeerDefaultAddition(getServiceDiscoveryProperties());
        }

        return ret;

    }

    /**
     * Get current service discovery peer addition override.
     * <p>
     * Any service discovery properties {@link #setServiceDiscoveryProperties(Properties)} should be set before calling this.
     *
     * @return SDOrdererAddition
     */

    public SDPeerAddition getSDPeerAddition() {

        if (null == sdPeerAddition) {
            sdPeerAddition = new SDOPeerDefaultAddition(getServiceDiscoveryProperties());
        }

        return sdPeerAddition;

    }

    /**
     * load the peer organizations CA certificates into the channel's trust store so that we
     * can verify signatures from peer messages
     *
     * @throws InvalidArgumentException
     * @throws CryptoException
     */
    protected synchronized void loadCACertificates(boolean force) throws InvalidArgumentException, CryptoException, TransactionException {

        if (!force && msps != null && !msps.isEmpty()) {
            return;
        }
        logger.debug(format("Channel %s loadCACertificates", name));

        Map<String, MSP> lmsp = parseConfigBlock(force);

        if (lmsp == null || lmsp.isEmpty()) {
            throw new InvalidArgumentException("Unable to load CA certificates. Channel " + name + " does not have any MSPs.");
        }

        List<byte[]> certList;
        for (MSP msp : lmsp.values()) {
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

                seekBlock(newTransactionContext(), seekInfo, deliverResponses, orderer);

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

            TransactionContext transactionContext = newTransactionContext(signer);

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

    protected Map<String, MSP> parseConfigBlock(boolean force) throws TransactionException {

        Map<String, MSP> lmsps = msps;

        if (!force && lmsps != null && !lmsps.isEmpty()) {
            return lmsps;
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
            return Collections.unmodifiableMap(newMSPS);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new TransactionException(e);
        }

    }

    private Map<String, MSP> traverseConfigGroupsMSP(String name, ConfigGroup configGroup, Map<String, MSP> msps) throws InvalidProtocolBufferException {

        ConfigValue mspv = configGroup.getValuesMap().get("MSP");
        if (null != mspv) {
            if (!msps.containsKey(name)) {

                MspConfigPackage.MSPConfig mspConfig = MspConfigPackage.MSPConfig.parseFrom(mspv.getValue());
                Integer type = mspConfig.getType();
                if (type == 0) {
                    MspConfigPackage.FabricMSPConfig fabricMSPConfig = MspConfigPackage.FabricMSPConfig.parseFrom(mspConfig.getConfig());

                    msps.put(name, new MSP(name, fabricMSPConfig));
                }
            }
        }

        for (Map.Entry<String, ConfigGroup> gm : configGroup.getGroupsMap().entrySet()) {
            traverseConfigGroupsMSP(gm.getKey(), gm.getValue(), msps);
        }

        return msps;
    }

    public static class AnchorPeersConfigUpdateResult {
        private UpdateChannelConfiguration updateChannelConfiguration = null;
        private Collection<String> peersAdded = Collections.emptyList();
        private Collection<String> peersRemoved = Collections.emptyList();
        private Collection<String> currentPeers = Collections.emptyList();
        private Collection<String> updatedPeers = Collections.emptyList();

        /**
         * The actual config update @see {@link UpdateChannelConfiguration}
         *
         * @return The config update. May be null when there is an error on no change needs to be done.
         */
        public UpdateChannelConfiguration getUpdateChannelConfiguration() {
            return updateChannelConfiguration;
        }

        /**
         * The peers to be added.
         *
         * @return The anchor peers to be added. This is less any that may be already present.
         */
        public Collection<String> getPeersAdded() {
            return peersAdded;
        }

        /**
         * The peers to be removed..
         *
         * @return The anchor peers to be removed. This is less any peers not present.
         */
        public Collection<String> getPeersRemoved() {
            return peersRemoved;
        }

        /**
         * The anchor peers found in the current channel configuration.
         *
         * @return The anchor peers found in the current channel configuration.
         */
        public Collection<String> getCurrentPeers() {
            return currentPeers;
        }

        /**
         * The anchor peers found in the updated channel configuration.
         */
        public Collection<String> getUpdatedPeers() {
            return updatedPeers;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(10000);

            sb.append("AnchorPeersConfigUpdateResult:{peersAdded= ");

            if (peersAdded == null) {
                sb.append("null");
            } else {
                sb.append(peersAdded.toString());
            }

            sb.append(", peersRemoved= ");
            if (peersRemoved == null) {
                sb.append("null");
            } else {
                sb.append(peersRemoved.toString());
            }

            sb.append(", currentPeers= ");
            if (currentPeers == null) {
                sb.append("null");
            } else {
                sb.append(currentPeers.toString());
            }

            sb.append(", updatedPeers= ");
            if (updatedPeers == null) {
                sb.append("null");
            } else {
                sb.append(updatedPeers.toString());
            }

            sb.append(", updateChannelConfiguration= ");
            if (updateChannelConfiguration == null) {
                sb.append("null");
            } else {
                sb.append(toHexString(updateChannelConfiguration.getUpdateChannelConfigurationAsBytes()));
            }
            sb.append("}");
            return sb.toString();
        }
    }

    /**
     * Get a channel configuration update to add or remove peers.
     * If both peersToAdd AND peersToRemove are null then only the current anchor peers are reported with @see {@link AnchorPeersConfigUpdateResult#getCurrentPeers()}
     *
     * @param peer          peer to use to the channel configuration from.
     * @param userContext   The usercontext to use.
     * @param peersToAdd    Peers to add as Host:Port peer1.org2.com:7022
     * @param peersToRemove Peers to remove as Host:Port peer1.org2.com:7022
     * @return The AnchorPeersConfigUpdateResult @see {@link AnchorPeersConfigUpdateResult}
     * @throws Exception
     */
    public AnchorPeersConfigUpdateResult getConfigUpdateAnchorPeers(Peer peer, User userContext, Collection<String> peersToAdd, Collection<String> peersToRemove) throws Exception {

        User.userContextCheck(userContext);

        checkPeer(peer);

        checkChannelState();

        final boolean reportOnly = peersToAdd == null && peersToRemove == null;

        if (!reportOnly && ((peersToAdd == null || peersToAdd.isEmpty()) && (peersToRemove == null || peersToRemove.isEmpty()))) {
            throw new InvalidArgumentException("No anchor peers to add or remove!");
        }

        if (IS_TRACE_LEVEL) {

            StringBuilder sbp = new StringBuilder("null");
            String sep = "";
            if (peersToAdd != null) {
                sbp = new StringBuilder("[");
                for (String s : peersToAdd) {
                    sbp.append(sep).append("'").append(s).append("'");
                    sep = ", ";
                }
                sbp.append("]");

            }
            StringBuilder sbr = new StringBuilder("null");
            sep = "";
            if (peersToRemove != null) {
                sbr = new StringBuilder("[");

                for (String s : peersToRemove) {

                    sbr.append(sep).append("'").append(s).append("'");
                    sep = ", ";
                }
                sbr.append("]");

            }
            logger.trace(format("getConfigUpdateAnchorPeers channel %s, peer: %s, user: %s, peers to add: %s, peers to remove: %s",
                    name, peer.toString(), userContext.getMspId() + ":" + userContext.getName(),
                    sbp.toString(), sbr.toString()
            ));
        }

        Set<String> peersToAddHS = new HashSet<>(16);
        if (null != peersToAdd) {
            for (String s : peersToAdd) {
                String[] ep = parseEndpoint(s);
                peersToAddHS.add(ep[0] + ":" + ep[1]);
            }
            //  peersToAddHS.addAll(peersToAdd);
        }

        Set<String> peersToRemoveHS = new HashSet<>(16);
        if (null != peersToRemove && !peersToRemove.isEmpty()) {
            for (String s : peersToRemove) {

                String[] ep = parseEndpoint(s);
                peersToRemoveHS.add(ep[0] + ":" + ep[1]);
            }
            peersToRemoveHS.removeAll(peersToAddHS); //add overrides remove;
        }
        Set<String> peersRemoved = new HashSet<>(peersToAddHS.size());
        Set<String> peersAdded = new HashSet<>(peersToRemoveHS.size());

        Block configBlock = getConfigBlock(Collections.singletonList(peer));
        if (IS_TRACE_LEVEL) {
            logger.trace(format("getConfigUpdateAnchorPeers  configBlock: %s",
                    toHexString(configBlock.toByteArray())));
        }

        Envelope envelope = Envelope.parseFrom(configBlock.getData().getData(0));
        Payload payload = Payload.parseFrom(envelope.getPayload());
        Header header = payload.getHeader();

        ChannelHeader channelHeader = ChannelHeader.parseFrom(header.getChannelHeader());
        if (!Objects.equals(name, channelHeader.getChannelId())) {
            throw new InvalidArgumentException(format("Expected config block for channel: %s, but got: %s", name, channelHeader.getChannelId()));
        }

        ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
        // ConfigGroup channelGroup = configEnvelope.getConfig().getChannelGroup();

        Configtx.Config config = configEnvelope.getConfig();
        Configtx.Config.Builder configBuilderUpdate = config.toBuilder();

        ConfigGroup.Builder channelGroupBuild = configBuilderUpdate.getChannelGroup().toBuilder();
        Map<String, ConfigGroup> groupsMap = channelGroupBuild.getGroupsMap();
        ConfigGroup.Builder application = groupsMap.get("Application").toBuilder();
        final String mspid = userContext.getMspId();
        ConfigGroup peerOrgConfigGroup = application.getGroupsMap().get(mspid);

        if (null == peerOrgConfigGroup) {
            StringBuilder sb = new StringBuilder(1000);
            String sep = "";

            for (String amspid : application.getGroupsMap().keySet()) {
                sb.append(sep).append(amspid);
                sep = ", ";

            }
            throw new InvalidArgumentException(format("Expected to find organization matching user context's mspid: %s, but only found %s.", mspid, sb.toString()));
        }
        ConfigGroup.Builder peerOrgConfigGroupBuilder = peerOrgConfigGroup.toBuilder();

        String modPolicy = peerOrgConfigGroup.getModPolicy() != null ? peerOrgConfigGroup.getModPolicy() : "Admins";

        Map<String, ConfigValue> valuesMap = peerOrgConfigGroupBuilder.getValuesMap();

        ConfigValue anchorPeersCV = valuesMap.get("AnchorPeers");

        final Set<String> currentAP = new HashSet<>(36); // The anchor peers that exist already.

        if (null != anchorPeersCV && anchorPeersCV.getValue() != null) {
            modPolicy = anchorPeersCV.getModPolicy() != null ? "Admins" : modPolicy;

            Configuration.AnchorPeers anchorPeers = Configuration.AnchorPeers.parseFrom(anchorPeersCV.getValue());
            List<Configuration.AnchorPeer> anchorPeersList = anchorPeers.getAnchorPeersList();
            if (anchorPeersList != null) {
                for (Configuration.AnchorPeer anchorPeer : anchorPeersList) {
                    currentAP.add(anchorPeer.getHost().toLowerCase() + ":" + anchorPeer.getPort());
                }
            }
        }

        if (IS_TRACE_LEVEL) {

            StringBuilder sbp = new StringBuilder("[");
            String sep = "";

            for (String s : currentAP) {
                sbp.append(sep).append("'").append(s).append("'");
                sep = ", ";
            }
            sbp.append("]");

            logger.trace(format("getConfigUpdateAnchorPeers channel %s,  current anchor peers: %s",
                    name, sbp.toString()));

        }

        if (reportOnly) {
            logger.trace("getConfigUpdateAnchorPeers reportOnly");

            AnchorPeersConfigUpdateResult ret = new AnchorPeersConfigUpdateResult();
            ret.currentPeers = currentAP;
            ret.peersAdded = Collections.emptyList();
            ret.peersRemoved = Collections.emptyList();
            ret.updatedPeers = Collections.emptyList();

            if (IS_TRACE_LEVEL) {
                logger.trace(format("getConfigUpdateAnchorPeers returned: %s",
                        ret.toString()));
            }
            return ret;

        }

        Set<String> peersFinalHS = new HashSet<>(16);

        Configuration.AnchorPeers.Builder anchorPeers = Configuration.AnchorPeers.newBuilder();
        for (String s : currentAP) {

            if (peersToRemoveHS.contains(s)) {
                peersRemoved.add(s);
                continue;
            }

            if (!peersToAddHS.contains(s)) {
                String[] split = s.split(":");
                anchorPeers.addAnchorPeers(Configuration.AnchorPeer.newBuilder().setHost(split[0]).setPort(Integer.parseInt(split[1])).build());
                peersFinalHS.add(s);
            }
        }

        for (String s : peersToAddHS) {
            if (!currentAP.contains(s)) {
                peersAdded.add(s);
                String[] split = s.split(":");
                anchorPeers.addAnchorPeers(Configuration.AnchorPeer.newBuilder().setHost(split[0]).setPort(Integer.parseInt(split[1])).build());
                peersFinalHS.add(s);
            }
        }

        if (peersRemoved.isEmpty() && peersAdded.isEmpty()) {
            logger.trace("getConfigUpdateAnchorPeers no Peers need adding or removing.");
            AnchorPeersConfigUpdateResult ret = new AnchorPeersConfigUpdateResult();
            ret.currentPeers = currentAP;
            ret.peersAdded = Collections.emptyList();
            ret.peersRemoved = Collections.emptyList();
            ret.updatedPeers = Collections.emptyList();
            if (IS_TRACE_LEVEL) {
                logger.trace(format("getConfigUpdateAnchorPeers returned: %s",
                        ret.toString()));
            }
            return ret;
        }

        Map m = new HashMap(valuesMap);
        m.remove("AnchorPeers");
        //       org1MSP.clearValues();

//        if (!peersFinalHS.isEmpty()) { // if there are anchor peers to add...   LEAVE IT.

        m.put("AnchorPeers", ConfigValue.newBuilder().setValue(anchorPeers.build().toByteString()).setModPolicy(modPolicy).build());
//       }
        ConfigGroup build = peerOrgConfigGroupBuilder.putAllValues(m).build();

        m.clear();
        m.putAll(application.getGroupsMap());
        m.put(mspid, build);
        // application.putAllValues(m);
        application.putAllGroups(m);
        ConfigGroup applicationBuilt = application.build();
        m.clear();
        m.putAll(channelGroupBuild.getGroupsMap());
        m.put("Application", applicationBuilt);
        channelGroupBuild.putAllGroups(m);

        configBuilderUpdate.setChannelGroup(channelGroupBuild.build());

        Configtx.ConfigUpdate.Builder updateBlockBuilder = Configtx.ConfigUpdate.newBuilder();

        Configtx.Config updated = configBuilderUpdate.build();

        if (IS_TRACE_LEVEL) {
            logger.trace(format("getConfigUpdateAnchorPeers  updated configBlock: %s",
                    toHexString(updated.toByteArray())));
        }

        ProtoUtils.computeUpdate(name, config, updated, updateBlockBuilder);

        AnchorPeersConfigUpdateResult ret = new AnchorPeersConfigUpdateResult();
        ret.currentPeers = currentAP;
        ret.peersAdded = peersAdded;
        ret.peersRemoved = peersRemoved;
        ret.updatedPeers = peersFinalHS;
        ret.updateChannelConfiguration = new UpdateChannelConfiguration(updateBlockBuilder.build().toByteArray());
        if (IS_TRACE_LEVEL) {
            logger.trace(format("getConfigUpdateAnchorPeers returned: %s",
                    ret.toString()));
        }

        return ret;
    }

    /**
     * Provide the Channel's latest raw Configuration Block.
     *
     * @param orderer
     * @return Channel configuration block.
     * @throws TransactionException
     */

    private Block getConfigurationBlock(TransactionContext transactionContext, Orderer orderer) throws TransactionException {

        logger.debug(format("getConfigurationBlock for channel %s", name));

        try {

            long lastConfigIndex = getLastConfigIndex(transactionContext, orderer);

            logger.debug(format("Last config index is %d", lastConfigIndex));

            Block configBlock = getBlockByNumber(transactionContext, orderer, lastConfigIndex);

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

    private String[] parseEndpoint(String endPoint) throws InvalidArgumentException {
        if (isNullOrEmpty(endPoint)) {
            throw new InvalidArgumentException("Endpoint is null or empty string");
        }

        try {
            URI uri = new URI("grpc://" + endPoint.toLowerCase());

            String host = uri.getHost();
            if (null == host) {
                throw new InvalidArgumentException(format("Endpoint '%s' expected to be format \"host:port\". Hostname part missing", endPoint));
            }
            int port = uri.getPort();
            if (port == -1) {
                throw new InvalidArgumentException(format("Endpoint '%s' expected to be format \"host:port\". Port does not seem to be a valid port number. ", endPoint));
            }

            // int port = Integer.parseInt(split[1]);
            if (port < 1) {
                throw new InvalidArgumentException(format("Endpoint '%s' expected to be format \"host:port\". Port does not seem to be a valid port number. ", endPoint));
            } else if (port > 65535) {
                throw new InvalidArgumentException(format("Endpoint '%s' expected to be format \"host:port\". Port does not seem to be a valid port number less than 65535. ", endPoint));
            }
            return new String[] {host, port + ""};

        } catch (URISyntaxException e) {
            throw new InvalidArgumentException(format("Endpoint '%s' expected to be format \"host:port\".", endPoint), e);
        }

    }

    /**
     * Get channel configuration from a specific Orderer
     *
     * @param userContext The user to sign the action.
     * @param orderer     To retrieve the configuration from.
     * @return Configuration block.
     * @throws InvalidArgumentException
     * @throws TransactionException
     */

    public byte[] getChannelConfigurationBytes(User userContext, Orderer orderer) throws InvalidArgumentException, TransactionException {

        try {
            Block configBlock = getConfigurationBlock(newTransactionContext(userContext), orderer);

            Envelope envelopeRet = Envelope.parseFrom(configBlock.getData().getData(0));

            Payload payload = Payload.parseFrom(envelopeRet.getPayload());

            ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
            return configEnvelope.getConfig().toByteArray();

        } catch (Exception e) {
            throw new TransactionException(e);
        }

    }

    /**
     * Get channel configuration from a specific peer
     *
     * @param userContext The user to sign the action.
     * @param peer        To retrieve the configuration from.
     * @return Configuration block.
     * @throws InvalidArgumentException
     * @throws TransactionException
     */

    public byte[] getChannelConfigurationBytes(User userContext, Peer peer) throws InvalidArgumentException, TransactionException {

        try {
            Block configBlock = getConfigBlock(newTransactionContext(userContext), Collections.singletonList(peer));

            Envelope envelopeRet = Envelope.parseFrom(configBlock.getData().getData(0));

            Payload payload = Payload.parseFrom(envelopeRet.getPayload());

            ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
            return configEnvelope.getConfig().toByteArray();

        } catch (Exception e) {
            throw new TransactionException(e);
        }

    }

    public byte[] getChannelConfigurationBytes() throws InvalidArgumentException, TransactionException {
        return getChannelConfigurationBytes(client.getUserContext());
    }

    /**
     * Channel Configuration bytes. Bytes that can be used with configtxlator tool to upgrade the channel.
     * If Peers exist on the channel config block will be retrieved from them.
     * If only Orderers exist the configblock is retrieved from them.
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

    public byte[] getChannelConfigurationBytes(User userContext) throws InvalidArgumentException, TransactionException {
        Block configBlock = null;
        try {

            Collection<Peer> peers = getShuffledPeers();

            if (!peers.isEmpty()) { // prefer peers.
                configBlock = getConfigBlock(newTransactionContext(userContext), new ArrayList<>(peers));

            } else { // no peers so look to orderers.

                List<Orderer> shuffledOrderers = getShuffledOrderers();
                if (shuffledOrderers.isEmpty()) {
                    throw new InvalidArgumentException(format("Channel %s has no peer or orderers defined. Can not get configuration block", name));
                }
                StringBuilder sb = new StringBuilder(1000);
                Exception fe = null;
                String sep = "";
                for (Orderer orderer : shuffledOrderers) {
                    try {
                        configBlock = getConfigurationBlock(newTransactionContext(userContext), orderer);
                        fe = null; // looks good.
                        break;
                    } catch (Exception e) {
                        fe = e;
                        sb.append(sep).append(orderer.toString()).append("-").append(e.getMessage());
                        sep = ", ";

                    }

                }
                if (fe != null) {
                    throw new TransactionException(sb.toString(), fe);
                }

            }
            if (configBlock == null) {
                throw new TransactionException("Transaction block could not be retrieved.");
            }

            Envelope envelopeRet = Envelope.parseFrom(configBlock.getData().getData(0));

            Payload payload = Payload.parseFrom(envelopeRet.getPayload());

            ConfigEnvelope configEnvelope = ConfigEnvelope.parseFrom(payload.getData());
            return configEnvelope.getConfig().toByteArray();

        } catch (Exception e) {
            throw new TransactionException(e);
        }

    }

    private long getLastConfigIndex(TransactionContext transactionContext, Orderer orderer) throws TransactionException, InvalidProtocolBufferException {
        Block latestBlock;
        latestBlock = getLatestBlock(orderer, transactionContext);

        BlockMetadata blockMetadata = latestBlock.getMetadata();

        Metadata metaData = Metadata.parseFrom(blockMetadata.getMetadata(1));

        LastConfig lastConfig = LastConfig.parseFrom(metaData.getValue());

        return lastConfig.getIndex();
    }

    private Block getBlockByNumber(TransactionContext transactionContext, Orderer orderer, final long number) throws TransactionException {

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

            seekBlock(transactionContext, seekInfo, deliverResponses, orderer);

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

    private int seekBlock(TransactionContext txContext, SeekInfo seekInfo, List<DeliverResponse> deliverResponses, Orderer ordererIn) throws TransactionException {

        logger.trace(format("seekBlock for channel %s", name));
        final long start = System.currentTimeMillis();
        @SuppressWarnings ("UnusedAssignment")
        int statusRC = 404;

        try {

            do {

                statusRC = 404;

                final Orderer orderer = ordererIn != null ? ordererIn : getRandomOrderer();

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

    private Block getLatestBlock(Orderer orderer, TransactionContext transactionContext) throws TransactionException {

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

        seekBlock(transactionContext, seekInfo, deliverResponses, orderer);

        DeliverResponse blockresp = deliverResponses.get(1);

        Block latestBlock = blockresp.getBlock();

        if (latestBlock == null) {
            throw new TransactionException(format("newest block for channel %s fetch bad deliver returned null:", name));
        }

        logger.trace(format("Received latest  block for channel %s, block no:%d", name, latestBlock.getHeader().getNumber()));
        return latestBlock;
    }

    public Collection<Orderer> getOrderers() {
        return Collections.unmodifiableCollection(new ArrayList<>(orderers));
    }

    /**
     * Send instantiate request to the channel. Chaincode is created and initialized.
     *
     * @param instantiateProposalRequest send instantiate chaincode proposal request.
     * @return Collections of proposal responses
     * @throws InvalidArgumentException
     * @throws ProposalException
     * @deprecated See new lifecycle chaincode management. {@link LifecycleInstallChaincodeRequest}
     */
    @Deprecated
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
     * @deprecated See new lifecycle chaincode management. {@link LifecycleInstallChaincodeRequest}
     */
    @Deprecated
    public Collection<ProposalResponse> sendInstantiationProposal(InstantiateProposalRequest instantiateProposalRequest,
                                                                  Collection<Peer> peers) throws InvalidArgumentException, ProposalException {
        checkChannelState();
        if (null == instantiateProposalRequest) {
            throw new InvalidArgumentException("InstantiateProposalRequest is null");
        }

        checkPeers(peers);

        try {
            TransactionContext transactionContext = newTransactionContext(instantiateProposalRequest.getUserContext());
            transactionContext.setProposalWaitTime(instantiateProposalRequest.getProposalWaitTime());
            InstantiateProposalBuilder instantiateProposalbuilder = InstantiateProposalBuilder.newBuilder();
            instantiateProposalbuilder.context(transactionContext);
            instantiateProposalbuilder.argss(instantiateProposalRequest.getArgs());
            instantiateProposalbuilder.chaincodeName(instantiateProposalRequest.getChaincodeName());
            instantiateProposalbuilder.chaincodeType(instantiateProposalRequest.getChaincodeLanguage());
            instantiateProposalbuilder.chaincodePath(instantiateProposalRequest.getChaincodePath());
            instantiateProposalbuilder.chaincodeVersion(instantiateProposalRequest.getChaincodeVersion());
            instantiateProposalbuilder.chaincodEndorsementPolicy(instantiateProposalRequest.getChaincodeEndorsementPolicy());
            instantiateProposalbuilder.chaincodeCollectionConfiguration(instantiateProposalRequest.getChaincodeCollectionConfiguration());
            instantiateProposalbuilder.setTransientMap(instantiateProposalRequest.getTransientMap());

            ProposalPackage.Proposal instantiateProposal = instantiateProposalbuilder.build();
            ProposalPackage.SignedProposal signedProposal = getSignedProposal(transactionContext, instantiateProposal);

            return sendProposalToPeers(peers, signedProposal, transactionContext);
        } catch (Exception e) {
            throw new ProposalException(e);
        }
    }

    private TransactionContext getTransactionContext(final TransactionRequest request) {
        return request.getTransactionContext()
                .orElse(newTransactionContext(request.getUserContext()));
    }

    /**
     * Create a new transaction context based on the client user context. The transaction context can be set on a
     * {@link TransactionRequest} prior to calling {@link Channel#sendTransactionProposal(TransactionProposalRequest)}
     * so that the caller can know the transaction ID in advance.
     * @return A transaction context.
     */
    public TransactionContext newTransactionContext() {
        return newTransactionContext(client.getUserContext());
    }

    private TransactionContext newTransactionContext(final User userContext) {
        return new TransactionContext(this, userContext, client.getCryptoSuite());
    }

    private TransactionContext newTransactionContext(final LifecycleRequest lifecycleRequest) throws InvalidArgumentException {
        User userContext = lifecycleRequest.getUserContext();
        if (null == userContext) {
            userContext = client.getUserContext();
        }

        userContextCheck(userContext);

        final TransactionContext transactionContext = new TransactionContext(this, userContext, client.getCryptoSuite());
        transactionContext.setProposalWaitTime(lifecycleRequest.getProposalWaitTime());
        transactionContext.verify(lifecycleRequest.isVerifiable());
        return transactionContext;
    }

    /**
     * Send install chaincode request proposal to all the channels on the peer.
     *
     * @param installProposalRequest
     * @return
     * @throws ProposalException
     * @throws InvalidArgumentException
     */
    @Deprecated
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
    @Deprecated
    Collection<ProposalResponse> sendInstallProposal(InstallProposalRequest installProposalRequest, Collection<Peer> peers)
            throws ProposalException, InvalidArgumentException {

        checkChannelState();
        checkPeers(peers);
        if (null == installProposalRequest) {
            throw new InvalidArgumentException("InstallProposalRequest is null");
        }

        try {
            TransactionContext transactionContext = newTransactionContext(installProposalRequest.getUserContext());
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

            ProposalPackage.Proposal deploymentProposal = installProposalbuilder.build();
            ProposalPackage.SignedProposal signedProposal = getSignedProposal(transactionContext, deploymentProposal);

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
     * @deprecated See new Lifecycle chaincode management.  {@link Channel#sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(LifecycleApproveChaincodeDefinitionForMyOrgRequest, Peer)}
     */
    @Deprecated
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
     * @deprecated See new Lifecycle chaincode management.  {@link Channel#sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(LifecycleApproveChaincodeDefinitionForMyOrgRequest, Peer)}
     */
    @Deprecated
    public Collection<ProposalResponse> sendUpgradeProposal(UpgradeProposalRequest upgradeProposalRequest, Collection<Peer> peers)
            throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeers(peers);

        if (null == upgradeProposalRequest) {
            throw new InvalidArgumentException("Upgradeproposal is null");
        }

        try {
            TransactionContext transactionContext = newTransactionContext(upgradeProposalRequest.getUserContext());
            //transactionContext.verify(false);  // Install will have no signing cause it's not really targeted to a channel.
            transactionContext.setProposalWaitTime(upgradeProposalRequest.getProposalWaitTime());
            UpgradeProposalBuilder upgradeProposalBuilder = UpgradeProposalBuilder.newBuilder();
            upgradeProposalBuilder.context(transactionContext);
            upgradeProposalBuilder.argss(upgradeProposalRequest.getArgs());
            upgradeProposalBuilder.chaincodeName(upgradeProposalRequest.getChaincodeName());
            upgradeProposalBuilder.chaincodePath(upgradeProposalRequest.getChaincodePath());
            upgradeProposalBuilder.chaincodeVersion(upgradeProposalRequest.getChaincodeVersion());
            upgradeProposalBuilder.chaincodEndorsementPolicy(upgradeProposalRequest.getChaincodeEndorsementPolicy());
            upgradeProposalBuilder.chaincodeCollectionConfiguration(upgradeProposalRequest.getChaincodeCollectionConfiguration());

            ProposalPackage.SignedProposal signedProposal = getSignedProposal(transactionContext, upgradeProposalBuilder.build());

            return sendProposalToPeers(peers, signedProposal, transactionContext);
        } catch (Exception e) {
            throw new ProposalException(e);
        }
    }

    private ProposalPackage.SignedProposal getSignedProposal(TransactionContext transactionContext, ProposalPackage.Proposal proposal) throws CryptoException, InvalidArgumentException {

        ProposalPackage.SignedProposal sp;
        sp = ProposalPackage.SignedProposal.newBuilder()
                .setProposalBytes(proposal.toByteString())
                .setSignature(transactionContext.signByteString(proposal.toByteArray()))
                .build();

        return sp;
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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

    private List<Orderer> getShuffledOrderers() {

        ArrayList<Orderer> orderers = new ArrayList<>(getOrderers());
        Collections.shuffle(orderers);
        return orderers;
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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
     *
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
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

            return new TransactionInfo(txID, TransactionPackage.ProcessedTransaction.parseFrom(proposalResponse.getProposalResponse().getResponse().getPayload()));
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

            TransactionContext context = newTransactionContext();

            ProposalPackage.Proposal q = QueryPeerChannelsBuilder.newBuilder().context(context).build();

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, q);
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

            ProposalResponsePackage.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final ProposalResponsePackage.Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) { //not likely but check it.
                throw new ProposalException(format("Peer %s channel query return with empty fabricResponseResponse", peer.getName()));
            }

            if (200 != fabricResponseResponse.getStatus()) {
                throw new ProposalException(format("Peer %s channel query expected 200, actual returned was: %d. "
                        + fabricResponseResponse.getMessage(), peer.getName(), fabricResponseResponse.getStatus()));

            }

            Query.ChannelQueryResponse qr = Query.ChannelQueryResponse.parseFrom(fabricResponseResponse.getPayload());

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

    List<Query.ChaincodeInfo> queryInstalledChaincodes(Peer peer) throws InvalidArgumentException, ProposalException {

        checkPeer(peer);

        if (!isSystemChannel()) {
            throw new InvalidArgumentException("queryInstalledChaincodes should only be invoked on system channel.");
        }

        try {

            TransactionContext context = newTransactionContext();

            ProposalPackage.Proposal q = QueryInstalledChaincodesBuilder.newBuilder().context(context).build();

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, q);
            Collection<ProposalResponse> proposalResponses = sendProposalToPeers(Collections.singletonList(peer), qProposal, context);

            if (null == proposalResponses) {
                throw new ProposalException(format("Peer %s channel query return with null for responses", peer.getName()));
            }

            if (proposalResponses.size() != 1) {

                throw new ProposalException(format("Peer %s channel query expected one response but got back %d  responses ", peer.getName(), proposalResponses.size()));
            }

            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            ProposalResponsePackage.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final ProposalResponsePackage.Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) { //not likely but check it.
                throw new ProposalException(format("Peer %s channel query return with empty fabricResponseResponse", peer.getName()));
            }

            if (200 != fabricResponseResponse.getStatus()) {
                throw new ProposalException(format("Peer %s channel query expected 200, actual returned was: %d. "
                        + fabricResponseResponse.getMessage(), peer.getName(), fabricResponseResponse.getStatus()));

            }

            Query.ChaincodeQueryResponse chaincodeQueryResponse = Query.ChaincodeQueryResponse.parseFrom(fabricResponseResponse.getPayload());

            return chaincodeQueryResponse.getChaincodesList();

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    //Not public
    Collection<LifecycleInstallChaincodeProposalResponse> sendLifecycleInstallProposal(LifecycleInstallChaincodeRequest installProposalRequest, Collection<Peer> peers)
            throws ProposalException, InvalidArgumentException {

        checkChannelState();
        checkPeers(peers);

        LifecycleChaincodePackage lifecycleChaincodePackage = installProposalRequest.getLifecycleChaincodePackage();
        if (null == lifecycleChaincodePackage) {
            throw new InvalidArgumentException("Install request is missing lifecycle package");
        }

        byte[] chaincodeBytes = lifecycleChaincodePackage.getAsBytes();

        if (null == chaincodeBytes) {
            throw new InvalidArgumentException("InstallProposalRequest lifecycleChaincodePackage bytes is null.");
        }

        if (chaincodeBytes.length == 0) {
            throw new InvalidArgumentException("InstallProposalRequest lifecycleChaincodePackage bytes is empty.");
        }

        try {
            TransactionContext transactionContext = newTransactionContext(installProposalRequest);
            transactionContext.verify(false);  // Install will have no signing cause it's not really targeted to a channel.
            LifecycleInstallProposalBuilder installProposalbuilder = LifecycleInstallProposalBuilder.newBuilder();
            installProposalbuilder.setChaincodeBytes(chaincodeBytes);
            installProposalbuilder.context(transactionContext);
            ProposalPackage.Proposal deploymentProposal = installProposalbuilder.build();
            ProposalPackage.SignedProposal signedProposal = getSignedProposal(transactionContext, deploymentProposal);

            return sendProposalToPeers(peers, signedProposal, transactionContext, LifecycleInstallChaincodeProposalResponse.class);
        } catch (Exception e) {
            throw new ProposalException(e);
        }

    }

    /**
     * Approve chaincode to be run on this peer's organization.
     *
     * @param lifecycleApproveChaincodeDefinitionForMyOrgRequest the request see {@link LifecycleApproveChaincodeDefinitionForMyOrgRequest}
     * @param peer
     * @return A {@link LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */

    public LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(LifecycleApproveChaincodeDefinitionForMyOrgRequest lifecycleApproveChaincodeDefinitionForMyOrgRequest, Peer peer) throws ProposalException, InvalidArgumentException {

        if (null == lifecycleApproveChaincodeDefinitionForMyOrgRequest) {
            throw new InvalidArgumentException("The lifecycleApproveChaincodeDefinitionForMyOrgRequest parameter can not be null.");
        }

        Collection<LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse> lifecycleApproveChaincodeDefinitionForMyOrgProposalResponses =
                sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(lifecycleApproveChaincodeDefinitionForMyOrgRequest, Collections.singleton(peer));
        return lifecycleApproveChaincodeDefinitionForMyOrgProposalResponses.iterator().next();

    }

    /**
     * Approve chaincode to be run on this peer's organization.
     *
     * @param lifecycleApproveChaincodeDefinitionForMyOrgRequest the request see {@link LifecycleApproveChaincodeDefinitionForMyOrgRequest}
     * @param peers                                              to send the request to.
     * @return A {@link LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse}
     * @throws ProposalException
     * @throws InvalidArgumentException
     */

    public Collection<LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse> sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(
            LifecycleApproveChaincodeDefinitionForMyOrgRequest lifecycleApproveChaincodeDefinitionForMyOrgRequest,
            Collection<Peer> peers) throws ProposalException, InvalidArgumentException {

        if (null == lifecycleApproveChaincodeDefinitionForMyOrgRequest) {
            throw new InvalidArgumentException("The lifecycleApproveChaincodeDefinitionForMyOrgRequest parameter can not be null.");
        }

        checkChannelState();
        checkPeers(peers);

        try {
            TransactionContext transactionContext = newTransactionContext(lifecycleApproveChaincodeDefinitionForMyOrgRequest);
            // transactionContext.verify(true);
            LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder approveChaincodeDefinitionForMyOrgProposalBuilder = LifecycleApproveChaincodeDefinitionForMyOrgProposalBuilder.
                    newBuilder();
            if (IS_TRACE_LEVEL) {

                logger.trace(format("LifecycleApproveChaincodeDefinitionForMyOrg channel: %s, sequence: %d, chaincodeName: %s, chaincodeVersion: %s, packageId: %s" +
                                ", sourceUnavailable: %b, isInitRequired: %s, validationParameter: '%s', endorsementPolicyPlugin: %s, validationPlugin: %s",
                        name,
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.getSequence(),
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeName(),
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeVersion(),
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.getPackageId(),
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.isSourceUnavailable(),
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.isInitRequired() + "",
                        toHexString(lifecycleApproveChaincodeDefinitionForMyOrgRequest.getValidationParameter()),
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeEndorsementPlugin(),
                        lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeValidationPlugin()));

            }

            approveChaincodeDefinitionForMyOrgProposalBuilder.context(transactionContext);
            approveChaincodeDefinitionForMyOrgProposalBuilder.sequence(lifecycleApproveChaincodeDefinitionForMyOrgRequest.getSequence());
            approveChaincodeDefinitionForMyOrgProposalBuilder.chaincodeName(lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeName());
            approveChaincodeDefinitionForMyOrgProposalBuilder.version(lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeVersion());

            String packageId = lifecycleApproveChaincodeDefinitionForMyOrgRequest.getPackageId();
            if (null != packageId) {
                approveChaincodeDefinitionForMyOrgProposalBuilder.setPackageId(packageId);
            } else if (!lifecycleApproveChaincodeDefinitionForMyOrgRequest.isSourceUnavailable()) {
                throw new InvalidArgumentException("The request must have a specific packageId or sourceNone set to true.");
            }

            Boolean initRequired = lifecycleApproveChaincodeDefinitionForMyOrgRequest.isInitRequired();
            if (null != initRequired) {
                approveChaincodeDefinitionForMyOrgProposalBuilder.initRequired(initRequired);
            }

            final ByteString validationParamter = lifecycleApproveChaincodeDefinitionForMyOrgRequest.getValidationParameter();
            if (null != validationParamter) {
                approveChaincodeDefinitionForMyOrgProposalBuilder.setValidationParamter(validationParamter);
            }

            String chaincodeCodeEndorsementPlugin = lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeEndorsementPlugin();
            if (null != chaincodeCodeEndorsementPlugin) {
                approveChaincodeDefinitionForMyOrgProposalBuilder.chaincodeCodeEndorsementPlugin(chaincodeCodeEndorsementPlugin);
            }

            String chaincodeCodeValidationPlugin = lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeValidationPlugin();
            if (null != chaincodeCodeValidationPlugin) {
                approveChaincodeDefinitionForMyOrgProposalBuilder.chaincodeCodeValidationPlugin(chaincodeCodeValidationPlugin);
            }

            ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = lifecycleApproveChaincodeDefinitionForMyOrgRequest.getChaincodeCollectionConfiguration();
            if (null != chaincodeCollectionConfiguration) {
                approveChaincodeDefinitionForMyOrgProposalBuilder.chaincodeCollectionConfiguration(chaincodeCollectionConfiguration.getCollectionConfigPackage());
            }

            ProposalPackage.Proposal deploymentProposal = approveChaincodeDefinitionForMyOrgProposalBuilder.build();
            ProposalPackage.SignedProposal signedProposal = getSignedProposal(transactionContext, deploymentProposal);

            return sendProposalToPeers(peers, signedProposal, transactionContext, LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse.class);
        } catch (Exception e) {
            throw new ProposalException(e);
        }

    }

    /**
     * Commit chaincode final approval to run on all organizations that have approved.
     *
     * @param lifecycleCommitChaincodeDefinitionRequest The request see {@link LifecycleCommitChaincodeDefinitionRequest}
     * @param peers                                     to send the request to.
     * @return A {@link LifecycleCommitChaincodeDefinitionProposalResponse}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<LifecycleCommitChaincodeDefinitionProposalResponse> sendLifecycleCommitChaincodeDefinitionProposal(LifecycleCommitChaincodeDefinitionRequest lifecycleCommitChaincodeDefinitionRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (null == lifecycleCommitChaincodeDefinitionRequest) {
            throw new InvalidArgumentException("The lifecycleCommitChaincodeDefinitionRequest parameter can not be null.");
        }
        checkChannelState();
        checkPeers(peers);

        try {

            if (IS_TRACE_LEVEL) {

                String collectionData = "null";

                final ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = lifecycleCommitChaincodeDefinitionRequest.getChaincodeCollectionConfiguration();
                if (null != chaincodeCollectionConfiguration) {
                    final byte[] asBytes = chaincodeCollectionConfiguration.getAsBytes();
                    if (null != asBytes) {
                        collectionData = toHexString(asBytes);
                    }
                }

                logger.trace(format("LifecycleCommitChaincodeDefinition channel: %s, sequence: %d, chaincodeName: %s, chaincodeVersion: %s" +
                                ", isInitRequired: %s, validationParameter: '%s', endorsementPolicyPlugin: %s, validationPlugin: %s" +
                                ", collectionConfiguration: %s",
                        name,
                        lifecycleCommitChaincodeDefinitionRequest.getSequence(),
                        lifecycleCommitChaincodeDefinitionRequest.getChaincodeName(),
                        lifecycleCommitChaincodeDefinitionRequest.getChaincodeVersion(),

                        lifecycleCommitChaincodeDefinitionRequest.isInitRequired() + "",
                        toHexString(lifecycleCommitChaincodeDefinitionRequest.getValidationParameter()),
                        lifecycleCommitChaincodeDefinitionRequest.getChaincodeEndorsementPlugin(),
                        lifecycleCommitChaincodeDefinitionRequest.getChaincodeValidationPlugin(),
                        collectionData));

            }
            TransactionContext transactionContext = newTransactionContext(lifecycleCommitChaincodeDefinitionRequest);
            LifecycleCommitChaincodeDefinitionProposalBuilder commitChaincodeDefinitionProposalBuilder = LifecycleCommitChaincodeDefinitionProposalBuilder.newBuilder();
            commitChaincodeDefinitionProposalBuilder.context(transactionContext);
            commitChaincodeDefinitionProposalBuilder.chaincodeName(lifecycleCommitChaincodeDefinitionRequest.getChaincodeName());
            commitChaincodeDefinitionProposalBuilder.version(lifecycleCommitChaincodeDefinitionRequest.getChaincodeVersion());
            commitChaincodeDefinitionProposalBuilder.sequence(lifecycleCommitChaincodeDefinitionRequest.getSequence());
            Boolean initRequired = lifecycleCommitChaincodeDefinitionRequest.isInitRequired();
            if (null != initRequired) {
                commitChaincodeDefinitionProposalBuilder.initRequired(initRequired);
            }

            ByteString validationParameter = lifecycleCommitChaincodeDefinitionRequest.getValidationParameter();
            if (null != validationParameter) {

                commitChaincodeDefinitionProposalBuilder.setValidationParamter(validationParameter);

            }

            String chaincodeCodeEndorsementPlugin = lifecycleCommitChaincodeDefinitionRequest.getChaincodeEndorsementPlugin();
            if (null != chaincodeCodeEndorsementPlugin) {
                commitChaincodeDefinitionProposalBuilder.chaincodeCodeEndorsementPlugin(chaincodeCodeEndorsementPlugin);
            }

            String chaincodeCodeValidationPlugin = lifecycleCommitChaincodeDefinitionRequest.getChaincodeValidationPlugin();
            if (null != chaincodeCodeValidationPlugin) {
                commitChaincodeDefinitionProposalBuilder.chaincodeCodeValidationPlugin(chaincodeCodeValidationPlugin);
            }

            ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = lifecycleCommitChaincodeDefinitionRequest.getChaincodeCollectionConfiguration();
            if (null != chaincodeCollectionConfiguration) {
                commitChaincodeDefinitionProposalBuilder.chaincodeCollectionConfiguration(chaincodeCollectionConfiguration.getCollectionConfigPackage());
            }

            ProposalPackage.Proposal deploymentProposal = commitChaincodeDefinitionProposalBuilder.build();
            ProposalPackage.SignedProposal signedProposal = getSignedProposal(transactionContext, deploymentProposal);

            return sendProposalToPeers(peers, signedProposal, transactionContext, LifecycleCommitChaincodeDefinitionProposalResponse.class);
        } catch (Exception e) {
            throw new ProposalException(e);
        }
    }

    // Not public
    Collection<LifecycleQueryInstalledChaincodesProposalResponse> lifecycleQueryInstalledChaincodes(LifecycleQueryInstalledChaincodesRequest lifecycleQueryInstalledChaincodesRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        logger.trace("LifecycleQueryInstalledChaincodes");
        if (null == lifecycleQueryInstalledChaincodesRequest) {
            throw new InvalidArgumentException("The lifecycleQueryInstalledChaincodesRequest parameter can not be null.");
        }

        checkPeers(peers);

        if (!isSystemChannel()) {
            throw new InvalidArgumentException("LifecycleQueryInstalledChaincodes should only be invoked on system channel.");
        }

        try {

            TransactionContext context = newTransactionContext(lifecycleQueryInstalledChaincodesRequest);

            ProposalPackage.Proposal proposalBuilder = LifecycleQueryInstalledChaincodesBuilder.newBuilder().context(context).build();

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, proposalBuilder);

            return sendProposalToPeers(peers, qProposal, context, LifecycleQueryInstalledChaincodesProposalResponse.class);

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    // Not public
    Collection<LifecycleQueryInstalledChaincodeProposalResponse> lifecycleQueryInstalledChaincode(LifecycleQueryInstalledChaincodeRequest lifecycleQueryInstalledChaincodeRequest,
                                                                                                  Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (null == lifecycleQueryInstalledChaincodeRequest) {
            throw new InvalidArgumentException("The lifecycleQueryInstalledChaincodeRequest parameter can not be null.");
        }

        checkPeers(peers);

        if (!isSystemChannel()) {
            throw new InvalidArgumentException("LifecycleQueryInstalledChaincodes should only be invoked on system channel.");
        }

        try {
            logger.trace(format("LifecycleQueryInstalledChaincode packageID: %s", lifecycleQueryInstalledChaincodeRequest.getPackageId()));

            TransactionContext context = newTransactionContext(lifecycleQueryInstalledChaincodeRequest);

            LifecycleQueryInstalledChaincodeBuilder lifecycleQueryInstalledChaincodeBuilder = LifecycleQueryInstalledChaincodeBuilder.newBuilder();

            lifecycleQueryInstalledChaincodeBuilder.setPackageId(lifecycleQueryInstalledChaincodeRequest.getPackageId());
            lifecycleQueryInstalledChaincodeBuilder.context(context);

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, lifecycleQueryInstalledChaincodeBuilder.build());
            return sendProposalToPeers(peers, qProposal, context, LifecycleQueryInstalledChaincodeProposalResponse.class);

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    /**
     * Query namespaces.  Takes no specific arguments returns namespaces including chaincode names that have been committed.
     *
     * @param proposalRequest the request.
     * @param peers The peers to which the request will be sent.
     * @return Peer responses.
     * @throws InvalidArgumentException if the channel is in an invalid state.
     * @throws ProposalException
     */

    public Collection<LifecycleQueryChaincodeDefinitionsProposalResponse> lifecycleQueryChaincodeDefinitions(LifecycleQueryChaincodeDefinitionsRequest proposalRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {
        if (null == proposalRequest) {
            throw new InvalidArgumentException("The proposal request can not be null.");
        }
        checkChannelState();
        checkPeers(peers);

        try {
            logger.trace(format("lifecycleQueryChaincodeDefinitions channel: %s", name));

            TransactionContext context = newTransactionContext(proposalRequest);
            LifecycleQueryChaincodeDefinitionsBuilder proposalBuilder = LifecycleQueryChaincodeDefinitionsBuilder.newBuilder();
            proposalBuilder.context(context);
            ProposalPackage.SignedProposal proposal = getSignedProposal(context, proposalBuilder.build());

            return sendProposalToPeers(peers, proposal, context, LifecycleQueryChaincodeDefinitionsProposalResponse.class);
        } catch (Exception e) {
            throw new ProposalException(format("QueryChaincodeDefinitions %s channel failed. " + e.getMessage(), name), e);
        }
    }

    /**
     * Query approval status for all organizations.
     *
     * @param lifecycleCheckCommitReadinessRequest The request see {@link LifecycleCheckCommitReadinessRequest}
     * @param peers                               Peers to send the request. Usually only need one.
     * @return A {@link LifecycleCheckCommitReadinessProposalResponse}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Collection<LifecycleCheckCommitReadinessProposalResponse> sendLifecycleCheckCommitReadinessRequest(LifecycleCheckCommitReadinessRequest lifecycleCheckCommitReadinessRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (null == lifecycleCheckCommitReadinessRequest) {
            throw new InvalidArgumentException("The lifecycleSimulateCommitChaincodeDefinitionRequest parameter can not be null.");
        }

        checkChannelState();
        checkPeers(peers);

        try {

            if (IS_TRACE_LEVEL) {

                String collectionData = "null";

                final org.hyperledger.fabric.protos.peer.Collection.CollectionConfigPackage chaincodeCollectionConfiguration = lifecycleCheckCommitReadinessRequest.getCollectionConfigPackage();
                if (null != chaincodeCollectionConfiguration) {
                    final byte[] asBytes = chaincodeCollectionConfiguration.toByteArray();
                    if (null != asBytes) {
                        collectionData = toHexString(asBytes);
                    }
                }

                logger.trace(format("LifecycleSimulateCommitChaincodeDefinition channel: %s, sequence: %d, chaincodeName: %s, chaincodeVersion: %s" +
                                ", isInitRequired: %s, validationParameter: '%s', endorsementPolicyPlugin: %s, validationPlugin: %s" +
                                ", collectionConfiguration: %s",
                        name,
                        lifecycleCheckCommitReadinessRequest.getSequence(),
                        lifecycleCheckCommitReadinessRequest.getChaincodeName(),
                        lifecycleCheckCommitReadinessRequest.getChaincodeVersion(),

                        lifecycleCheckCommitReadinessRequest.isInitRequired() + "",
                        toHexString(lifecycleCheckCommitReadinessRequest.getValidationParameter()),
                        lifecycleCheckCommitReadinessRequest.getChaincodeEndorsementPlugin(),
                        lifecycleCheckCommitReadinessRequest.getChaincodeValidationPlugin(),
                        collectionData));

            }

            TransactionContext context = newTransactionContext(lifecycleCheckCommitReadinessRequest);

            LifecycleCheckCommitReadinessBuilder lifecycleCheckCommitReadinessBuilder = LifecycleCheckCommitReadinessBuilder.newBuilder();
            lifecycleCheckCommitReadinessBuilder.setSequence(lifecycleCheckCommitReadinessRequest.getSequence());
            lifecycleCheckCommitReadinessBuilder.setName(lifecycleCheckCommitReadinessRequest.getChaincodeName());
            lifecycleCheckCommitReadinessBuilder.setVersion(lifecycleCheckCommitReadinessRequest.getChaincodeVersion());
            String endorsementPlugin = lifecycleCheckCommitReadinessRequest.getChaincodeEndorsementPlugin();
            if (!isNullOrEmpty(endorsementPlugin)) {
                lifecycleCheckCommitReadinessBuilder.setEndorsementPlugin(endorsementPlugin);
            }
            String validationPlugin = lifecycleCheckCommitReadinessRequest.getChaincodeValidationPlugin();

            if (!isNullOrEmpty(validationPlugin)) {
                lifecycleCheckCommitReadinessBuilder.setValidationPlugin(validationPlugin);
            }

            ByteString validationParameter = lifecycleCheckCommitReadinessRequest.getValidationParameter();
            if (null != validationParameter) {
                lifecycleCheckCommitReadinessBuilder.setValidationParameter(validationParameter);
            }

            org.hyperledger.fabric.protos.peer.Collection.CollectionConfigPackage collectionConfigPackage = lifecycleCheckCommitReadinessRequest.getCollectionConfigPackage();

            if (null != collectionConfigPackage) {
                lifecycleCheckCommitReadinessBuilder.setCollections(collectionConfigPackage);
            }

            Boolean initRequired = lifecycleCheckCommitReadinessRequest.isInitRequired();
            if (null != initRequired) {
                lifecycleCheckCommitReadinessBuilder.setInitRequired(initRequired);
            }

            lifecycleCheckCommitReadinessBuilder.context(context);

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, lifecycleCheckCommitReadinessBuilder.build());
            return sendProposalToPeers(peers, qProposal, context, LifecycleCheckCommitReadinessProposalResponse.class);

        } catch (Exception e) {
            throw new ProposalException(format("CheckCommitReadiness %s channel failed. " + e.getMessage(), name), e);

        }
    }

    /**
     * lifecycleQueryChaincodeDefinition get definition of chaincode.
     *
     * @param queryLifecycleQueryChaincodeDefinitionRequest The request see {@link QueryLifecycleQueryChaincodeDefinitionRequest}
     * @param peers                                         The peers to send the request to.
     * @return A {@link LifecycleQueryChaincodeDefinitionProposalResponse}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<LifecycleQueryChaincodeDefinitionProposalResponse> lifecycleQueryChaincodeDefinition(
            QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest, Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (null == queryLifecycleQueryChaincodeDefinitionRequest) {
            throw new InvalidArgumentException("The queryLifecycleQueryChaincodeDefinitionRequest parameter can not be null.");
        }

        checkChannelState();
        checkPeers(peers);

        try {

            logger.trace(format("LifecycleQueryChaincodeDefinition channel: %s, chaincode name: %s", name, queryLifecycleQueryChaincodeDefinitionRequest.getChaincodeName()));
            TransactionContext context = newTransactionContext(queryLifecycleQueryChaincodeDefinitionRequest);
            LifecycleQueryChaincodeDefinitionBuilder lifecycleQueryChaincodeDefinitionBuilder = LifecycleQueryChaincodeDefinitionBuilder.newBuilder();
            lifecycleQueryChaincodeDefinitionBuilder.context(context).setChaincodeName(queryLifecycleQueryChaincodeDefinitionRequest.getChaincodeName());

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, lifecycleQueryChaincodeDefinitionBuilder.build());
            return sendProposalToPeers(peers, qProposal, context, LifecycleQueryChaincodeDefinitionProposalResponse.class);

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    /**
     * Query peer for chaincode that has been instantiated
     *
     * <STRONG>This method may not be thread safe if client context is changed!</STRONG>
     *
     * @param peer The peer to query.
     * @return A list of ChaincodeInfo @see {@link Query.ChaincodeInfo}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public List<Query.ChaincodeInfo> queryInstantiatedChaincodes(Peer peer) throws InvalidArgumentException, ProposalException {
        return queryInstantiatedChaincodes(peer, client.getUserContext());

    }

    /**
     * Query peer for chaincode that has been instantiated
     *
     * @param peer        The peer to query.
     * @param userContext the user context.
     * @return A list of ChaincodeInfo @see {@link Query.ChaincodeInfo}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public List<Query.ChaincodeInfo> queryInstantiatedChaincodes(Peer peer, User userContext) throws InvalidArgumentException, ProposalException {

        checkChannelState();
        checkPeer(peer);
        User.userContextCheck(userContext);

        try {

            TransactionContext context = newTransactionContext(userContext);

            ProposalPackage.Proposal q = QueryInstantiatedChaincodesBuilder.newBuilder().context(context).build();

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, q);
            Collection<ProposalResponse> proposalResponses = sendProposalToPeers(Collections.singletonList(peer), qProposal, context);

            if (null == proposalResponses) {
                throw new ProposalException(format("Peer %s channel query return with null for responses", peer.getName()));
            }

            if (proposalResponses.size() != 1) {

                throw new ProposalException(format("Peer %s channel query expected one response but got back %d  responses ", peer.getName(), proposalResponses.size()));
            }

            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            ProposalResponsePackage.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final ProposalResponsePackage.Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) { //not likely but check it.
                throw new ProposalException(format("Peer %s channel query return with empty fabricResponseResponse", peer.getName()));
            }

            if (200 != fabricResponseResponse.getStatus()) {
                throw new ProposalException(format("Peer %s channel query expected 200, actual returned was: %d. "
                        + fabricResponseResponse.getMessage(), peer.getName(), fabricResponseResponse.getStatus()));

            }

            Query.ChaincodeQueryResponse chaincodeQueryResponse = Query.ChaincodeQueryResponse.parseFrom(fabricResponseResponse.getPayload());

            return chaincodeQueryResponse.getChaincodesList();

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    /**
     * Get information on the collections used by the chaincode.
     *
     * @param chaincodeName The name of the chaincode to query.
     * @param peer          Peer to query.
     * @param userContext   The context of the user to sign the request.
     * @return CollectionConfigPackage with information on the collection used by the chaincode.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public CollectionConfigPackage queryCollectionsConfig(String chaincodeName, Peer peer, User userContext) throws InvalidArgumentException, ProposalException {

        if (isNullOrEmpty(chaincodeName)) {
            throw new InvalidArgumentException("Parameter chaincodeName expected to be non null or empty string.");
        }
        checkChannelState();
        checkPeer(peer);
        User.userContextCheck(userContext);

        try {

            TransactionContext context = newTransactionContext(userContext);

            QueryCollectionsConfigBuilder queryCollectionsConfigBuilder = QueryCollectionsConfigBuilder.newBuilder()
                    .context(context).chaincodeName(chaincodeName);

            ProposalPackage.Proposal q = queryCollectionsConfigBuilder.build();

            ProposalPackage.SignedProposal qProposal = getSignedProposal(context, q);
            Collection<ProposalResponse> proposalResponses = sendProposalToPeers(Collections.singletonList(peer), qProposal, context);

            if (null == proposalResponses) {
                throw new ProposalException(format("Peer %s channel query return with null for responses", peer.getName()));
            }

            if (proposalResponses.size() != 1) {

                throw new ProposalException(format("Peer %s channel query expected one response but got back %d  responses ", peer.getName(), proposalResponses.size()));
            }

            ProposalResponse proposalResponse = proposalResponses.iterator().next();

            ProposalResponsePackage.ProposalResponse fabricResponse = proposalResponse.getProposalResponse();
            if (null == fabricResponse) {
                throw new ProposalException(format("Peer %s channel query return with empty fabric response", peer.getName()));

            }

            final ProposalResponsePackage.Response fabricResponseResponse = fabricResponse.getResponse();

            if (null == fabricResponseResponse) { //not likely but check it.
                throw new ProposalException(format("Peer %s channel query return with empty fabricResponseResponse", peer.getName()));
            }

            if (200 != fabricResponseResponse.getStatus()) {
                throw new ProposalException(format("Peer %s channel query expected 200, actual returned was: %d. "
                        + fabricResponseResponse.getMessage(), peer.getName(), fabricResponseResponse.getStatus()));

            }

            return new CollectionConfigPackage(fabricResponseResponse.getPayload());

        } catch (ProposalException e) {
            throw e;
        } catch (Exception e) {
            throw new ProposalException(format("Query for peer %s channels failed. " + e.getMessage(), name), e);

        }

    }

    /**
     * Send a transaction  proposal.
     *
     * @param transactionProposalRequest The transaction proposal to be sent to all the required peers needed for endorsing.
     * @return responses from peers.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Collection<ProposalResponse> sendTransactionProposal(TransactionProposalRequest transactionProposalRequest) throws ProposalException, InvalidArgumentException {

        return sendProposal(transactionProposalRequest, getEndorsingPeers());
    }

    private static class PeerExactMatch { // use original equals of Peer and not what's overrident
        final Peer peer;

        private PeerExactMatch(Peer peer) {
            this.peer = peer;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof PeerExactMatch)) {
                return false;
            }

            return peer == ((PeerExactMatch) obj).peer;
        }

        @Override
        public int hashCode() {
            return System.identityHashCode(peer);
        }
    }

    /**
     * Send a transaction  proposal.
     *
     * @param transactionProposalRequest The transaction proposal to be sent to all the required peers needed for endorsing.
     * @param discoveryOptions
     * @return responses from peers.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Collection<ProposalResponse> sendTransactionProposalToEndorsers(TransactionProposalRequest transactionProposalRequest, DiscoveryOptions discoveryOptions) throws ProposalException, InvalidArgumentException, ServiceDiscoveryException {
        final String chaincodeName = transactionProposalRequest.getChaincodeName() != null ? transactionProposalRequest.getChaincodeName() : transactionProposalRequest.getChaincodeID().getName();
        checkChannelState();
        if (null == transactionProposalRequest) {
            throw new InvalidArgumentException("The proposalRequest is null");
        }
        if (isNullOrEmpty(transactionProposalRequest.getFcn())) {
            throw new InvalidArgumentException("The proposalRequest's fcn is null or empty.");
        }
        if (null == serviceDiscovery) {
            throw new ServiceDiscoveryException("The channel is not configured with any peers with the 'discover' role");
        }
        logger.debug(format("Channel %s sendTransactionProposalToEndorsers chaincode name: %s", name, chaincodeName));

        TransactionContext transactionContext = getTransactionContext(transactionProposalRequest);
        transactionContext.verify(transactionProposalRequest.doVerify());
        transactionContext.setProposalWaitTime(transactionProposalRequest.getProposalWaitTime());

        // Protobuf message builder
        ProposalBuilder proposalBuilder = ProposalBuilder.newBuilder();
        proposalBuilder.context(transactionContext);
        proposalBuilder.request(transactionProposalRequest);

        ProposalPackage.SignedProposal invokeProposal = null;
        try {
            invokeProposal = getSignedProposal(transactionContext, proposalBuilder.build());
        } catch (CryptoException e) {
            throw new InvalidArgumentException(e);
        }
        SDChaindcode sdChaindcode;
        final List<ServiceDiscoveryChaincodeCalls> serviceDiscoveryChaincodeInterests = discoveryOptions.getServiceDiscoveryChaincodeInterests();

        if (null != serviceDiscoveryChaincodeInterests && !serviceDiscoveryChaincodeInterests.isEmpty()) {
            final String firstname = serviceDiscoveryChaincodeInterests.get(0).getName();
            if (!firstname.equals(chaincodeName)) {
                serviceDiscoveryChaincodeInterests.add(0, new ServiceDiscoveryChaincodeCalls(chaincodeName));
            }
            List<List<ServiceDiscoveryChaincodeCalls>> ccl = new LinkedList<>();
            ccl.add(serviceDiscoveryChaincodeInterests);
            final Map<String, SDChaindcode> sdChaindcodeMap = serviceDiscovery.discoverEndorserEndpoints(transactionContext, ccl);
            if (sdChaindcodeMap == null) {
                throw new ServiceDiscoveryException(format("Channel %s failed doing service discovery for chaincode %s ", name, chaincodeName));
            }
            sdChaindcode = sdChaindcodeMap.get(chaincodeName);

        } else {
            if (discoveryOptions.forceDiscovery) {
                logger.trace("Forcing discovery.");
                serviceDiscovery.networkDiscovery(transactionContext, true);
            }
            sdChaindcode = serviceDiscovery.discoverEndorserEndpoint(transactionContext, chaincodeName);
        }
        logger.trace(format("Channel %s chaincode %s discovered: %s", name, chaincodeName, "" + sdChaindcode));

        if (null == sdChaindcode) {
            throw new ServiceDiscoveryException(format("Channel %s failed to find any endorsers for chaincode %s", name, chaincodeName));
        }

        if (sdChaindcode.getLayouts() == null || sdChaindcode.getLayouts().isEmpty()) {
            throw new ServiceDiscoveryException(format("Channel %s failed to find any endorsers for chaincode %s no layouts found.", name, chaincodeName));
        }

        SDChaindcode sdChaindcodeEndorsementCopy = new SDChaindcode(sdChaindcode); //copy. no ignored.

        final boolean inspectResults = discoveryOptions.inspectResults;

        if (sdChaindcodeEndorsementCopy.ignoreList(discoveryOptions.getIgnoreList()) < 1) { // apply ignore list
            throw new ServiceDiscoveryException("Applying ignore list reduced to no available endorser options.");
        }

        if (IS_TRACE_LEVEL && null != discoveryOptions.getIgnoreList() && !discoveryOptions.getIgnoreList().isEmpty()) {
            logger.trace(format("SDchaincode after ignore list: %s", sdChaindcodeEndorsementCopy));
        }
        final ServiceDiscovery.EndorsementSelector lendorsementSelector = discoveryOptions.endorsementSelector != null ?
                discoveryOptions.endorsementSelector : this.endorsementSelector;
        try {

            final Map<SDEndorser, ProposalResponse> goodResponses = new HashMap<>(); // all good endorsements by endpoint
            final Map<SDEndorser, ProposalResponse> allTried = new HashMap<>(); // all tried by endpoint

            boolean done = false;
            int attempts = 1; //safety valve

            do {
                if (IS_TRACE_LEVEL) {
                    logger.trace(format("Attempts: %d,  chaincode discovery state: %s", attempts, sdChaindcodeEndorsementCopy));
                }
                final SDEndorserState sdEndorserState = lendorsementSelector.endorserSelector(sdChaindcodeEndorsementCopy);

                if (IS_TRACE_LEVEL) {

                    StringBuilder sb = new StringBuilder(1000);
                    String sep = "";
                    for (SDEndorser sdEndorser : sdEndorserState.getSdEndorsers()) {
                        sb.append(sep).append(sdEndorser);
                        sep = ", ";
                    }

                    logger.trace(format("Attempts: %d,  chaincode discovery state: %s. Endorser selector picked: %s. With selected endorsers: %s", attempts, sdChaindcodeEndorsementCopy.name, sdEndorserState.getPickedLayout(), sb.toString()));

                }

                Collection<SDEndorser> ep = sdEndorserState.getSdEndorsers();
                ep = new ArrayList<>(ep); // just in case it's not already a copy

                if (IS_TRACE_LEVEL) {

                    StringBuilder sb = new StringBuilder(1000);
                    String sep = "";
                    for (SDEndorser sdEndorser : ep) {
                        sb.append(sep).append(sdEndorser);
                    }
                    logger.trace(format("Channel %s, chaincode %s attempts: %d requested endorsements: %s", name, chaincodeName, attempts, sb.toString()));
                }

                //Safety check make sure the selector isn't giving back endpoints to retry
                ep.removeIf(sdEndorser -> goodResponses.keySet().contains(sdEndorser));

                if (ep.isEmpty()) { // this would be odd but lets go with it.
                    logger.debug(format("Channel %s, chaincode %s attempts: %d endorser selector returned no additional endorements needed.", name, chaincodeName, attempts));

                    Collection<SDEndorser> needed = sdChaindcode.meetsEndorsmentPolicy(goodResponses.keySet());
                    if (needed != null) { // means endorsment meet with those in the needed.
                        ArrayList<ProposalResponse> ret = new ArrayList<>(needed.size());
                        needed.forEach(s -> ret.add(goodResponses.get(s)));

                        if (IS_DEBUG_LEVEL) {

                            StringBuilder sb = new StringBuilder(1000);
                            String sep = "";
                            for (ProposalResponse proposalResponse : ret) {
                                sb.append(sep).append(proposalResponse.getPeer());
                                sep = ", ";
                            }
                            logger.debug(format("Channel %s, chaincode %s attempts: %d got all needed endorsements: %s", name, chaincodeName, attempts, sb.toString()));
                        }

                        return ret; // the happy path :)!

                    } else { //still don't have the needed endorsements.

                        logger.debug(format("Channel %s, chaincode %s attempts: %d missing needed endorsements", name, chaincodeName, attempts));

                        if (inspectResults) {
                            return allTried.values();
                        } else {
                            throw new ServiceDiscoveryException(format("Could not meet endorsement policy for chaincode %s", chaincodeName));
                        }
                    }
                }

                Map<String, Peer> lpeerEndpointMap = new HashMap<>(peerEndpointMap);
                Map<SDEndorser, Peer> endorsers = new HashMap<>(ep.size());
                Map<PeerExactMatch, SDEndorser> peer2sdEndorser = new HashMap<>(ep.size());
                for (SDEndorser sdEndorser : ep) {

                    Peer epeer = lpeerEndpointMap.get(sdEndorser.getEndpoint());
                    if (epeer != null && !epeer.hasConnected()) {
                        // mostly because gossip may have malicious data so if we've not connected update TLS props from chaincode discovery.
                        final Properties properties = epeer.getProperties();

                        final byte[] bytes = combineCerts(sdEndorser.getTLSCerts(), sdEndorser.getTLSIntermediateCerts());
                        properties.put("pemBytes", bytes);
                        epeer.setProperties(properties);

                    } else if (null == epeer) {
                        epeer = sdPeerAddition.addPeer(new SDPeerAdditionInfo() {

                            @Override
                            public String getMspId() {
                                return sdEndorser.getMspid();
                            }

                            @Override
                            public String getEndpoint() {
                                return sdEndorser.getEndpoint();
                            }

                            @Override
                            public Channel getChannel() {
                                return Channel.this;
                            }

                            @Override
                            public HFClient getClient() {
                                return Channel.this.client;
                            }

                            @Override
                            public byte[][] getTLSCerts() {

                                return sdEndorser.getTLSCerts().toArray(new byte[sdEndorser.getTLSCerts().size()][]);
                            }

                            @Override
                            public byte[][] getTLSIntermediateCerts() {
                                return sdEndorser.getTLSIntermediateCerts().toArray(new byte[sdEndorser.getTLSIntermediateCerts().size()][]);
                            }

                            @Override
                            public Map<String, Peer> getEndpointMap() {
                                return Collections.unmodifiableMap(Channel.this.peerEndpointMap);
                            }

                            @Override
                            public String getName() {
                                return sdEndorser.getName();
                            }

                            @Override
                            public Properties getProperties() {
                                Properties properties = new Properties();
                                if (asLocalhost) {
                                    properties.put("hostnameOverride",
                                            sdEndorser.getName().substring(0, sdEndorser.getName().lastIndexOf(':')));
                                }
                                return properties;
                            }

                            @Override
                            public boolean isTLS() {
                                return sdEndorser.isTLS();
                            }
                        });
                    }
                    endorsers.put(sdEndorser, epeer);
                    peer2sdEndorser.put(new PeerExactMatch(epeer), sdEndorser); // reverse
                }

                final Collection<ProposalResponse> proposalResponses = sendProposalToPeers(endorsers.values(), invokeProposal, transactionContext);
                HashSet<SDEndorser> loopGood = new HashSet<>();
                HashSet<SDEndorser> loopBad = new HashSet<>();

                for (ProposalResponse proposalResponse : proposalResponses) {
                    final SDEndorser sdEndorser = peer2sdEndorser.get(new PeerExactMatch(proposalResponse.getPeer()));
                    allTried.put(sdEndorser, proposalResponse);

                    final ChaincodeResponse.Status status = proposalResponse.getStatus();

                    if (ChaincodeResponse.Status.SUCCESS.equals(status)) {

                        goodResponses.put(sdEndorser, proposalResponse);
                        logger.trace(format("Channel %s, chaincode %s attempts %d good endorsements: %s", name, chaincodeName, attempts, sdEndorser));
                        loopGood.add(sdEndorser);

                    } else {
                        logger.debug(format("Channel %s, chaincode %s attempts %d bad endorsements: %s", name, chaincodeName, attempts, sdEndorser));
                        loopBad.add(sdEndorser);
                    }
                }

                //Always check on original
                Collection<SDEndorser> required = sdChaindcode.meetsEndorsmentPolicy(goodResponses.keySet());
                if (required != null) {
                    ArrayList<ProposalResponse> ret = new ArrayList<>(required.size());
                    required.forEach(s -> ret.add(goodResponses.get(s)));

                    if (IS_DEBUG_LEVEL) {

                        StringBuilder sb = new StringBuilder(1000);
                        String sep = "";
                        for (ProposalResponse proposalResponse : ret) {
                            sb.append(sep).append(proposalResponse.getPeer());
                            sep = ", ";
                        }
                        logger.debug(format("Channel %s, chaincode %s got all needed endorsements: %s", name, chaincodeName, sb.toString()));
                    }
                    return ret; // the happy path :)!

                } else { //still don't have the needed endorsements.

                    sdChaindcodeEndorsementCopy.endorsedList(loopGood); // mark the good ones in the working copy.

                    if (sdChaindcodeEndorsementCopy.ignoreListSDEndorser(loopBad) < 1) { // apply ignore list
                        done = true; // no more layouts
                    }
                }

            } while (!done && ++attempts <= 5);
            logger.debug(format("Endorsements not achieved chaincode: %s, done: %b, attempts: %d", chaincodeName, done, attempts));
            if (inspectResults) {
                return allTried.values();
            } else {
                throw new ServiceDiscoveryException(format("Could not meet endorsement policy for chaincode %s", chaincodeName));
            }
        } catch (ProposalException e) {
            throw e;

        } catch (Exception e) {
            ProposalException exp = new ProposalException(e);
            logger.error(exp.getMessage(), exp);
            throw exp;
        }
    }

    /**
     * Collection of discovered chaincode names.
     *
     * @return
     */

    public Collection<String> getDiscoveredChaincodeNames() {
        if (serviceDiscovery == null) {
            return Collections.emptyList();
        }

        return serviceDiscovery.getDiscoveredChaincodeNames();
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

        if (isNullOrEmpty(proposalRequest.getFcn())) {
            throw new InvalidArgumentException("The proposalRequest's fcn is null or empty.");
        }

        try {
            TransactionContext transactionContext = getTransactionContext(proposalRequest);
            transactionContext.verify(proposalRequest.doVerify());
            transactionContext.setProposalWaitTime(proposalRequest.getProposalWaitTime());

            // Protobuf message builder
            ProposalBuilder proposalBuilder = ProposalBuilder.newBuilder();
            proposalBuilder.context(transactionContext);
            proposalBuilder.request(proposalRequest);

            ProposalPackage.SignedProposal invokeProposal = getSignedProposal(transactionContext, proposalBuilder.build());
            return sendProposalToPeers(peers, invokeProposal, transactionContext);
        } catch (ProposalException e) {
            throw e;

        } catch (Exception e) {
            ProposalException exp = new ProposalException(e);
            logger.error(exp.getMessage(), exp);
            throw exp;
        }
    }

    private transient ServiceDiscovery.EndorsementSelector endorsementSelector = ServiceDiscovery.DEFAULT_ENDORSEMENT_SELECTION;

    public ServiceDiscovery.EndorsementSelector setSDEndorserSelector(ServiceDiscovery.EndorsementSelector endorsementSelector) {
        ServiceDiscovery.EndorsementSelector ret = this.endorsementSelector;
        this.endorsementSelector = endorsementSelector;
        return ret;

    }

    private Collection<ProposalResponse> sendProposalToPeers(Collection<Peer> peers,
                                                             ProposalPackage.SignedProposal signedProposal,
                                                             TransactionContext transactionContext) throws InvalidArgumentException, ProposalException {

        return sendProposalToPeers(peers,
                signedProposal,
                transactionContext, ProposalResponse.class);

    }

    private <T extends ProposalResponse> Collection<T> sendProposalToPeers(Collection<Peer> peers,
                                                                           ProposalPackage.SignedProposal signedProposal,
                                                                           TransactionContext transactionContext, Class<T> clazz) throws InvalidArgumentException, ProposalException {
        checkPeers(peers);

        if (transactionContext.getVerify()) {
            try {
                loadCACertificates(false);
            } catch (Exception e) {
                throw new ProposalException(e);
            }
        }

        Constructor<? extends ProposalResponse> declaredConstructor;
        try {
            declaredConstructor = clazz.getDeclaredConstructor(TransactionContext.class, int.class, String.class);
        } catch (NoSuchMethodException e) {
            throw new InvalidArgumentException(e);
        }

        final String txID = transactionContext.getTxID();

        class Pair {
            private final Peer peer;

            private final Future<ProposalResponsePackage.ProposalResponse> future;

            private Pair(Peer peer, Future<ProposalResponsePackage.ProposalResponse> future) {
                this.peer = peer;
                this.future = future;
            }
        }
        List<Pair> peerFuturePairs = new ArrayList<>();
        for (Peer peer : peers) {
            logger.debug(format("Channel %s send proposal to %s, txID: %s",
                    name, peer.toString(), txID));

            if (null != diagnosticFileDumper) {
                logger.trace(format("Sending to channel %s, peer: %s, proposal: %s, txID: %s", name, peer, txID,
                        diagnosticFileDumper.createDiagnosticProtobufFile(signedProposal.toByteArray())));
            }

            Future<ProposalResponsePackage.ProposalResponse> proposalResponseListenableFuture;
            try {
                proposalResponseListenableFuture = peer.sendProposalAsync(signedProposal);
            } catch (Exception e) {
                proposalResponseListenableFuture = new CompletableFuture<>();
                ((CompletableFuture) proposalResponseListenableFuture).completeExceptionally(e);
            }
            peerFuturePairs.add(new Pair(peer, proposalResponseListenableFuture));
        }

        Collection<T> proposalResponses = new ArrayList<>();
        for (Pair peerFuturePair : peerFuturePairs) {
            ProposalResponsePackage.ProposalResponse fabricResponse = null;
            String message;
            int status = 500;
            final String peerName = peerFuturePair.peer.toString();
            try {
                fabricResponse = peerFuturePair.future.get(transactionContext.getProposalWaitTime(), TimeUnit.MILLISECONDS);
                message = fabricResponse.getResponse().getMessage();
                status = fabricResponse.getResponse().getStatus();
                peerFuturePair.peer.setHasConnected();
                logger.debug(format("Channel %s, transaction: %s got back from peer %s status: %d, message: %s",
                        name, txID, peerName, status, message));
                if (null != diagnosticFileDumper) {
                    logger.trace(format("Got back from channel %s, peer: %s, proposal response: %s", name, peerName,
                            diagnosticFileDumper.createDiagnosticProtobufFile(fabricResponse.toByteArray())));

                }
            } catch (InterruptedException e) {
                message = "Sending proposal with transaction: " + txID + " to " + peerName + " failed because of interruption";
                logger.error(message, e);
            } catch (TimeoutException e) {
                message = format("Channel %s sending proposal with transaction %s to %s failed because of timeout(%d milliseconds) expiration",
                        toString(), txID, peerName, transactionContext.getProposalWaitTime());
                logger.error(message, e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof Error) {
                    String emsg = "Sending proposal with txID: " + txID + " to " + peerName + " failed because of " + cause.getMessage();
                    logger.error(emsg, new Exception(cause)); //wrapped in exception to get full stack trace.
                    throw (Error) cause;
                } else {
                    if (cause instanceof StatusRuntimeException) {
                        message = format("Channel %s Sending proposal with transaction: %s to %s failed because of: gRPC failure=%s",
                                toString(), txID, peerName, ((StatusRuntimeException) cause).getStatus());
                    } else {
                        message = format("Channel %s sending proposal with transaction: %s to %s failed because of: %s",
                                toString(), txID, peerName, cause.getMessage());
                    }
                    logger.error(message, new Exception(cause)); //wrapped in exception to get full stack trace.
                }
            }

            ProposalResponse proposalResponse = null;
            try {
                proposalResponse = declaredConstructor.newInstance(transactionContext, status, message);
            } catch (Exception e) {
                throw new InvalidArgumentException(e); // very unlikely to happen.
            }

            //ProposalResponse proposalResponse = new ProposalResponse(transactionContext, status, message);
            proposalResponse.setProposalResponse(fabricResponse);
            proposalResponse.setProposal(signedProposal);
            proposalResponse.setPeer(peerFuturePair.peer);

            if (fabricResponse != null && transactionContext.getVerify()) {
                proposalResponse.verify(client.getCryptoSuite());
            }

            proposalResponses.add((T) proposalResponse);
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
        return sendTransaction(proposalResponses, getOrderers(), userContext);
    }

    /**
     * Send transaction to one of the orderers on the channel using the usercontext set on the client.
     *
     * @param proposalResponses .
     * @return a future allowing access to the result of the transaction invocation once complete.
     */
    public CompletableFuture<TransactionEvent> sendTransaction(Collection<? extends ProposalResponse> proposalResponses) {
        return sendTransaction(proposalResponses, getOrderers());
    }

    /**
     * Send transaction to one of the specified orderers using the usercontext set on the client..
     *
     * @param proposalResponses The proposal responses to be sent to the orderer
     * @param orderers          The orderers to send the transaction to.
     * @return a future allowing access to the result of the transaction invocation once complete.
     */

    public CompletableFuture<TransactionEvent> sendTransaction(Collection<? extends ProposalResponse> proposalResponses, Collection<Orderer> orderers) {
        return sendTransaction(proposalResponses, orderers, client.getUserContext());
    }

    /**
     * NofEvents may be used with @see {@link TransactionOptions#nOfEvents(NOfEvents)}  to control how reporting Peer service events and Eventhubs will
     * complete the future acknowledging the transaction has been seen by those Peers.
     * <p>
     * You can use the method @see {@link #nofNoEvents} to create an NOEvents that will result in the future being completed immediately
     * when the Orderer has accepted the transaction. Note in this case the transaction event will be set to null.
     * <p>
     * NofEvents can add Peer Eventing services and Eventhubs that should complete the future. By default all will need to
     * see the transactions to complete the future.  The method @see {@link #setN(int)} can set how many in the group need to see the transaction
     * completion. Essentially setting it to 1 is any.
     * <p>
     * NofEvents may also contain other NofEvent grouping. They can be nested.
     */
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

        private HashSet<Peer> peers = new HashSet<>();
        private HashSet<NOfEvents> nOfEvents = new HashSet<>();

        /**
         * Peers that need to see the transaction event to complete.
         *
         * @param peers The peers that need to see the transaction event to complete.
         * @return This NofEvents.
         */
        public NOfEvents addPeers(Peer... peers) {
            if (peers == null || peers.length == 0) {
                throw new IllegalArgumentException("Peers added must be not null or empty.");
            }
            this.peers.addAll(Arrays.asList(peers));

            return this;
        }

        /**
         * Peers that need to see the transaction event to complete.
         *
         * @param peers The peers that need to see the transaction event to complete.
         * @return This NofEvents.
         */
        public NOfEvents addPeers(Collection<Peer> peers) {
            addPeers(peers.toArray(new Peer[peers.size()]));
            return this;
        }

        /**
         * NOfEvents that need to see the transaction event to complete.
         *
         * @param nOfEvents The nested event group that need to set the transacton event to complete.
         * @return This NofEvents.
         */

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

        /**
         * NOfEvents that need to see the transaction event to complete.
         *
         * @param nofs The nested event group that need to set the transacton event to complete.
         * @return This NofEvents.
         */
        public NOfEvents addNOfs(Collection<NOfEvents> nofs) {
            addNOfs(nofs.toArray(new NOfEvents[nofs.size()]));
            return this;
        }

        synchronized Collection<Peer> unSeenPeers() {
            Set<Peer> unseen = new HashSet<>(16);
            unseen.addAll(peers);
            for (NOfEvents nOfEvents : nOfEvents) {
                unseen.addAll(nofNoEvents.unSeenPeers());
            }
            return unseen;
        }

        synchronized boolean seen(Peer peer) {
            if (!started) {
                started = true;
                n = Long.min(peers.size() + nOfEvents.size(), n);
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

            for (NOfEvents nofc : nof.nOfEvents) {
                this.nOfEvents.add(new NOfEvents(nofc));

            }
        }

        private NOfEvents() { }

        public static NOfEvents createNofEvents() {
            return new NOfEvents();
        }

        /**
         * Special NofEvents indicating that no transaction events are needed to complete the Future.
         * This will result in the Future being completed as soon has the Orderer has seen the transaction.
         */
        public static NOfEvents nofNoEvents = new NOfEvents() {
            @Override
            public NOfEvents addNOfs(NOfEvents... nOfEvents) {
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
     * IF there are no eventing peers this future returns immediately completed
     * indicating that orderer has accepted the transaction only.
     *
     * @param proposalResponses
     * @param orderers
     * @return Future allowing access to the result of the transaction invocation.
     */
    public CompletableFuture<TransactionEvent> sendTransaction(Collection<? extends ProposalResponse> proposalResponses, Collection<Orderer> orderers, User userContext) {
        return sendTransaction(proposalResponses, createTransactionOptions().orderers(orderers).userContext(userContext));
    }

    /**
     * TransactionOptions class can be used to change how the SDK processes the Transaction.
     */
    public static class TransactionOptions {
        List<Orderer> orderers;
        boolean shuffleOrders = true;
        NOfEvents nOfEvents;
        User userContext;
        boolean failFast = true;

        /**
         * Fail fast when there is an invalid transaction received on the eventing peer being observed.
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
            this.orderers = new ArrayList<>(Arrays.asList(orderers)); //convert make sure we have a copy.
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
         * Events reporting Eventing Peers to complete the transaction.
         * This maybe set to NOfEvents.nofNoEvents that will complete the future as soon as a successful submission
         * to an Orderer, but the completed Transaction event in that case will be null.
         *
         * @param nOfEvents More details: @see {@link NOfEvents}
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
     * Additional metadata used by service discovery to find the endorsements needed.
     * Specify which chaincode is invoked and what collections are used.
     */
    public static class ServiceDiscoveryChaincodeCalls {
        String name;
        List<String> collections;

        ServiceDiscoveryChaincodeCalls(String chaincodeName) {
            this.name = chaincodeName;
        }

        /**
         * The collections used by this chaincode.
         *
         * @param collectionName name of collection.
         * @return
         */
        public ServiceDiscoveryChaincodeCalls addCollections(String... collectionName) {
            if (collections == null) {
                collections = new LinkedList<>();
            }
            collections.addAll(new ArrayList<>(Arrays.asList(collectionName)));
            return this;
        }

        String write(List<ServiceDiscoveryChaincodeCalls> dep) {
            StringBuilder cns = new StringBuilder(1000);
            cns.append("ServiceDiscoveryChaincodeCalls(name: ").append(name);

            String sep = "";

            final List<String> collections = getCollections();
            if (!collections.isEmpty()) {
                cns.append(", collections:[");
                String sep2 = "";
                for (String collection : collections) {
                    cns.append(sep2).append(collection);
                    sep2 = ", ";
                }
                cns.append("]");
            }
            if (dep != null && !dep.isEmpty()) {
                cns.append(" ,dependents:[");
                String sep2 = "";

                for (ServiceDiscoveryChaincodeCalls chaincodeCalls : dep) {
                    cns.append(sep2).append(chaincodeCalls.write(null));
                    sep2 = ", ";
                }

                cns.append("]");
            }
            cns.append(")");

            return cns.toString();
        }

        /**
         * Create ch
         *
         * @param name
         * @return
         * @throws InvalidArgumentException
         */
        public static ServiceDiscoveryChaincodeCalls createServiceDiscoveryChaincodeCalls(String name) throws InvalidArgumentException {
            if (isNullOrEmpty(name)) {
                throw new InvalidArgumentException("The name parameter must be non null nor an empty string.");
            }
            return new ServiceDiscoveryChaincodeCalls(name);
        }

        private Protocol.ChaincodeCall ret = null;

        Protocol.ChaincodeCall build() {
            if (ret == null) {
                final Protocol.ChaincodeCall.Builder builder = Protocol.ChaincodeCall.newBuilder().setName(name);
                if (collections != null && !collections.isEmpty()) {
                    builder.addAllCollectionNames(collections);
                }
                ret = builder.build();
            }

            return ret;
        }

        String getName() {
            return name;
        }

        List<String> getCollections() {
            return collections == null ? Collections.emptyList() : collections;
        }
    }

    /**
     * Options for doing service discovery.
     */
    public static class DiscoveryOptions {
        Set<String> ignoreList = new HashSet<>();
        ServiceDiscovery.EndorsementSelector endorsementSelector = null;
        boolean inspectResults = false;
        boolean forceDiscovery = false;

        List<ServiceDiscoveryChaincodeCalls> getServiceDiscoveryChaincodeInterests() {
            return serviceDiscoveryChaincodeInterests;
        }

        List<ServiceDiscoveryChaincodeCalls> serviceDiscoveryChaincodeInterests = null;

        /**
         * Create transaction options.
         *
         * @return return transaction options.
         */
        public static DiscoveryOptions createDiscoveryOptions() {
            return new DiscoveryOptions();
        }

        public boolean isInspectResults() {
            return inspectResults;
        }

        /**
         * Set to true to inspect proposals results on error.
         *
         * @param inspectResults
         * @return
         */
        public DiscoveryOptions setInspectResults(boolean inspectResults) {
            this.inspectResults = inspectResults;
            return this;
        }

        /**
         * Set the handler which selects the endorser endpoints from the alternatives provided by service discovery.
         *
         * @param endorsementSelector
         * @return
         * @throws InvalidArgumentException
         */
        public DiscoveryOptions setEndorsementSelector(ServiceDiscovery.EndorsementSelector endorsementSelector) throws InvalidArgumentException {
            if (endorsementSelector == null) {
                throw new InvalidArgumentException("endorsementSelector parameter is null.");
            }
            this.endorsementSelector = endorsementSelector;
            return this;
        }

        /**
         * Set which other chaincode calls are made by this chaincode and they're collections.
         *
         * @param serviceDiscoveryChaincodeInterests
         * @return DiscoveryOptions
         */
        public DiscoveryOptions setServiceDiscoveryChaincodeInterests(ServiceDiscoveryChaincodeCalls... serviceDiscoveryChaincodeInterests) {

            if (this.serviceDiscoveryChaincodeInterests == null) {
                this.serviceDiscoveryChaincodeInterests = new LinkedList<>();
            }
            this.serviceDiscoveryChaincodeInterests.addAll(new ArrayList<>(Arrays.asList(serviceDiscoveryChaincodeInterests)));
            return this;
        }

        /**
         * Force new service discovery
         *
         * @param forceDiscovery
         * @return
         */
        public DiscoveryOptions setForceDiscovery(boolean forceDiscovery) {
            this.forceDiscovery = forceDiscovery;
            return this;
        }

        public DiscoveryOptions ignoreEndpoints(String... endpoints) throws InvalidArgumentException {
            if (endpoints == null) {
                throw new InvalidArgumentException("endpoints parameter is null.");
            }
            for (String endpoint : endpoints) {
                if (endpoint == null) {
                    throw new InvalidArgumentException("endpoints parameter is null.");
                }
                ignoreList.add(endpoint);
            }
            return this;
        }

        Collection<String> getIgnoreList() {
            return ignoreList;
        }
    }

    /**
     * Send transaction to one of a specified set of orderers with the specified user context.
     * IF there are no eventing peers this future returns immediately completed
     * indicating that orderer has accepted the transaction only.
     *
     * @param proposalResponses
     * @param transactionOptions
     * @return Future allowing access to the result of the transaction invocation.
     */
    public CompletableFuture<TransactionEvent> sendTransaction(Collection<? extends ProposalResponse> proposalResponses,
                                                               TransactionOptions transactionOptions) {
        return doSendTransaction(proposalResponses, transactionOptions)
                .whenComplete((result, exception) -> logCompletion("sendTransaction", result, exception));
    }

    private <T> T logCompletion(final String message, final T result, final Throwable exception) {

        if (exception != null) {
            logger.error("Future completed exceptionally: " + message, exception);
        }
        return result;
    }

    private CompletableFuture<TransactionEvent> doSendTransaction(Collection<? extends ProposalResponse> proposalResponses,
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

            List<ProposalResponsePackage.Endorsement> ed = new LinkedList<>();
            ProposalPackage.Proposal proposal = null;
            ByteString proposalResponsePayload = null;
            String proposalTransactionID = null;
            TransactionContext transactionContext = null;

            for (ProposalResponse sdkProposalResponse : proposalResponses) {
                ed.add(sdkProposalResponse.getProposalResponse().getEndorsement());
                if (proposal == null) {
                    proposal = sdkProposalResponse.getProposal();
                    proposalTransactionID = sdkProposalResponse.getTransactionID();
                    if (proposalTransactionID == null) {
                        throw new InvalidArgumentException("Proposals with missing transaction ID");
                    }
                    proposalResponsePayload = sdkProposalResponse.getProposalResponse().getPayload();
                    if (proposalResponsePayload == null) {
                        throw new InvalidArgumentException("Proposals with missing payload.");
                    }
                    transactionContext = sdkProposalResponse.getTransactionContext();
                    if (transactionContext == null) {
                        throw new InvalidArgumentException("Proposals with missing transaction context.");
                    }
                } else {
                    final String transactionID = sdkProposalResponse.getTransactionID();
                    if (transactionID == null) {
                        throw new InvalidArgumentException("Proposals with missing transaction id.");
                    }
                    if (!proposalTransactionID.equals(transactionID)) {
                        throw new InvalidArgumentException(format("Proposals with different transaction IDs %s,  and %s", proposalTransactionID, transactionID));
                    }
                }
            }

            TransactionBuilder transactionBuilder = TransactionBuilder.newBuilder();

            Payload transactionPayload = transactionBuilder
                    .chaincodeProposal(proposal)
                    .endorsements(ed)
                    .proposalResponsePayload(proposalResponsePayload).build();

            Envelope transactionEnvelope = createTransactionEnvelope(transactionPayload, transactionContext);

            NOfEvents nOfEvents = transactionOptions.nOfEvents;

            if (nOfEvents == null) {
                nOfEvents = NOfEvents.createNofEvents();
                Collection<Peer> eventingPeers = getEventingPeers();
                boolean anyAdded = false;
                if (!eventingPeers.isEmpty()) {
                    anyAdded = true;
                    nOfEvents.addPeers(eventingPeers);
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

                if (nOfEvents.unSeenPeers().isEmpty()) {
                    issues.append("NofEvents had no added  Peer eventing services.");
                }
                String foundIssues = issues.toString();
                if (!foundIssues.isEmpty()) {
                    throw new InvalidArgumentException(foundIssues);
                }
            }

            final boolean replyonly = nOfEvents == NOfEvents.nofNoEvents || (getEventingPeers().isEmpty());

            CompletableFuture<TransactionEvent> sret;
            if (replyonly) { //If there are no eventsto complete the future, complete it
                // immediately but give no transaction event
                logger.debug(format("Completing transaction id %s immediately no peer eventing services found in channel %s.", proposalTransactionID, name));
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

    private Envelope createTransactionEnvelope(Payload transactionPayload, TransactionContext transactionContext) throws CryptoException, InvalidArgumentException {
        return Envelope.newBuilder()
                .setPayload(transactionPayload.toByteString())
                .setSignature(ByteString.copyFrom(transactionContext.sign(transactionPayload.toByteArray())))
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
            TransactionContext transactionContext = newTransactionContext(signer);
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

        if (null == listener) {
            throw new InvalidArgumentException("Listener parameter is null.");
        }

        String handle = new BL(listener).getHandle();
        logger.trace(format("Register event BlockEvent listener %s", handle));
        return handle;
    }

    /**
     * Register a Queued block listener. This queue should never block insertion of events.
     *
     * @param blockEventQueue the queue
     * @return return a handle to ungregister the handler.
     * @throws InvalidArgumentException
     */
    public String registerBlockListener(BlockingQueue<QueuedBlockEvent> blockEventQueue) throws InvalidArgumentException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (null == blockEventQueue) {
            throw new InvalidArgumentException("BlockEventQueue parameter is null.");
        }

        String handle = new BL(blockEventQueue, -1L, null).getHandle();
        logger.trace(format("Register QueuedBlockEvent listener %s", handle));
        return handle;
    }

    /**
     * Register a Queued block listener. This queue should never block insertion of events.
     *
     * @param blockEventQueue the queue
     * @param timeout         The time that is waited on for event to be waited on the queue
     * @param timeUnit        the time unit for timeout.
     * @return return a handle to ungregister the handler.
     * @throws InvalidArgumentException
     */
    public String registerBlockListener(BlockingQueue<QueuedBlockEvent> blockEventQueue, long timeout, TimeUnit timeUnit) throws InvalidArgumentException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        if (null == blockEventQueue) {
            throw new InvalidArgumentException("BlockEventQueue parameter is null.");
        }

        if (timeout < 0L) {
            throw new InvalidArgumentException(format("Timeout parameter must be greater than 0 not %d", timeout));
        }

        if (null == timeUnit) {
            throw new InvalidArgumentException("TimeUnit parameter must not be null.");
        }

        String handle = new BL(blockEventQueue, timeout, timeUnit).getHandle();
        logger.trace(format("Register QueuedBlockEvent listener %s", handle));
        return handle;
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
        logger.trace(format("Unregister BlockListener with handle %s.", handle));

        LinkedHashMap<String, BL> lblockListeners = blockListeners;
        if (lblockListeners == null) {
            return false;
        }

        synchronized (lblockListeners) {
            return null != lblockListeners.remove(handle);
        }
    }

    public Collection<String> getBlockListenerHandles() throws InvalidArgumentException {
        if (shutdown) {
            throw new InvalidArgumentException(format("Channel %s has been shutdown.", name));
        }

        LinkedHashMap<String, BL> lblockListeners = blockListeners;
        if (lblockListeners == null) {
            return Collections.emptyList();
        }

        synchronized (lblockListeners) {
            Set<String> ret = new HashSet<>(lblockListeners.keySet());
            // remove the SDKs own transaction block listener.
            final String ltransactionListenerProcessorHandle = transactionListenerProcessorHandle;
            if (null != ltransactionListenerProcessorHandle) {
                ret.remove(ltransactionListenerProcessorHandle);
            }

            return Collections.unmodifiableSet(ret);
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
                } catch (EventingException e) {
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
                                    name, blockEvent.getBlockNumber(), blockchainID, blockEvent.getPeer() != null ? ("" + blockEvent.getPeer()) :
                                            "");

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
                            if (l.listener != null) {
                                client.getExecutorService().execute(() -> l.listener.received(blockEvent));
                            } else if (l.blockingQueue != null) {
                                if (l.timeout < 0 || l.timeUnit == null) {
                                    l.blockingQueue.put(new QueuedBlockEvent(l.handle, blockEvent));
                                } else {
                                    if (!l.blockingQueue.offer(new QueuedBlockEvent(l.handle, blockEvent), l.timeout, l.timeUnit)) {
                                        logger.warn(format("Error calling block listener %s on channel: %s event: %s could not be added in time %d %s ",
                                                l.handle, name, from, l.timeout, l.timeUnit));
                                    }
                                }
                            }
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

            logger.info(format("Channel %s eventThread shutting down. shutdown: %b  thread: %s ", name, shutdown, Thread.currentThread().getName()));
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
            HFClient lclient = client;
            if (null == lclient || shutdown) { //can happen if were not quite shutdown
                return;
            }

            final String source = blockEvent.getPeer() != null ? blockEvent.getPeer().toString() :
                    "not peer!";

            logger.debug(format("is peer %b, is filtered: %b", blockEvent.getPeer() != null, blockEvent.isFiltered()));

            final Iterable<TransactionEvent> transactionEvents = blockEvent.getTransactionEvents();

            if (transactionEvents == null || !transactionEvents.iterator().hasNext()) {
                // no transactions today we can assume it was a config or update block.
                if (isLaterBlock(blockEvent.getBlockNumber())) {
                    ServiceDiscovery lserviceDiscovery = serviceDiscovery;
                    if (null != lserviceDiscovery) {

                        client.getExecutorService().execute(() -> lserviceDiscovery.fullNetworkDiscovery(true));
                    }
                } else {
                    lclient.getExecutorService().execute(() -> {
                        try {
                            if (!shutdown) {
                                loadCACertificates(true);
                            }
                        } catch (Exception e) {
                            logger.warn(format("Channel %s failed to load certificates for an update", name), e);
                        }
                    });
                }

                return;
            }

            if (txListeners.isEmpty() || shutdown) {
                return;
            }

            for (TransactionEvent transactionEvent : blockEvent.getTransactionEvents()) {
                logger.debug(format("Channel %s got event from %s for transaction %s in block number: %d", name,
                        source, transactionEvent.getTransactionID(), blockEvent.getBlockNumber()));

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
                        if (shutdown) {
                            break;
                        }
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

    private volatile long lastBlock = -1L;

    private synchronized boolean isLaterBlock(final long blockno) {
        if (blockno > lastBlock) {
            lastBlock = blockno;
            return true;
        }
        return false;
    }

    void runSweeper() {
        if (shutdown || DELTA_SWEEP < 1) {
            return;
        }

        if (sweeper == null) {
            sweeperExecutorService = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = Executors.defaultThreadFactory().newThread(r);
                t.setDaemon(true);
                return t;
            });
            sweeper = sweeperExecutorService.scheduleAtFixedRate(() -> {
                try {
                    if (txListeners != null) {
                        synchronized (txListeners) {
                            for (Iterator<Map.Entry<String, LinkedList<TL>>> it = txListeners.entrySet().iterator(); it.hasNext();) {
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

                List<MatchPair> matches = new LinkedList<>(); //Find matches.

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

        String ltransactionListenerProcessorHandle = transactionListenerProcessorHandle;
        transactionListenerProcessorHandle = null;
        if (null != ltransactionListenerProcessorHandle) {
            try {
                unregisterBlockListener(ltransactionListenerProcessorHandle);
            } catch (Exception e) {
                logger.error(format("Shutting down channel %s transactionListenerProcessorHandle", name), e);
            }
        }

        String lchaincodeEventUpgradeListenerHandle = chaincodeEventUpgradeListenerHandle;
        chaincodeEventUpgradeListenerHandle = null;
        if (null != lchaincodeEventUpgradeListenerHandle) {
            try {
                unregisterChaincodeEventListener(lchaincodeEventUpgradeListenerHandle);
            } catch (Exception e) {
                logger.error(format("Shutting down channel %s chaincodeEventUpgradeListenr", name), e);
            }
        }

        initialized = false;
        shutdown = true;

        final ServiceDiscovery lserviceDiscovery = serviceDiscovery;
        serviceDiscovery = null;
        if (null != lserviceDiscovery) {
            lserviceDiscovery.shutdown();
        }

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

        for (Peer peer : new ArrayList<>(getPeers())) {
            try {
                removePeerInternal(peer);
                peer.shutdown(force);
            } catch (Exception e) {
                // Best effort.
            }
        }
        peers.clear(); // make sure.

        peerMSPIDMap.clear();
        ordererMSPIDMap.clear();

        peerEndpointMap.clear();
        ordererEndpointMap.clear();

        //Make sure
        for (Set<Peer> peerRoleSet : peerRoleSetMap.values()) {
            peerRoleSet.clear();
        }

        for (Orderer orderer : getOrderers()) {
            orderer.shutdown(force);
        }

        orderers.clear();

        if (null != eventQueueThread) {
            eventQueueThread.interrupt();
            eventQueueThread = null;
        }
        ScheduledFuture<?> lsweeper = sweeper;
        sweeper = null;

        if (null != lsweeper) {
            lsweeper.cancel(true);
        }

        ScheduledExecutorService lse = sweeperExecutorService;
        sweeperExecutorService = null;
        if (null != lse) {
            lse.shutdownNow();
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
        try {
            shutdown(true);
        } finally {
            super.finalize();
        }
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
        protected BlockInfo.Type eventType = BlockInfo.Type.BLOCK;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(1000);
            sb.append("PeerOptions( " + format("newest: %s, startEvents: %s, stopEvents: %s, eventType: %s", "" + newest, "" + startEvents, "" + stopEvents, eventType));

            if (peerRoles != null && !peerRoles.isEmpty()) {
                sb.append(", PeerRoles:[");

                String sep = "";
                for (PeerRole peerRole : peerRoles) {
                    sb.append(sep).append(peerRole.getPropertyName());
                    sep = " ,";
                }
                sb.append("]");
            }
            sb.append(")");
            return sb.toString();
        }

        /**
         * Returns requested event type
         *
         * @return enum value of the event type
         */
        BlockInfo.Type getEventType() {
            return this.eventType;
        }

        /**
         * Register the peer eventing services to return filtered blocks.
         *
         * @return the PeerOptions instance.
         */
        public PeerOptions registerEventsForFilteredBlocks() {
            this.eventType = BlockInfo.Type.FILTERED_BLOCK;
            return this;
        }

        /**
         * Register the peer eventing services to return private data maps with the blocks.
         *
         * @return the PeerOptions instance.
         */
        public PeerOptions registerEventsForPrivateData() {
            this.eventType = BlockInfo.Type.BLOCK_WITH_PRIVATE_DATA;
            return this;
        }

        /**
         * Register the peer eventing services to return full event blocks.
         *
         * @return the PeerOptions instance.
         */
        public PeerOptions registerEventsForBlocks() {
            this.eventType = BlockInfo.Type.BLOCK;
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

        protected PeerOptions() { }

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
                peerRoles = EnumSet.complementOf(EnumSet.of(PeerRole.SERVICE_DISCOVERY));
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
        final MspConfigPackage.FabricMSPConfig fabricMSPConfig;
        byte[][] adminCerts;
        byte[][] rootCerts;
        byte[][] intermediateCerts;

        MSP(String orgName, MspConfigPackage.FabricMSPConfig fabricMSPConfig) {
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
            // May be fed by multiple eventhubs but BlockingQueue.add() is thread-safe
            events.add(event);

            return true;
        }

        BlockEvent getNextEvent() throws EventingException {
            if (shutdown) {
                throw new EventingException(format("Channel %s has been shutdown", name));
            }
            BlockEvent ret = null;
            if (eventException != null) {
                throw new EventingException(eventException);
            }
            try {
                ret = events.take();
            } catch (InterruptedException e) {
                if (shutdown) {
                    throw new EventingException(format("channel %s is shutdown", name), e);
                } else {
                    logger.warn(e);
                    if (eventException != null) {
                        EventingException eve = new EventingException(e);
                        logger.error(eve.getMessage(), eve);
                        throw eve;
                    }
                }
            }

            if (eventException != null) {
                throw new EventingException(eventException);
            }

            if (shutdown) {
                throw new EventingException(format("Channel %s has been shutdown.", name));
            }

            return ret;
        }
    }

    class BL {
        final BlockListener listener;
        final String handle;
        private final BlockingQueue<QueuedBlockEvent> blockingQueue;
        private final long timeout;
        private final TimeUnit timeUnit;

        {
            handle = BLOCK_LISTENER_TAG + Utils.generateUUID() + BLOCK_LISTENER_TAG;
            logger.debug(format("Channel %s blockListener %s starting", name, handle));

            synchronized (blockListeners) {
                blockListeners.put(handle, this);
            }
        }

        BL(BlockListener listener) {
            this.listener = listener;
            blockingQueue = null;
            timeout = Long.MAX_VALUE;
            timeUnit = null;
        }

        BL(BlockingQueue<QueuedBlockEvent> blockingQueue, long timeout, TimeUnit timeUnit) {
            this.blockingQueue = blockingQueue;
            this.timeout = timeout;
            this.timeUnit = timeUnit;
            listener = null;
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

        private final NOfEvents nOfEvents;
        long sweepTime = System.currentTimeMillis() + (long) (DELTA_SWEEP * 1.5);

        TL(String txID, CompletableFuture<TransactionEvent> future, NOfEvents nOfEvents, boolean failFast) {
            this.txID = txID;
            this.future = future;
            this.nOfEvents = new NOfEvents(nOfEvents);
            peers = new HashSet<>(nOfEvents.unSeenPeers());

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

            if (peer != null && !peers.contains(peer)) {
                return false;
            }

            if (failFast && !transactionEvent.isValid()) {
                return true;
            }

            if (peer != null) {
                nOfEvents.seen(peer);
                logger.debug(format("Channel %s seen transaction event %s for peer %s", name, txID, peer.toString()));
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

            if (IS_WARN_LEVEL && ret) {
                StringBuilder sb = new StringBuilder(10000);

                String sep = "Non reporting peers: ";
                for (Peer peer : nOfEvents.unSeenPeers()) {
                    sb.append(sep).append(peer.toString()).append(" status:")
                            .append(peer.getEventingStatus());
                    sep = ", ";
                }

                logger.warn(format("Force removing transaction listener after %d ms for transaction %s. %s" +
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
