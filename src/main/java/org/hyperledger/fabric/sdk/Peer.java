/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at`
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.discovery.Protocol;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.sdk.Channel.PeerOptions;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.PeerEventingServiceException;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.security.certgen.TLSCertificateKeyPair;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.checkGrpcUrl;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;
import static org.hyperledger.fabric.sdk.helper.Utils.parseGrpcUrl;

/**
 * The Peer class represents a peer to which SDK sends deploy, or query proposals requests.
 */
public class Peer implements Serializable {
    public static final String PEER_ORGANIZATION_MSPID_PROPERTY = "org.hyperledger.fabric.sdk.peer.organization_mspid";

    private static final Config config = Config.getConfig();
    private static final Log logger = LogFactory.getLog(Peer.class);
    private static final boolean IS_DEBUG_LEVEL = logger.isDebugEnabled();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();
    private static final long serialVersionUID = -5273194649991828876L;

    private static final long PEER_EVENT_RETRY_WAIT_TIME = config.getPeerRetryWaitTime();
    private transient String id;
    private Properties properties;
    private final String name;
    private final String url;
    private transient volatile EndorserClient endorserClent;
    private transient PeerEventServiceClient peerEventingClient;
    private transient volatile boolean shutdown = false;
    private Channel channel;
    private String channelName; // used for logging.
    private transient TransactionContext transactionContext;
    private transient long lastConnectTime;
    private transient AtomicLong reconnectCount;
    private transient BlockEvent lastBlockEvent;
    private transient long lastBlockNumber = -1L;
    private transient byte[] clientTLSCertificateDigest;
    private transient boolean foundClientTLSCertificateDigest;
    private transient boolean connected = false; // has this peer connected.
    private String endPoint = null;
    private String protocol = null;

    // The Peer has successfully connected.
    boolean hasConnected() {
        return connected;
    }

    Peer(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        reconnectCount = new AtomicLong(0L);
        id = config.getNextID();

        Exception e = checkGrpcUrl(grpcURL);
        if (e != null) {
            throw new InvalidArgumentException("Bad peer url.", e);

        }

        if (isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for peer");
        }

        this.url = grpcURL;
        this.name = name;
        this.properties = properties == null ? new Properties() : (Properties) properties.clone(); //keep our own copy.

        logger.debug("Created " + toString());
    }

    static Peer createNewInstance(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        return new Peer(name, grpcURL, properties);
    }

    /**
     * Peer's name
     *
     * @return return the peer's name.
     */
    public String getName() {
        return name;
    }

    public Properties getProperties() {
        return properties == null ? null : (Properties) properties.clone();
    }

    void unsetChannel() {
        logger.debug(toString() + " unset " + channel);
        channel = null;
    }

    BlockEvent getLastBlockEvent() {
        return lastBlockEvent;
    }

    ExecutorService getExecutorService() {
        return channel.getExecutorService();
    }

    void initiateEventing(TransactionContext transactionContext, PeerOptions peersOptions) throws TransactionException {
        this.transactionContext = transactionContext.retryTransactionSameContext();

        if (peerEventingClient == null && !shutdown) {
            peerEventingClient = new PeerEventServiceClient(this, Endpoint.createEndpoint(url, properties), properties, peersOptions);
            peerEventingClient.connect(transactionContext);
        }
    }

    /**
     * The channel the peer is set on.
     *
     * @return
     */
    Channel getChannel() {
        return channel;
    }

    boolean isShutdown() {
        return shutdown;
    }

    /**
     * Set the channel the peer is on.
     *
     * @param channel
     */
    void setChannel(Channel channel) throws InvalidArgumentException {
        if (null != this.channel) {
            throw new InvalidArgumentException(format("Can not add peer %s to channel %s because it already belongs to channel %s.",
                    name, channel.getName(), this.channel.getName()));
        }
        logger.debug(format("%s setting channel to %s, from %s", toString(), "" + channel, "" + this.channel));

        this.channel = channel;
        this.channelName = channel.getName();
        toString = null; //recalculated
    }

    /**
     * Get the URL of the peer.
     *
     * @return {string} Get the URL associated with the peer.
     */
    public String getUrl() {
        return url;
    }

    /**
     * for use in list of peers comparisons , e.g. list.contains() calls
     *
     * @param otherPeer the peer instance to compare against
     * @return true if both peer instances have the same name and url
     */
    @Override
    public boolean equals(Object otherPeer) {
        if (this == otherPeer) {
            return true;
        }
        if (otherPeer == null) {
            return false;
        }
        if (!(otherPeer instanceof Peer)) {
            return false;
        }
        Peer p = (Peer) otherPeer;
        return Objects.equals(this.name, p.name) && Objects.equals(this.url, p.url);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, url);
    }

    CompletableFuture<ProposalResponsePackage.ProposalResponse> sendProposalAsync(ProposalPackage.SignedProposal proposal) {
        try {
            checkSendProposal(proposal);
        } catch (Exception e) {
            CompletableFuture<ProposalResponsePackage.ProposalResponse> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }

        if (IS_DEBUG_LEVEL) {
            logger.debug(format("peer.sendProposalAsync %s", toString()));
        }

        EndorserClient localEndorserClient = getEndorserClient();

        return localEndorserClient.sendProposalAsync(proposal).exceptionally(throwable -> {
            removeEndorserClient(true);
            if (throwable instanceof CompletionException) {
                throw (CompletionException) throwable;
            }
            throw new CompletionException(throwable);
        });
    }

    private synchronized EndorserClient getEndorserClient() {
        EndorserClient localEndorserClient = endorserClent; //work off thread local copy.

        if (null == localEndorserClient || !localEndorserClient.isChannelActive()) {
            if (IS_TRACE_LEVEL) {
                logger.trace(format("Channel %s creating new endorser client %s", channelName, toString()));
            }
            Endpoint endpoint = Endpoint.createEndpoint(url, properties);
            foundClientTLSCertificateDigest = true;
            clientTLSCertificateDigest = endpoint.getClientTLSCertificateDigest();
            localEndorserClient = new EndorserClient(channelName, name, url, endpoint.getChannelBuilder());
            if (IS_DEBUG_LEVEL) {
                logger.debug(format("%s created new  %s", toString(), localEndorserClient.toString()));
            }
            endorserClent = localEndorserClient;
        }
        return localEndorserClient;
    }

    private synchronized void removeEndorserClient(boolean force) {
        EndorserClient localEndorserClient = endorserClent;
        endorserClent = null;

        if (null != localEndorserClient) {
            if (IS_DEBUG_LEVEL) {
                logger.debug(format("Peer %s removing endorser client %s, isActive: %b", toString(), localEndorserClient.toString(), localEndorserClient.isChannelActive()));
            }
            try {
                localEndorserClient.shutdown(force);
            } catch (Exception e) {
                logger.warn(toString() + " error message: " + e.getMessage());
            }

        }
    }

    CompletableFuture<Protocol.Response> sendDiscoveryRequestAsync(Protocol.SignedRequest discoveryRequest) {
        logger.debug(format("peer.sendDiscoveryRequstAsync %s", toString()));

        EndorserClient localEndorserClient = getEndorserClient();

        return localEndorserClient.sendDiscoveryRequestAsync(discoveryRequest).exceptionally(throwable -> {
            removeEndorserClient(true);
            if (throwable instanceof CompletionException) {
                throw (CompletionException) throwable;
            }
            throw new CompletionException(throwable);
        });
    }

    synchronized byte[] getClientTLSCertificateDigest() {
        byte[] lclientTLSCertificateDigest = clientTLSCertificateDigest;
        if (lclientTLSCertificateDigest == null) {
            if (!foundClientTLSCertificateDigest) {
                foundClientTLSCertificateDigest = true;
                Endpoint endpoint = Endpoint.createEndpoint(url, properties);
                lclientTLSCertificateDigest = endpoint.getClientTLSCertificateDigest();
            }
        }

        return lclientTLSCertificateDigest;
    }

    private void checkSendProposal(ProposalPackage.SignedProposal proposal) throws
            PeerException, InvalidArgumentException {
        if (shutdown) {
            throw new PeerException(format("%s was shutdown.", toString()));
        }
        if (proposal == null) {
            throw new PeerException(toString() + " Proposal is null");
        }
        Exception e = checkGrpcUrl(url);
        if (e != null) {
            throw new InvalidArgumentException("Bad peer url.", e);

        }
    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        final String me = toString();
        logger.debug(me + " is shutting down.");
        shutdown = true;
        channel = null;
        lastBlockEvent = null;
        lastBlockNumber = -1L;

        removeEndorserClient(force);

        PeerEventServiceClient lpeerEventingClient = peerEventingClient;
        peerEventingClient = null;

        if (null != lpeerEventingClient) {
            // PeerEventServiceClient peerEventingClient1 = peerEventingClient;
            logger.debug(me + " is shutting down " + lpeerEventingClient);
            lpeerEventingClient.shutdown(force);
        }

        logger.debug(me + " is shut down.");
    }

    String getEventingStatus() {

        PeerEventServiceClient lpeerEventingClient = peerEventingClient;
        if (null == lpeerEventingClient) {
            return " eventing client service not active.";

        }
        return lpeerEventingClient.getStatus();
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (!shutdown) {
                logger.debug(toString() + " finalized without previous shutdown.");
            }
            shutdown(true);
        } finally {
            super.finalize();
        }
    }

    void reconnectPeerEventServiceClient(final PeerEventServiceClient failedPeerEventServiceClient,
                                         final Throwable throwable) {
        if (shutdown) {
            logger.debug(toString() + "not reconnecting PeerEventServiceClient shutdown ");
            return;

        }
        PeerEventingServiceDisconnected ldisconnectedHandler = disconnectedHandler;
        if (null == ldisconnectedHandler) {

            return; // just wont reconnect.

        }
        TransactionContext ltransactionContext = transactionContext;
        if (ltransactionContext == null) {

            logger.warn(toString() + " not reconnecting PeerEventServiceClient no transaction available ");
            return;
        }

        final TransactionContext fltransactionContext = ltransactionContext.retryTransactionSameContext();

        final ExecutorService executorService = getExecutorService();
        final PeerOptions peerOptions = null != failedPeerEventServiceClient.getPeerOptions() ? failedPeerEventServiceClient.getPeerOptions() :
                PeerOptions.createPeerOptions();
        if (!shutdown && executorService != null && !executorService.isShutdown() && !executorService.isTerminated()) {

            executorService.execute(() -> ldisconnectedHandler.disconnected(new PeerEventingServiceDisconnectEvent() {
                @Override
                public BlockEvent getLatestBLockReceived() {
                    return lastBlockEvent;
                }

                @Override
                public long getLastConnectTime() {
                    return lastConnectTime;
                }

                @Override
                public long getReconnectCount() {
                    return reconnectCount.longValue();
                }

                @Override
                public Throwable getExceptionThrown() {
                    return throwable;
                }

                @Override
                public void reconnect(Long startBLockNumber) throws TransactionException {
                    logger.trace(format("%s reconnecting. Starting block number: %s", Peer.this.toString(), startBLockNumber == null ? "newest" : startBLockNumber));
                    reconnectCount.getAndIncrement();

                    if (startBLockNumber == null) {
                        peerOptions.startEventsNewest();
                    } else {
                        peerOptions.startEvents(startBLockNumber);
                    }

                    if (!shutdown) {
                        PeerEventServiceClient lpeerEventingClient = new PeerEventServiceClient(Peer.this,
                                Endpoint.createEndpoint(url, properties), properties, peerOptions);
                        lpeerEventingClient.connect(fltransactionContext);
                        peerEventingClient = lpeerEventingClient;
                    }
                }
            }));
        }
    }

    void setLastConnectTime(long lastConnectTime) {
        this.lastConnectTime = lastConnectTime;
    }

    void resetReconnectCount() {
        connected = true;
        reconnectCount = new AtomicLong(0L);
    }

    long getReconnectCount() {
        return reconnectCount.longValue();
    }

    synchronized void setTLSCertificateKeyPair(TLSCertificateKeyPair tlsCertificateKeyPair) {
        if (properties == null) {
            properties = new Properties();
        }
        properties.put("clientKeyBytes", tlsCertificateKeyPair.getKeyPemBytes());
        properties.put("clientCertBytes", tlsCertificateKeyPair.getCertPEMBytes());

        Endpoint endpoint = Endpoint.createEndpoint(url, properties);
        foundClientTLSCertificateDigest = true;
        clientTLSCertificateDigest = endpoint.getClientTLSCertificateDigest();
        removeEndorserClient(true);
        endorserClent = new EndorserClient(channelName, name, url, endpoint.getChannelBuilder());
    }

    void setHasConnected() {
        connected = true;
    }

    void setProperties(Properties properties) {
        this.properties = properties == null ? new Properties() : properties;
        toString = null; //recalculated
    }

    public interface PeerEventingServiceDisconnected {
        /**
         * Called when a disconnect is detected in peer eventing service.
         *
         * @param event
         */
        void disconnected(PeerEventingServiceDisconnectEvent event);
    }

    public interface PeerEventingServiceDisconnectEvent {
        /**
         * The latest BlockEvent received by peer eventing service.
         *
         * @return The latest BlockEvent.
         */
        BlockEvent getLatestBLockReceived();

        /**
         * Last connect time
         *
         * @return Last connect time as reported by System.currentTimeMillis()
         */
        long getLastConnectTime();

        /**
         * Number reconnection attempts since last disconnection.
         *
         * @return reconnect attempts.
         */
        long getReconnectCount();

        /**
         * Last exception throw for failing connection
         *
         * @return
         */
        Throwable getExceptionThrown();

        void reconnect(Long startEvent) throws TransactionException;
    }

    private transient PeerEventingServiceDisconnected disconnectedHandler = getDefaultDisconnectHandler();

    private static PeerEventingServiceDisconnected getDefaultDisconnectHandler() {
        return new PeerEventingServiceDisconnected() { //default.
            @Override
            public synchronized void disconnected(final PeerEventingServiceDisconnectEvent event) {
                BlockEvent lastBlockEvent = event.getLatestBLockReceived();
                Throwable thrown = event.getExceptionThrown();

                long sleepTime = PEER_EVENT_RETRY_WAIT_TIME;

                if (thrown instanceof PeerEventingServiceException) {
                    // means we connected and got an error or connected but timout waiting on the response
                    // not going away.. sleep longer.
                    sleepTime = Math.min(5000L, PEER_EVENT_RETRY_WAIT_TIME + event.getReconnectCount() * 100L); //wait longer if we connected.
                    //don't flood server.
                }

                Long startBlockNumber = null;

                if (null != lastBlockEvent) {

                    startBlockNumber = lastBlockEvent.getBlockNumber();
                }

                try {
                    Thread.sleep(sleepTime);
                } catch (InterruptedException e) {
                    logger.warn(toString() + " " + e.getMessage());
                }

                try {
                    event.reconnect(startBlockNumber);
                } catch (TransactionException e) {
                    logger.warn(toString() + " " + e.getMessage());
                }
            }
        };
    }

    /**
     * Get current disconnect handler service
     *
     * @return The current disconnect handler service.
     */
    public PeerEventingServiceDisconnected getPeerEventingServiceDisconnected() {
        return disconnectedHandler;
    }

    /**
     * Set class to handle peer eventing service  disconnects
     *
     * @param newPeerEventingServiceDisconnectedHandler New handler to replace.  If set to null no retry will take place.
     * @return the old handler.
     */
    public PeerEventingServiceDisconnected setPeerEventingServiceDisconnected(PeerEventingServiceDisconnected newPeerEventingServiceDisconnectedHandler) {
        PeerEventingServiceDisconnected ret = disconnectedHandler;
        disconnectedHandler = newPeerEventingServiceDisconnectedHandler;
        return ret;
    }

    synchronized void setLastBlockSeen(BlockEvent lastBlockSeen) {
        connected = true;
        long newLastBlockNumber = lastBlockSeen.getBlockNumber();
        // overkill but make sure.
        if (lastBlockNumber < newLastBlockNumber) {
            lastBlockNumber = newLastBlockNumber;
            this.lastBlockEvent = lastBlockSeen;
            if (IS_TRACE_LEVEL) {
                logger.trace(toString() + " last block seen: " + lastBlockNumber);
            }
        }
    }

    /**
     * Possible roles a peer can perform.
     */
    public enum PeerRole {
        /**
         * Endorsing peer installs and runs chaincode.
         */
        ENDORSING_PEER("endorsingPeer"),
        /**
         * Chaincode query peer will be used to invoke chaincode on chaincode query requests.
         */
        CHAINCODE_QUERY("chaincodeQuery"),
        /**
         * Ledger Query will be used when query ledger operations are requested.
         */
        LEDGER_QUERY("ledgerQuery"),
        /**
         * Peer will monitor block events for the channel it belongs to.
         */
        EVENT_SOURCE("eventSource"),

        /**
         * Peer will monitor block events for the channel it belongs to.
         */
        SERVICE_DISCOVERY("serviceDiscovery");

        /**
         * All roles.
         */
        public static final EnumSet<PeerRole> ALL = EnumSet.allOf(PeerRole.class);
        /**
         * All roles except event source.
         */
        public static final EnumSet<PeerRole> NO_EVENT_SOURCE = EnumSet.complementOf(EnumSet.of(PeerRole.EVENT_SOURCE));
        private final String propertyName;

        PeerRole(String propertyName) {
            this.propertyName = propertyName;
        }

        public String getPropertyName() {
            return propertyName;
        }
    }

    String getEndpoint() {
        if (null == endPoint) {
            Properties properties = parseGrpcUrl(url);
            endPoint = properties.get("host") + ":" + properties.getProperty("port").toLowerCase().trim();

        }
        return endPoint;
    }

    public String getProtocol() {
        if (null == protocol) {
            Properties properties = parseGrpcUrl(url);
            protocol = properties.getProperty("protocol");

        }
        return protocol;
    }

    private transient String toString;

    @Override
    public String toString() {
        String ltoString = toString;
        if (ltoString == null) {
            String mspid = "";

            if (properties != null && !isNullOrEmpty(properties.getProperty(PEER_ORGANIZATION_MSPID_PROPERTY))) {
                mspid = ", mspid: " + properties.getProperty(PEER_ORGANIZATION_MSPID_PROPERTY);
            }
            ltoString = "Peer{ id: " + id + ", name: " + name + ", channelName: " + channelName + ", url: " + url + mspid + "}";
            toString = ltoString;
        }
        return ltoString;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        disconnectedHandler = getDefaultDisconnectHandler();
        connected = false;
        reconnectCount = new AtomicLong(0L);
        id = config.getNextID();
        lastBlockNumber = -1L;

        logger.debug(format("Reserialized peer: %s", this.toString()));
    }
} // end Peer
