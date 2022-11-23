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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.NetworkConfigurationException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.User.userContextCheck;

public class HFClient {
    private static final Config config = Config.getConfig(); // never remove this! config needs to load first.

    private CryptoSuite cryptoSuite;
    protected ExecutorService executorService;

    static {

        if (null == System.getProperty("org.hyperledger.fabric.sdk.logGRPC")) {
            // Turn this off by default!
            Logger.getLogger("io.netty").setLevel(Level.OFF);
            Logger.getLogger("io.grpc").setLevel(Level.OFF);

        }
    }

    public ExecutorService getExecutorService() {
        if (null == executorService) {
            synchronized (this) { //was null so lets get a lock for safe update.
                if (null == executorService) { // no other thread has done it ...
                    executorService = Executors.newFixedThreadPool(CLIENT_THREAD_EXECUTOR_POOLSIZE, r -> {
                        Thread t = threadFactory.newThread(r);
                        t.setDaemon(true);
                        return t;
                    });
                }
            }

        }
        return executorService;
    }

    private static final Log logger = LogFactory.getLog(HFClient.class);

    private final Map<String, Channel> channels = new HashMap<>();

    public User getUserContext() {
        return userContext;
    }

    private User userContext;

    protected final ThreadFactory threadFactory = Executors.defaultThreadFactory();

    private static final int CLIENT_THREAD_EXECUTOR_POOLSIZE = Math.max(config.getClientThreadExecutorCorePoolSize(), config.getClientThreadExecutorMaxiumPoolSize());

    private HFClient() {
    }

    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
    }

    public void setCryptoSuite(CryptoSuite cryptoSuite) throws CryptoException, InvalidArgumentException {
        if (null == cryptoSuite) {
            throw new InvalidArgumentException("CryptoSuite parameter is null.");
        }
        if (this.cryptoSuite != null && cryptoSuite != this.cryptoSuite) {
            throw new InvalidArgumentException("CryptoSuite may only be set once.");

        }

        this.cryptoSuite = cryptoSuite;

    }

    /**
     * Set executor service  Applications need to set the executor service prior to doing any other operations on the client.
     *
     * @param executorService The executor service the application wants to use.
     * @throws InvalidArgumentException if executor service has been set already.
     */

    public synchronized void setExecutorService(ExecutorService executorService) throws InvalidArgumentException {

        if (executorService == null) {
            throw new InvalidArgumentException("Executor service can not be null.");
        }
        if (this.executorService != null && this.executorService != executorService) {
            throw new InvalidArgumentException("Executor service has already been set.");
        }

        this.executorService = executorService;

    }

    /**
     * createNewInstance create a new instance of the HFClient
     *
     * @return client
     */
    public static HFClient createNewInstance() {
        return new HFClient();
    }

    /**
     * Set sensible default grpc properties for newPeer and newOrderer.  Only sets values
     * if they don't already exist.
     * @param props The properties object to apply defaults to
     */
    private void setDefaultProperties(Properties props) {
        if (!props.containsKey("grpc.NettyChannelBuilderOption.keepAliveTime")) {
            props.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {2L, TimeUnit.MINUTES});
        }
        if (!props.containsKey("grpc.NettyChannelBuilderOption.keepAliveTimeout")) {
            props.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {20L, TimeUnit.SECONDS});
        }
        if (!props.containsKey("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls")) {
            props.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls",  new Object[] {true});
        }
    }

    /**
     * Configures a channel based on information loaded from a Network Config file.
     * Note that it is up to the caller to initialize the returned channel.
     *
     * @param channelName                    The name of the channel to be configured
     * @param networkConfig                  The network configuration to use to configure the channel
     * @param networkConfigAddPeerHandler    A handler that will create and add peers to the channel.
     * @param networkConfigAddOrdererHandler A handler that will create orderers and add orderers to the channel.
     * @return The configured channel, or null if the channel is not defined in the configuration
     * @throws InvalidArgumentException
     */
    public Channel loadChannelFromConfig(String channelName, NetworkConfig networkConfig,
                                         NetworkConfig.NetworkConfigAddPeerHandler networkConfigAddPeerHandler,
                                         NetworkConfig.NetworkConfigAddOrdererHandler networkConfigAddOrdererHandler) throws InvalidArgumentException, NetworkConfigurationException {
        clientCheck();

        // Sanity checks
        if (channelName == null || channelName.isEmpty()) {
            throw new InvalidArgumentException("channelName must be specified");
        }

        if (networkConfig == null) {
            throw new InvalidArgumentException("networkConfig must be specified");
        }

        if (null == networkConfigAddPeerHandler) {
            throw new InvalidArgumentException("networkConfigAddPeerHandler is null.");
        }

        if (null == networkConfigAddOrdererHandler) {
            throw new InvalidArgumentException("networkConfigAddOrdererHandler is null.");
        }

        if (channels.containsKey(channelName)) {
            throw new InvalidArgumentException(format("Channel with name %s already exists", channelName));
        }

        return networkConfig.loadChannel(this, channelName, networkConfigAddPeerHandler, networkConfigAddOrdererHandler);
    }

    /**
     * Configures a channel based on information loaded from a Network Config file.
     * Note that it is up to the caller to initialize the returned channel.
     *
     * @param channelName   The name of the channel to be configured
     * @param networkConfig The network configuration to use to configure the channel
     * @return The configured channel, or null if the channel is not defined in the configuration
     * @throws InvalidArgumentException
     */
    public Channel loadChannelFromConfig(String channelName, NetworkConfig networkConfig) throws InvalidArgumentException, NetworkConfigurationException {
        clientCheck();

        // Sanity checks
        if (channelName == null || channelName.isEmpty()) {
            throw new InvalidArgumentException("channelName must be specified");
        }

        if (networkConfig == null) {
            throw new InvalidArgumentException("networkConfig must be specified");
        }

        if (channels.containsKey(channelName)) {
            throw new InvalidArgumentException(format("Channel with name %s already exists", channelName));
        }

        return networkConfig.loadChannel(this, channelName);
    }

    /**
     * newChannel - already configured channel.
     *
     * @param name
     * @return a new channel.
     * @throws InvalidArgumentException
     */

    public Channel newChannel(String name) throws InvalidArgumentException {
        clientCheck();
        if (Utils.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Channel name can not be null or empty string.");
        }

        synchronized (channels) {

            if (channels.containsKey(name)) {
                throw new InvalidArgumentException(format("Channel by the name %s already exists", name));
            }
            logger.trace("Creating channel :" + name);
            Channel newChannel = Channel.createNewInstance(name, this);

            channels.put(name, newChannel);
            return newChannel;

        }

    }

    /**
     * Create a new channel
     *
     * @param name                           The channel's name
     * @param orderer                        Orderer to create the channel with.
     * @param channelConfiguration           Channel configuration data.
     * @param channelConfigurationSignatures byte arrays containing ConfigSignature's proto serialized.
     *                                       See {@link Channel#getChannelConfigurationSignature} on how to create
     * @return a new channel.
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public Channel newChannel(String name, Orderer orderer, ChannelConfiguration channelConfiguration,
                              byte[]... channelConfigurationSignatures) throws TransactionException, InvalidArgumentException {

        clientCheck();
        if (Utils.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Channel name can not be null or empty string.");
        }

        synchronized (channels) {

            if (channels.containsKey(name)) {
                throw new InvalidArgumentException(format("Channel by the name %s already exits", name));
            }

            logger.trace("Creating channel :" + name);

            Channel newChannel = Channel.createNewInstance(name, this, orderer, channelConfiguration,
                    channelConfigurationSignatures);

            channels.put(name, newChannel);
            return newChannel;

        }

    }

    /**
     * Deserialize a channel serialized by {@link Channel#serializeChannel()}
     *
     * @param file a file which contains the bytes to be deserialized.
     * @return A Channel that has not been initialized.
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidArgumentException
     */

    public Channel deSerializeChannel(File file) throws IOException, ClassNotFoundException, InvalidArgumentException {

        if (null == file) {
            throw new InvalidArgumentException("File parameter may not be null");
        }

        return deSerializeChannel(Files.readAllBytes(Paths.get(file.getAbsolutePath())));
    }

    /**
     * Deserialize a channel serialized by {@link Channel#serializeChannel()}
     *
     * @param channelBytes bytes to be deserialized.
     * @return A Channel that has not been initialized.
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidArgumentException
     */

    public Channel deSerializeChannel(byte[] channelBytes)
            throws IOException, ClassNotFoundException, InvalidArgumentException {

        Channel channel;
        ObjectInputStream in = null;
        try {
            in = new ObjectInputStream(new ByteArrayInputStream(channelBytes));
            channel = (Channel) in.readObject();
            final String name = channel.getName();
            synchronized (channels) {
                if (null != getChannel(name)) {
                    channel.shutdown(true);
                    throw new InvalidArgumentException(format("Channel %s already exists in the client", name));
                }
                channels.put(name, channel);
                channel.client = this;
            }

        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException e) {
                // Best effort here.
                logger.error(e);
            }
        }

        return channel;

    }

    /**
     * newPeer create a new peer
     *
     * @param name       name of peer.
     * @param grpcURL    to the peer's location
     * @param properties <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>pemBytes - byte array for x509 pem certificates for SSL</li>
     *                   <li>trustServerCertificate - boolen(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>clientKeyFile - File location for private key pem for mutual TLS</li>
     *                   <li>clientCertFile - File location for x509 pem certificate for mutual TLS</li>
     *                   <li>clientKeyBytes - Private key pem bytes for mutual TLS</li>
     *                   <li>clientCertBytes - x509 pem certificate bytes for mutual TLS</li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
     *                   </li>
     *                   <li>
     *                   peerEventRegistrationWaitTime - Time in milliseconds to wait for peer eventing service registration.
     *                   </li>
     *                   <li>
     *                   org.hyperledger.fabric.sdk.peer.organization_mspid {@link Peer#PEER_ORGANIZATION_MSPID_PROPERTY} - Associates peer to an organization by its mspid.
     *                   </li>
     *                   <li>
     *                   grpc.NettyChannelBuilderOption.&lt;methodName&gt;  where methodName is any method on
     *                   grpc ManagedChannelBuilder.  If more than one argument to the method is needed then the
     *                   parameters need to be supplied in an array of Objects.
     *                   </li>
     *                   </ul>
     * @return Peer
     * @throws InvalidArgumentException
     */

    public Peer newPeer(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        clientCheck();
        setDefaultProperties(properties);
        return Peer.createNewInstance(name, grpcURL, properties);
    }

    /**
     * newPeer create a new peer
     *
     * @param name
     * @param grpcURL to the peer's location
     * @return Peer
     * @throws InvalidArgumentException
     */

    public Peer newPeer(String name, String grpcURL) throws InvalidArgumentException {
        clientCheck();
        return Peer.createNewInstance(name, grpcURL, new Properties());
    }

    /**
     * getChannel by name
     *
     * @param name The channel name
     * @return a channel (or null if the channel does not exist)
     */

    public Channel getChannel(String name) {
        return channels.get(name);
    }

    /**
     * newInstallProposalRequest get new Install proposal request.
     *
     * @return InstallProposalRequest
     * @deprecated see {@link #newLifecycleQueryInstalledChaincodesRequest()}
     */
    @Deprecated
    public InstallProposalRequest newInstallProposalRequest() {
        return new InstallProposalRequest(userContext);
    }

    /**
     * newInstallProposalRequest get new Query Install proposal request.
     *
     * @return {@link LifecycleInstallChaincodeProposalResponse}
     */
    public LifecycleInstallChaincodeRequest newLifecycleInstallChaincodeRequest() {
        return new LifecycleInstallChaincodeRequest(userContext);
    }

    /**
     * Get newLifecycleQueryInstalledChaincodeRequest to find chaincodes installed.
     *
     * @return {@link LifecycleInstallChaincodeProposalResponse} finds chaincodes installed.
     */
    public LifecycleQueryInstalledChaincodeRequest newLifecycleQueryInstalledChaincodeRequest() {
        return new LifecycleQueryInstalledChaincodeRequest(userContext);
    }

    /**
     * LifecycleQueryInstalledChaincodesRequest get new Query Install proposal request.
     *
     * @return {@link LifecycleQueryInstalledChaincodesRequest}
     */
    public LifecycleQueryInstalledChaincodesRequest newLifecycleQueryInstalledChaincodesRequest() {
        return new LifecycleQueryInstalledChaincodesRequest(userContext);
    }

    /**
     * newLifecycleApproveChaincodeDefinitionForMyOrgRequest get new Install proposal request.
     *
     * @return LifecycleApproveChaincodeDefinitionForMyOrgRequest
     */
    public LifecycleApproveChaincodeDefinitionForMyOrgRequest newLifecycleApproveChaincodeDefinitionForMyOrgRequest() {
        return new LifecycleApproveChaincodeDefinitionForMyOrgRequest(userContext);
    }

    /**
     * Get a LifecycleSimulateCommitChaincodeDefinitionRequest to find which chaincodes are approved by which organization.
     *
     * @return
     */
    public LifecycleCheckCommitReadinessRequest newLifecycleSimulateCommitChaincodeDefinitionRequest() {
        return new LifecycleCheckCommitReadinessRequest(userContext);
    }

    /**
     * newLifecycleApproveChaincodeDefinitionForMyOrgRequest get new Install proposal request.
     *
     * @return LifecycleCommitChaincodeDefinitionRequest
     */
    public LifecycleCommitChaincodeDefinitionRequest newLifecycleCommitChaincodeDefinitionRequest() {
        return new LifecycleCommitChaincodeDefinitionRequest(userContext);
    }

    /**
     * Create a new QueryChaincodeDefinitions proposal request.
     *
     * @return A proposal request.
     */
    public LifecycleQueryChaincodeDefinitionsRequest newLifecycleQueryChaincodeDefinitionsRequest() {
        return new LifecycleQueryChaincodeDefinitionsRequest(userContext);
    }

    /**
     * get QueryLifecycleQueryChaincodeDefinitionRequest find which chaincodes are defined.
     *
     * @return QueryLifecycleQueryChaincodeDefinitionRequest
     */
    public QueryLifecycleQueryChaincodeDefinitionRequest newQueryLifecycleQueryChaincodeDefinitionRequest() {
        return new QueryLifecycleQueryChaincodeDefinitionRequest(userContext);
    }

    /**
     * Send install chaincode request proposal to peers.
     *
     * @param lifecycleInstallChaincodeRequest
     * @param peers                            Collection of peers to install on.
     * @return responses from peers.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<LifecycleInstallChaincodeProposalResponse> sendLifecycleInstallChaincodeRequest(LifecycleInstallChaincodeRequest lifecycleInstallChaincodeRequest,
                                                                                                      Collection<Peer> peers) throws ProposalException, InvalidArgumentException {

        if (null == lifecycleInstallChaincodeRequest) {
            throw new InvalidArgumentException("The lifecycleInstallChaincodeRequest parameter can not be null.");
        }
        clientCheck();

        lifecycleInstallChaincodeRequest.setSubmitted();
        Channel systemChannel = Channel.newSystemChannel(this);

        return systemChannel.sendLifecycleInstallProposal(lifecycleInstallChaincodeRequest, peers);

    }

    /**
     * Query installed chaincode on a peer.
     *
     * @param lifecycleQueryInstalledChaincodeRequest The request {@link LifecycleQueryInstalledChaincodeRequest}
     * @param peers                                   the peer to send the request to.
     * @return LifecycleQueryInstalledChaincodeProposalResponse
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<LifecycleQueryInstalledChaincodeProposalResponse> sendLifecycleQueryInstalledChaincode(LifecycleQueryInstalledChaincodeRequest lifecycleQueryInstalledChaincodeRequest,
                                                                                                             Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (null == lifecycleQueryInstalledChaincodeRequest) {
            throw new InvalidArgumentException("The lifecycleQueryInstalledChaincodeRequest parameter can not be null.");
        }
        clientCheck();

        if (null == peers) {

            throw new InvalidArgumentException("The parameter peers set to null");

        }

        if (peers.isEmpty()) {

            throw new InvalidArgumentException("Peers to query is empty.");

        }

        if (lifecycleQueryInstalledChaincodeRequest == null) {
            throw new InvalidArgumentException("The lifecycleQueryInstalledChaincoded parameter must not be null.");
        }

        if (Utils.isNullOrEmpty(lifecycleQueryInstalledChaincodeRequest.getPackageId())) {
            throw new InvalidArgumentException("The lifecycleQueryInstalledChaincoded packageID parameter must not be null.");
        }

        try {
            //Run this on a system channel.

            Channel systemChannel = Channel.newSystemChannel(this);

            return systemChannel.lifecycleQueryInstalledChaincode(lifecycleQueryInstalledChaincodeRequest, peers);
        } catch (ProposalException e) {
            logger.error(format("lifecycleQueryInstalledChaincodeRequest for failed. %s", e.getMessage()), e);
            throw e;
        }

    }

    /**
     * Query the peer for installed chaincodes information
     *
     * @param lifecycleQueryInstalledChaincodesRequest the request {@link LifecycleQueryInstalledChaincodesRequest}
     * @param peers                                    The peer to query.
     * @return Collection of ChaincodeInfo on installed chaincode @see {@link LifecycleQueryInstalledChaincodesProposalResponse}
     * @throws InvalidArgumentException
     * @throws ProposalException
     */

    public Collection<LifecycleQueryInstalledChaincodesProposalResponse> sendLifecycleQueryInstalledChaincodes(LifecycleQueryInstalledChaincodesRequest lifecycleQueryInstalledChaincodesRequest,
                                                                                                               Collection<Peer> peers) throws InvalidArgumentException, ProposalException {

        if (null == lifecycleQueryInstalledChaincodesRequest) {
            throw new InvalidArgumentException("The lifecycleQueryInstalledChaincodesRequest parameter can not be null.");
        }

        clientCheck();

        if (null == peers) {

            throw new InvalidArgumentException("The peers set to null");

        }

        if (peers.isEmpty()) {
            throw new InvalidArgumentException("The peers parameter is empty.");
        }

        try {
            //Run this on a system channel.
            Channel systemChannel = Channel.newSystemChannel(this);
            return systemChannel.lifecycleQueryInstalledChaincodes(lifecycleQueryInstalledChaincodesRequest, peers);
        } catch (ProposalException e) {
            logger.error(e);
            throw e;
        }

    }

    /**
     * newInstantiationProposalRequest get new instantiation proposal request.
     *
     * @return see {@link InstantiateProposalRequest}
     * @deprecated See {@link LifecycleCommitChaincodeDefinitionRequest } for defining the chaincode and
     * and then {@link TransactionProposalRequest#setInit(boolean)} to do the initialization if it's required by the chaincode.
     */
    @Deprecated
    public InstantiateProposalRequest newInstantiationProposalRequest() {
        return new InstantiateProposalRequest(userContext);
    }

    /**
     * @return {@link UpgradeProposalRequest}
     * @deprecated See {@link LifecycleCommitChaincodeDefinitionRequest } for defining the chaincode and
     * and then {@link TransactionProposalRequest#setInit(boolean)} to do the initialization if it's required by the chaincode.     */
    @Deprecated
    public UpgradeProposalRequest newUpgradeProposalRequest() {
        return new UpgradeProposalRequest(userContext);
    }

    /**
     * newTransactionProposalRequest  get new transaction proposal request.
     *
     * @return TransactionProposalRequest
     */

    public TransactionProposalRequest newTransactionProposalRequest() {
        return TransactionProposalRequest.newInstance(userContext);
    }

    /**
     * newQueryProposalRequest get new query proposal request.
     *
     * @return QueryByChaincodeRequest
     */

    public QueryByChaincodeRequest newQueryProposalRequest() {
        return QueryByChaincodeRequest.newInstance(userContext);
    }

    /**
     * Set the User context for this client.
     *
     * @param userContext
     * @return the old user context. Maybe null if never set!
     * @throws IllegalStateException if no crypto suite has been set.
     * @throws NullPointerException if the user context is null.
     * @throws IllegalArgumentException if the user context is not valid.
     */

    public User setUserContext(User userContext) {

        if (null == cryptoSuite) {
            throw new IllegalStateException("No cryptoSuite has been set.");
        }
        userContextCheck(userContext);

        User ret = this.userContext;
        this.userContext = userContext;

        logger.debug(
                format("Setting user context to MSPID: %s user: %s", userContext.getMspId(), userContext.getName()));

        return ret;
    }

    /**
     * Create a new urlOrderer.
     *
     * @param name    name of the orderer.
     * @param grpcURL url location of orderer grpc or grpcs protocol.
     * @return a new Orderer.
     * @throws InvalidArgumentException
     */

    public Orderer newOrderer(String name, String grpcURL) throws InvalidArgumentException {
        clientCheck();
        return newOrderer(name, grpcURL, new Properties());
    }

    /**
     * Create a new orderer.
     *
     * @param name       name of Orderer.
     * @param grpcURL    url location of orderer grpc or grpcs protocol.
     * @param properties <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>pemBytes - byte array for x509 pem certificates for SSL</li>
     *                   <li>trustServerCertificate - boolean(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>clientKeyFile - File location for private key pem for mutual TLS</li>
     *                   <li>clientCertFile - File location for x509 pem certificate for mutual TLS</li>
     *                   <li>clientKeyBytes - Private key pem bytes for mutual TLS</li>
     *                   <li>clientCertBytes - x509 pem certificate bytes for mutual TLS</li>
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
     *                   </li>
     *                   <li>
     *                   org.hyperledger.fabric.sdk.orderer.organization_mspid {@link Orderer#ORDERER_ORGANIZATION_MSPID_PROPERTY} - Associates orderer to an organization by its mspid.
     *                   </li>
     *                   <li>
     *                   grpc.NettyChannelBuilderOption.&lt;methodName&gt;  where methodName is any method on
     *                   grpc ManagedChannelBuilder.  If more than one argument to the method is needed then the
     *                   parameters need to be supplied in an array of Objects.
     *                   </li>
     *                   <li>
     *                   ordererWaitTimeMilliSecs Time to wait in milliseconds for the
     *                   Orderer to accept requests before timing out. The default is two seconds.
     *                   </li>
     *                   </ul>
     * @return The orderer.
     * @throws InvalidArgumentException
     */

    public Orderer newOrderer(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        clientCheck();
        setDefaultProperties(properties);
        return Orderer.createNewInstance(name, grpcURL, properties);
    }

    /**
     * Query the joined channels for peers
     *
     * @param peer the peer to query
     * @return A set of strings with the names of the channels the peer has joined.
     * @throws InvalidArgumentException
     * @throws ProposalException
     */
    public Set<String> queryChannels(Peer peer) throws InvalidArgumentException, ProposalException {

        clientCheck();

        if (null == peer) {

            throw new InvalidArgumentException("peer set to null");

        }

        //Run this on a system channel.

        try {
            Channel systemChannel = Channel.newSystemChannel(this);

            return systemChannel.queryChannels(peer);
        } catch (ProposalException e) {
            logger.error(format("queryChannels for peer %s failed." + e.getMessage(), peer.getName()), e);
            throw e;
        }

    }

    /**
     * Query the peer for installed chaincode information
     *
     * @param peer The peer to query.
     * @return List of ChaincodeInfo on installed chaincode @see {@link ChaincodeInfo}
     * @throws InvalidArgumentException
     * @throws ProposalException
     * @deprecated See {@link LifecycleQueryInstalledChaincodesRequest}
     */
    @Deprecated
    public List<ChaincodeInfo> queryInstalledChaincodes(Peer peer) throws InvalidArgumentException, ProposalException {

        clientCheck();

        if (null == peer) {

            throw new InvalidArgumentException("peer set to null");

        }

        try {
            //Run this on a system channel.

            Channel systemChannel = Channel.newSystemChannel(this);

            return systemChannel.queryInstalledChaincodes(peer);
        } catch (ProposalException e) {
            logger.error(format("queryInstalledChaincodes for peer %s failed." + e.getMessage(), peer.getName()), e);
            throw e;
        }

    }

    /**
     * Get signature for channel configuration
     *
     * @param channelConfiguration
     * @param signer
     * @return byte array with the signature
     * @throws InvalidArgumentException
     */

    public byte[] getChannelConfigurationSignature(ChannelConfiguration channelConfiguration, User signer)
            throws InvalidArgumentException {

        clientCheck();

        Channel systemChannel = Channel.newSystemChannel(this);
        return systemChannel.getChannelConfigurationSignature(channelConfiguration, signer);

    }

    /**
     * Get signature for update channel configuration
     *
     * @param updateChannelConfiguration
     * @param signer
     * @return byte array with the signature
     * @throws InvalidArgumentException
     */

    public byte[] getUpdateChannelConfigurationSignature(UpdateChannelConfiguration updateChannelConfiguration,
                                                         User signer) throws InvalidArgumentException {

        clientCheck();

        Channel systemChannel = Channel.newSystemChannel(this);
        return systemChannel.getUpdateChannelConfigurationSignature(updateChannelConfiguration, signer);

    }

    /**
     * Send install chaincode request proposal to peers.
     *
     * @param installProposalRequest
     * @param peers                  Collection of peers to install on.
     * @return responses from peers.
     * @throws InvalidArgumentException
     * @throws ProposalException
     * @deprecated See {@link LifecycleInstallChaincodeRequest}
     */
    @Deprecated
    public Collection<ProposalResponse> sendInstallProposal(InstallProposalRequest installProposalRequest,
                                                            Collection<Peer> peers) throws ProposalException, InvalidArgumentException {

        clientCheck();

        Channel systemChannel = Channel.newSystemChannel(this);

        return systemChannel.sendInstallProposal(installProposalRequest, peers);

    }

    private void clientCheck() throws InvalidArgumentException {

        if (null == cryptoSuite) {
            throw new InvalidArgumentException("No cryptoSuite has been set.");
        }

        userContextCheck(userContext);

    }

    void removeChannel(Channel channel) {
        synchronized (channels) {
            final String name = channel.getName();
            if (channels.get(name) == channel) { // Only remove if it's the same instance.
                channels.remove(name);
            }
        }
    }

}
