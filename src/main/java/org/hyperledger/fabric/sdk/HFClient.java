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

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.User.userContextCheck;

public class HFClient {

    private CryptoSuite cryptoSuite;

    static {

        if (null == System.getProperty("org.hyperledger.fabric.sdk.logGRPC")) {
            // Turn this off by default!
            Logger.getLogger("io.netty").setLevel(Level.OFF);
            Logger.getLogger("io.grpc").setLevel(Level.OFF);

        }
    }

    private final ExecutorService executorService = Executors.newCachedThreadPool(r -> {
        Thread t = Executors.defaultThreadFactory().newThread(r);
        t.setDaemon(true);
        return t;
    });

    ExecutorService getExecutorService() {
        return executorService;
    }

    private static final Log logger = LogFactory.getLog(HFClient.class);

    private final Map<String, Channel> channels = new HashMap<>();

    public User getUserContext() {
        return userContext;
    }

    private User userContext;

    private HFClient() {

    }

    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
    }

    public void setCryptoSuite(CryptoSuite cryptoSuite) throws CryptoException, InvalidArgumentException {
        if (this.cryptoSuite != null) {
            throw new InvalidArgumentException("CryptoSuite may only be set once.");

        }

        cryptoSuite.init();
        this.cryptoSuite = cryptoSuite;

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
     * newChannel - already configured channel.
     *
     * @param name
     * @return a new channel.
     * @throws InvalidArgumentException
     */

    public Channel newChannel(String name) throws InvalidArgumentException {
        clientCheck();
        logger.trace("Creating channel :" + name);
        Channel newChannel = Channel.createNewInstance(name, this);
        channels.put(name, newChannel);
        return newChannel;
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

    public Channel newChannel(String name, Orderer orderer, ChannelConfiguration channelConfiguration, byte[]... channelConfigurationSignatures) throws TransactionException, InvalidArgumentException {

        clientCheck();
        logger.trace("Creating channel :" + name);
        Channel newChannel = Channel.createNewInstance(name, this, orderer, channelConfiguration, channelConfigurationSignatures);
        channels.put(name, newChannel);
        return newChannel;
    }

    /**
     * newPeer create a new peer
     *
     * @param name
     * @param grpcURL    to the peer's location
     * @param properties <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>trustServerCertificate - boolen(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
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
        return Peer.createNewInstance(name, grpcURL, null);
    }

    /**
     * getChannel by name
     *
     * @param name
     * @return a channel
     */

    public Channel getChannel(String name) {
        return channels.get(name);
    }

    /**
     * newInstallProposalRequest get new Install proposal request.
     *
     * @return InstallProposalRequest
     */
    public InstallProposalRequest newInstallProposalRequest() {
        return new InstallProposalRequest(userContext);
    }

    /**
     * newInstantiationProposalRequest get new instantiation proposal request.
     *
     * @return InstantiateProposalRequest
     */

    public InstantiateProposalRequest newInstantiationProposalRequest() {
        return new InstantiateProposalRequest(userContext);
    }

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
     * @throws InvalidArgumentException
     */

    public void setUserContext(User userContext) throws InvalidArgumentException {

        if (null == cryptoSuite) {
            throw new InvalidArgumentException("No cryptoSuite has been set.");
        }
        userContextCheck(userContext);
        this.userContext = userContext;

        logger.debug(format("Setting user context to MSPID: %s user: %s", userContext.getMspId(), userContext.getName()));

    }

    /**
     * Create a new Eventhub.
     *
     * @param name       name of Orderer.
     * @param grpcURL    url location of orderer grpc or grpcs protocol.
     * @param properties <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>trustServerCertificate - boolean(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
     *                   </li>
     *                   <li>
     *                   grpc.NettyChannelBuilderOption.&lt;methodName&gt;  where methodName is any method on
     *                   grpc ManagedChannelBuilder.  If more than one argument to the method is needed then the
     *                   parameters need to be supplied in an array of Objects.
     *                   </li>
     *                   </ul>
     * @return The orderer.
     * @throws InvalidArgumentException
     */

    public EventHub newEventHub(String name, String grpcURL, Properties properties) throws InvalidArgumentException {
        clientCheck();
        return EventHub.createNewInstance(name, grpcURL, executorService, properties);
    }

    /**
     * Create a new event hub
     *
     * @param name    Name of eventhup should match peer's name it's associated with.
     * @param grpcURL The http url location of the event hub
     * @return event hub
     * @throws InvalidArgumentException
     */

    public EventHub newEventHub(String name, String grpcURL) throws InvalidArgumentException {
        clientCheck();
        return newEventHub(name, grpcURL, null);
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
        return newOrderer(name, grpcURL, null);
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
     *                   <li>trustServerCertificate - boolean(true/false) override CN to match pemFile certificate -- for development only.
     *                   If the pemFile has the target server's certificate (instead of a CA Root certificate),
     *                   instruct the TLS client to trust the CN value of the certificate in the pemFile,
     *                   useful in development to get past default server hostname verification during
     *                   TLS handshake, when the server host name does not match the certificate.
     *                   </li>
     *                   <li>sslProvider - Specify the SSL provider, openSSL or JDK.</li>
     *                   <li>negotiationType - Specify the type of negotiation, TLS or plainText.</li>
     *                   <li>hostnameOverride - Specify the certificates CN -- for development only.
     *                   If the pemFile does not represent the server certificate, use this property to specify the URI authority
     *                   (a.k.a hostname) expected in the target server's certificate. This is required to get past default server
     *                   hostname verifications during TLS handshake.
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
        return Orderer.createNewInstance(name, grpcURL, properties);
    }

    /**
     * Query the channels for peers
     *
     * @param peer the peer to query
     * @return A set of strings with the peer names.
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
        } catch (InvalidArgumentException e) {
            throw e;  //dont log
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
     */

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

    public byte[] getChannelConfigurationSignature(ChannelConfiguration channelConfiguration, User signer) throws InvalidArgumentException {

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

    public byte[] getUpdateChannelConfigurationSignature(UpdateChannelConfiguration updateChannelConfiguration, User signer) throws InvalidArgumentException {

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
     */

    public Collection<ProposalResponse> sendInstallProposal(InstallProposalRequest installProposalRequest, Collection<Peer> peers)
            throws ProposalException, InvalidArgumentException {

        clientCheck();

        installProposalRequest.setSubmitted();
        Channel systemChannel = Channel.newSystemChannel(this);

        return systemChannel.sendInstallProposal(installProposalRequest, peers);

    }

    private void clientCheck() throws InvalidArgumentException {

        if (null == cryptoSuite) {
            throw new InvalidArgumentException("No cryptoSuite has been set.");
        }

        userContextCheck(userContext);

    }

}
