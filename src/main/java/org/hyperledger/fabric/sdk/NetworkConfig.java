/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.hyperledger.fabric.sdk.Channel.PeerOptions;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.NetworkConfigurationException;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;

/**
 * Holds details of network and channel configurations typically loaded from an external config file.
 * <br>
 * Also contains convenience methods for utilizing the config details,
 * including the main {@link HFClient#getChannel(String)} method
 */

public class NetworkConfig {
    public static final String CLIENT_CERT_BYTES = "clientCertBytes";

    public static final String CLIENT_KEY_BYTES = "clientKeyBytes";

    public static final String CLIENT_CERT_FILE = "clientCertFile";

    public static final String CLIENT_KEY_FILE = "clientKeyFile";

    private static final String URL_PROP_NAME = "url";

    private final JsonObject jsonConfig;

    private final OrgInfo clientOrganization;

    private Map<String, Node> orderers;
    private Map<String, Node> peers;

    /**
     * Names of Peers found
     *
     * @return Collection of peer names found.
     */
    public Collection<String> getPeerNames() {
        if (peers == null) {
            return Collections.emptySet();
        } else {
            return new HashSet<>(peers.keySet());
        }
    }

    /**
     * Names of Orderers found
     *
     * @return Collection of peer names found.
     */
    public Collection<String> getOrdererNames() {
        if (orderers == null) {
            return Collections.emptySet();
        } else {
            return new HashSet<>(orderers.keySet());
        }
    }

    private Properties getNodeProperties(String type, String name, Map<String, Node> nodes) {
        if (isNullOrEmpty(name)) {
            throw new IllegalArgumentException("Parameter name is null or empty.");
        }

        Node node = nodes.get(name);
        if (node == null) {
            throw new IllegalArgumentException(format("%s %s not found.", type, name));
        }

        if (null == node.properties) {
            return new Properties();
        } else {

            return (Properties) node.properties.clone();
        }

    }

    private void setNodeProperties(String type, String name, Map<String, Node> nodes, Properties properties) {
        if (isNullOrEmpty(name)) {
            throw new IllegalArgumentException("Parameter name is null or empty.");
        }
        if (properties == null) {
            throw new IllegalArgumentException("Parameter properties is null.");
        }

        Node node = nodes.get(name);
        if (node == null) {
            throw new IllegalArgumentException(format("%S %s not found.", type, name));
        }

        Properties ourCopyProps = new Properties();
        ourCopyProps.putAll(properties);

        node.properties = ourCopyProps;

    }

    /**
     * Get properties for a specific peer.
     *
     * @param name Name of peer to get the properties for.
     * @return The peer's properties.
     */
    public Properties getPeerProperties(String name) {
        return getNodeProperties("Peer", name, peers);

    }

    /**
     * Get properties for a specific Orderer.
     *
     * @param name Name of orderer to get the properties for.
     * @return The orderer's properties.
     */
    public Properties getOrdererProperties(String name) {
        return getNodeProperties("Orderer", name, orderers);

    }

    /**
     * Set a specific peer's properties.
     *
     * @param name       The name of the peer's property to set.
     * @param properties The properties to set.
     */
    public void setPeerProperties(String name, Properties properties) {
        setNodeProperties("Peer", name, peers, properties);
    }

    /**
     * Set a specific orderer's properties.
     *
     * @param name       The name of the orderer's property to set.
     * @param properties The properties to set.
     */
    public void setOrdererProperties(String name, Properties properties) {
        setNodeProperties("Orderer", name, orderers, properties);
    }

    private String getNodeUrl(String type, String name, Map<String, Node> nodes) {
        if (isNullOrEmpty(name)) {
            throw new IllegalArgumentException("Parameter name is null or empty.");
        }

        Node node = nodes.get(name);
        if (node == null) {
            throw new IllegalStateException(format("%s %s not found.", type, name));
        }

        return node.getUrl();
    }

    /**
     * Get URL for a specific peer.
     *
     * @param name Name of peer to get the URL for.
     * @return The peer's URL.
     */
    public String getPeerUrl(String name) {
        return getNodeUrl("Peer", name, peers);
    }

    // Organizations, keyed on org name (and not on mspid!)
    private Map<String, OrgInfo> organizations;

    private static final Log logger = LogFactory.getLog(NetworkConfig.class);

    private NetworkConfig(JsonObject jsonConfig) throws NetworkConfigurationException {

        this.jsonConfig = jsonConfig;

        // Extract the main details
        String configName = getJsonValueAsString(jsonConfig.get("name"));
        if (configName == null || configName.isEmpty()) {
            throw new NetworkConfigurationException("Network config must have a name");
        }

        String configVersion = getJsonValueAsString(jsonConfig.get("version"));
        if (configVersion == null || configVersion.isEmpty()) {
            throw new NetworkConfigurationException("Network config must have a version");
            // TODO: Validate the version
        }

        // Preload and create all peers, orderers, etc
        createAllPeers();
        createAllOrderers();

        Map<String, JsonObject> foundCertificateAuthorities = findCertificateAuthorities();
        //createAllCertificateAuthorities();
        createAllOrganizations(foundCertificateAuthorities);

        // Validate the organization for this client
        JsonObject jsonClient = getJsonObject(jsonConfig, "client");
        String orgName = jsonClient == null ? null : getJsonValueAsString(jsonClient.get("organization"));
        if (orgName == null || orgName.isEmpty()) {
            throw new NetworkConfigurationException("A client organization must be specified");
        }

        clientOrganization = getOrganizationInfo(orgName);
        if (clientOrganization == null) {
            throw new NetworkConfigurationException("Client organization " + orgName + " is not defined");
        }

    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in a YAML file.
     *
     * @param configFile The file containing the network configuration
     * @return A new NetworkConfig instance
     * @throws IOException if an error occurs reading the file
     * @throws NetworkConfigurationException if the configuration is invalid
     */
    public static NetworkConfig fromYamlFile(File configFile) throws IOException, NetworkConfigurationException {
        return fromFile(configFile, false);
    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in a JSON file.
     *
     * @param configFile The file containing the network configuration
     * @return A new NetworkConfig instance
     * @throws IOException if an error occurs reading the file
     * @throws NetworkConfigurationException if the configuration is invalid
     */
    public static NetworkConfig fromJsonFile(File configFile) throws IOException, NetworkConfigurationException {
        return fromFile(configFile, true);
    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in YAML format
     *
     * @param configStream A stream opened on a YAML document containing network configuration details
     * @return A new NetworkConfig instance
     * @throws NetworkConfigurationException if the configuration is invalid
     */
    public static NetworkConfig fromYamlStream(InputStream configStream) throws NetworkConfigurationException {

        logger.trace("NetworkConfig.fromYamlStream...");

        // Sanity check
        if (configStream == null) {
            throw new IllegalArgumentException("configStream must be specified");
        }

        Yaml yaml = new Yaml(new SafeConstructor());

        Map<String, Object> map = yaml.load(configStream);

        JsonObjectBuilder builder = Json.createObjectBuilder(map);

        JsonObject jsonConfig = builder.build();
        return fromJsonObject(jsonConfig);
    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in JSON format
     *
     * @param configStream A stream opened on a JSON document containing network configuration details
     * @return A new NetworkConfig instance
     * @throws NetworkConfigurationException if the configuration is invalid
     */
    public static NetworkConfig fromJsonStream(InputStream configStream) throws NetworkConfigurationException {

        logger.trace("NetworkConfig.fromJsonStream...");

        // Sanity check
        if (configStream == null) {
            throw new IllegalArgumentException("configStream must be specified");
        }

        // Read the input stream and convert to JSON

        try (JsonReader reader = Json.createReader(configStream)) {
            JsonObject jsonConfig = (JsonObject) reader.read();
            return fromJsonObject(jsonConfig);
        }

    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in a JSON object
     *
     * @param jsonConfig JSON object containing network configuration details
     * @return A new NetworkConfig instance
     * @throws NetworkConfigurationException if the configuration is invalid
     */
    public static NetworkConfig fromJsonObject(JsonObject jsonConfig) throws NetworkConfigurationException {

        // Sanity check
        if (jsonConfig == null) {
            throw new IllegalArgumentException("jsonConfig must be specified");
        }

        if (logger.isTraceEnabled()) {
            logger.trace(format("NetworkConfig.fromJsonObject: %s", jsonConfig.toString()));
        }

        return NetworkConfig.load(jsonConfig);
    }

    // Loads a NetworkConfig object from a Json or Yaml file
    private static NetworkConfig fromFile(File configFile, boolean isJson) throws IOException, NetworkConfigurationException {

        // Sanity check
        if (configFile == null) {
            throw new IllegalArgumentException("configFile must be specified");
        }

        if (logger.isTraceEnabled()) {
            logger.trace(format("NetworkConfig.fromFile: %s  isJson = %b", configFile.getAbsolutePath(), isJson));
        }

        // Json file
        try (InputStream stream = new FileInputStream(configFile)) {
            return isJson ? fromJsonStream(stream) : fromYamlStream(stream);
        }
    }

    /**
     * Returns a new NetworkConfig instance and populates it from the specified JSON object
     *
     * @param jsonConfig The JSON object containing the config details
     * @return A populated NetworkConfig instance
     */
    private static NetworkConfig load(JsonObject jsonConfig) throws NetworkConfigurationException {

        // Sanity check
        if (jsonConfig == null) {
            throw new IllegalArgumentException("config must be specified");
        }

        return new NetworkConfig(jsonConfig);
    }

    public OrgInfo getClientOrganization() {
        return clientOrganization;
    }

    public OrgInfo getOrganizationInfo(String orgName) {
        return organizations.get(orgName);
    }

    /**
     * Find organizations for a peer.
     *
     * @param peerName name of peer
     * @return returns map of orgName to {@link OrgInfo} that the peer belongs to.
     */
    public Map<String, OrgInfo> getPeerOrgInfos(final String peerName) {
        if (Utils.isNullOrEmpty(peerName)) {
            throw new IllegalArgumentException("peerName can not be null or empty.");
        }

        if (organizations == null || organizations.isEmpty()) {
            return new HashMap<>();
        }

        Map<String, OrgInfo> ret = new HashMap<>(16);
        organizations.forEach((name, orgInfo) -> {

            if (orgInfo.getPeerNames().contains(peerName)) {
                ret.put(name, orgInfo);
            }
        });

        return ret;
    }

    /**
     * Returns the admin user associated with the client organization
     *
     * @return The admin user details
     * @throws NetworkConfigurationException if the configuration is invalid
     */
    public UserInfo getPeerAdmin() throws NetworkConfigurationException {
        // Get the details from the client organization
        return getPeerAdmin(clientOrganization.getName());
    }

    /**
     * Returns the admin user associated with the specified organization
     *
     * @param orgName The name of the organization
     * @return The admin user details
     * @throws NetworkConfigurationException if the configuration is invalid
     */
    public UserInfo getPeerAdmin(String orgName) throws NetworkConfigurationException {

        OrgInfo org = getOrganizationInfo(orgName);
        if (org == null) {
            throw new NetworkConfigurationException(format("Organization %s is not defined", orgName));
        }

        return org.getPeerAdmin();
    }

    /**
     * Returns a channel configured using the details in the Network Configuration file
     *
     * @param client      The associated client
     * @param channelName The name of the channel
     * @return A configured Channel instance
     */
    Channel loadChannel(HFClient client, String channelName) throws NetworkConfigurationException, InvalidArgumentException {
        return loadChannel(client, channelName, networkConfigAddPeerHandlerDefault, networkConfigAddOrdererHandlerDefault);
    }

    /**
     * Returns a channel configured using the details in the Network Configuration file
     *
     * @param client      The associated client
     * @param channelName The name of the channel
     * @return A configured Channel instance
     */
    Channel loadChannel(HFClient client,
                        String channelName,
                        NetworkConfigAddPeerHandler networkConfigAddPeerHandler,
                        NetworkConfigAddOrdererHandler networkConfigAddOrdererHandler)
            throws NetworkConfigurationException, InvalidArgumentException {

        if (logger.isTraceEnabled()) {
            logger.trace(format("NetworkConfig.loadChannel: %s", channelName));
        }

        JsonObject channels = getJsonObject(jsonConfig, "channels");
        if (null == channels) {
            throw new NetworkConfigurationException("Channel configuration has no channels defined.");
        }

        JsonObject jsonChannel = getJsonObject(channels, channelName);
        if (null == jsonChannel) {
            final Set<String> channelNames = getChannelNames();
            if (channelNames.isEmpty()) {
                throw new NetworkConfigurationException("Channel configuration has no channels defined.");
            }
            throw new NetworkConfigurationException(format("Channel %s not found in configuration file. Found channel names: %s ",
                    channelName, String.join(", ", channelNames)));
        }

        Channel channel = client.getChannel(channelName);
        if (channel != null) {
            // The channel already exists in the client!
            // Note that by rights this should never happen as HFClient.loadChannelFromConfig should have already checked for this!
            throw new NetworkConfigurationException(format("Channel %s is already configured in the client!", channelName));
        }

        return reconstructChannel(client, channelName, jsonChannel, networkConfigAddPeerHandler, networkConfigAddOrdererHandler);
    }

    // Creates Node instances representing all the orderers defined in the config file
    private void createAllOrderers() throws NetworkConfigurationException {

        // Sanity check
        if (orderers != null) {
            throw new NetworkConfigurationException("INTERNAL ERROR: orderers have already been initialized!");
        }

        orderers = new HashMap<>();

        // orderers is a JSON object containing a nested object for each orderers
        JsonObject jsonOrderers = getJsonObject(jsonConfig, "orderers");

        if (jsonOrderers != null) {

            for (Entry<String, JsonValue> entry : jsonOrderers.entrySet()) {
                String ordererName = entry.getKey();

                JsonObject jsonOrderer = getJsonValueAsObject(entry.getValue());
                if (jsonOrderer == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid orderer entry: %s", ordererName));
                }

                Node orderer = createNode(jsonOrderer);
                if (orderer == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid orderer entry: %s", ordererName));
                }
                orderers.put(ordererName, orderer);
            }
        }

    }

    // Creates Node instances representing all the peers  defined in the config file
    private void createAllPeers() throws NetworkConfigurationException {

        // Sanity checks
        if (peers != null) {
            throw new NetworkConfigurationException("INTERNAL ERROR: peers have already been initialized!");
        }

        peers = new HashMap<>();

        // peers is a JSON object containing a nested object for each peer
        JsonObject jsonPeers = getJsonObject(jsonConfig, "peers");

        //out("Peers: " + (jsonPeers == null ? "null" : jsonPeers.toString()));
        if (jsonPeers != null) {

            for (Entry<String, JsonValue> entry : jsonPeers.entrySet()) {
                String peerName = entry.getKey();

                JsonObject jsonPeer = getJsonValueAsObject(entry.getValue());
                if (jsonPeer == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid peer entry: %s", peerName));
                }

                Node peer = createNode(jsonPeer);
                if (peer == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid peer entry: %s", peerName));
                }
                peers.put(peerName, peer);

            }
        }

    }

    // Produce a map from tag to jsonobject for the CA
    private Map<String, JsonObject> findCertificateAuthorities() throws NetworkConfigurationException {
        Map<String, JsonObject> ret = new HashMap<>();

        JsonObject jsonCertificateAuthorities = getJsonObject(jsonConfig, "certificateAuthorities");
        if (null != jsonCertificateAuthorities) {

            for (Entry<String, JsonValue> entry : jsonCertificateAuthorities.entrySet()) {
                String name = entry.getKey();

                JsonObject jsonCA = getJsonValueAsObject(entry.getValue());
                if (jsonCA == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid CA entry: %s", name));
                }
                ret.put(name, jsonCA);
            }
        }

        return ret;

    }

    // Creates JsonObjects representing all the Organizations defined in the config file
    private void createAllOrganizations(Map<String, JsonObject> foundCertificateAuthorities) throws NetworkConfigurationException {

        // Sanity check
        if (organizations != null) {
            throw new NetworkConfigurationException("INTERNAL ERROR: organizations have already been initialized!");
        }

        organizations = new HashMap<>();

        // organizations is a JSON object containing a nested object for each Org
        JsonObject jsonOrganizations = getJsonObject(jsonConfig, "organizations");

        if (jsonOrganizations != null) {

            for (Entry<String, JsonValue> entry : jsonOrganizations.entrySet()) {
                String orgName = entry.getKey();

                JsonObject jsonOrg = getJsonValueAsObject(entry.getValue());
                if (jsonOrg == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid Organization entry: %s", orgName));
                }

                OrgInfo org = createOrg(orgName, jsonOrg, foundCertificateAuthorities);
                organizations.put(orgName, org);
            }
        }

    }

    // Reconstructs an existing channel
    private Channel reconstructChannel(HFClient client,
                                       String channelName,
                                       JsonObject jsonChannel,
                                       NetworkConfigAddPeerHandler networkConfigAddPeerHandler,
                                       NetworkConfigAddOrdererHandler networkConfigAddOrdererHandler)
            throws NetworkConfigurationException, InvalidArgumentException {

        Channel channel = client.newChannel(channelName);

        // orderers is an array of orderer name strings
        JsonArray ordererNames = getJsonValueAsArray(jsonChannel.get("orderers"));

        //out("Orderer names: " + (ordererNames == null ? "null" : ordererNames.toString()));
        if (ordererNames != null) {
            for (JsonValue jsonVal : ordererNames) {

                String ordererName = getJsonValueAsString(jsonVal);

                // Orderer orderer = getOrderer(client, ordererName);
                Node node = orderers.get(ordererName);
                if (null == node) {
                    throw new NetworkConfigurationException(format("Error constructing channel %s. Orderer %s not defined in configuration", channelName, ordererName));
                }

                logger.debug(format("Channel %s, adding orderer %s, url: %s", channel.getName(), ordererName, node.url));
                Properties nodeProps = node.properties;
                if (null != nodeProps) {
                    nodeProps = (Properties) nodeProps.clone();
                }

                networkConfigAddOrdererHandler.addOrderer(this, client, channel, ordererName, node.url, nodeProps, node.jsonObject);
            }
        }

        // peers is an object containing a nested object for each peer
        JsonObject jsonPeers = getJsonObject(jsonChannel, "peers");
        boolean foundPeer = false;

        //out("Peers: " + (peers == null ? "null" : peers.toString()));
        if (jsonPeers != null) {

            for (Entry<String, JsonValue> entry : jsonPeers.entrySet()) {
                String peerName = entry.getKey();

                if (logger.isTraceEnabled()) {
                    logger.trace(format("NetworkConfig.reconstructChannel: Processing peer %s", peerName));
                }

                JsonObject jsonPeer = getJsonValueAsObject(entry.getValue());
                if (jsonPeer == null) {
                    throw new NetworkConfigurationException(format("Error constructing channel %s. Invalid peer entry: %s", channelName, peerName));
                }

                Node node = peers.get(peerName);
                if (node == null) {
                    throw new NetworkConfigurationException(format("Error constructing channel %s. Peer %s not defined in configuration", channelName, peerName));
                }

                // Set the various roles
                PeerOptions peerOptions = PeerOptions.createPeerOptions();

                for (PeerRole peerRole : PeerRole.values()) {
                    setPeerRole(channelName, peerOptions, jsonPeer, peerRole);
                }

                logger.debug(format("Channel %s, adding peer %s, url: %s", channel.getName(), peerName, node.url));

                Properties nodeProps = node.properties;
                if (null != nodeProps) {
                    nodeProps = (Properties) nodeProps.clone();
                }
                networkConfigAddPeerHandler.addPeer(this, client, channel, peerName, node.url, nodeProps, peerOptions, node.jsonObject);

                foundPeer = true;

            }

        }

        if (!foundPeer) {
            // peers is a required field
            throw new NetworkConfigurationException(format("Error constructing channel %s. At least one peer must be specified", channelName));
        }

        return channel;
    }

    /**
     * Interface defining handler for adding peers.
     */

    public interface NetworkConfigAddPeerHandler {

        /**
         * @param networkConfig  The network configuration.
         * @param client         The client to be used to create the peer.
         * @param channel        The channel the peer is to be added.
         * @param peerName       The peer's name.
         * @param peerURL        The peers's url
         * @param peerProperties properties that were found in the networkconfig
         * @param peerOptions    options when adding peer to the channel.
         * @param jsonPeer       json peer was created
         * @throws NetworkConfigurationException if the configuration cannot be parsed
         */
        void addPeer(NetworkConfig networkConfig, HFClient client, Channel channel, String peerName, String peerURL, Properties peerProperties, PeerOptions peerOptions, JsonObject jsonPeer) throws NetworkConfigurationException;
    }

    private static final NetworkConfigAddPeerHandler networkConfigAddPeerHandlerDefault = (networkConfig, client, channel, peerName, peerURL, peerProperties, peerOptions, jsonPeer) -> {
        try {
            Peer peer = client.newPeer(peerName, peerURL, peerProperties);
            channel.addPeer(peer, peerOptions);
        } catch (Exception e) {
            throw new NetworkConfigurationException(format("Error on creating channel %s peer %s", channel.getName(), peerName), e);
        }
    };

    /**
     * Interface defining handler for adding orderers.
     */
    public interface NetworkConfigAddOrdererHandler {

        /**
         * @param networkConfig     The network configuration.
         * @param client            The client to be used to create the orderer.
         * @param channel           The channel the orderer is to be added.
         * @param ordererName       The orderer's name.
         * @param ordererURL        The orderers's url
         * @param ordererProperties properties that were found in the networkconfig
         * @param jsonOrderer       json orderer was created
         * @throws NetworkConfigurationException if the configuration cannot be parsed
         */
        void addOrderer(NetworkConfig networkConfig, HFClient client, Channel channel, String ordererName, String ordererURL, Properties ordererProperties, JsonObject jsonOrderer) throws NetworkConfigurationException;
    }

    private static final NetworkConfigAddOrdererHandler networkConfigAddOrdererHandlerDefault = (networkConfig, client, channel, ordererName, ordererURL, ordererProperties, jsonOrderer) -> {
        try {
            Orderer orderer = client.newOrderer(ordererName, ordererURL, ordererProperties);
            channel.addOrderer(orderer);
        } catch (Exception e) {
            throw new NetworkConfigurationException(format("Error on creating channel %s orderer %s", channel.getName(), ordererName), e);
        }
    };

    private static void setPeerRole(String channelName, PeerOptions peerOptions, JsonObject jsonPeer, PeerRole role) throws NetworkConfigurationException {
        String propName = roleNameRemap(role);
        JsonValue val = jsonPeer.get(propName);
        if (val != null) {
            Boolean isSet = getJsonValueAsBoolean(val);
            if (isSet == null) {
                // This is an invalid boolean value
                throw new NetworkConfigurationException(format("Error constructing channel %s. Role %s has invalid boolean value: %s", channelName, propName, val.toString()));
            }
            if (isSet) {
                peerOptions.addPeerRole(role);
            }
        }
    }

    private static final Map<PeerRole, String> roleNameRemapHash = new HashMap<>();
    static {
        roleNameRemapHash.put(PeerRole.SERVICE_DISCOVERY, "discover");
    }

    private static String roleNameRemap(PeerRole peerRole) {
        String remap = roleNameRemapHash.get(peerRole);
        return remap == null ? peerRole.getPropertyName() : remap;
    }

    // Creates a new Node instance from a JSON object
    private Node createNode(JsonObject jsonNode) {
        String url = jsonNode.getString(URL_PROP_NAME, null);
        if (url == null) {
            return null;
        }

        Properties props = extractProperties(jsonNode, "grpcOptions");

        String value = props.getProperty("grpc.keepalive_time_ms");
        if (null != value) {
            props.remove("grpc.keepalive_time_ms");
            props.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {Long.parseLong(value), TimeUnit.MILLISECONDS});
        }

        value = props.getProperty("grpc.keepalive_timeout_ms");
        if (null != value) {
            props.remove("grpc.keepalive_timeout_ms");
            props.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {Long.parseLong(value), TimeUnit.MILLISECONDS});
        }

        value = props.getProperty("grpc.keepalive_without_calls");
        if (null != value) {
            props.remove("grpc.keepalive_without_calls");
            props.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[] {Boolean.valueOf(value)});
        }

        // Extract the pem details
        getTLSCerts(jsonNode, props);

        return new Node(url, props, jsonNode);
    }

    private void getTLSCerts(JsonObject jsonOrderer, Properties props) {
        JsonObject jsonTlsCaCerts = getJsonObject(jsonOrderer, "tlsCACerts");
        if (jsonTlsCaCerts != null) {
            String pemFilename = getJsonValueAsString(jsonTlsCaCerts.get("path"));
            if (pemFilename != null) {
                // let the sdk handle non existing errors could be they don't exist during parsing but are there later.
                props.put("pemFile", pemFilename);
            }

            byte[] pemBytes = getJsonValueAsList(jsonTlsCaCerts.get("pem"), NetworkConfig::getJsonValueAsString).stream()
                    .collect(Collectors.joining("\n"))
                    .getBytes();
            props.put("pemBytes", pemBytes);

            JsonObject jsonTlsClientCerts = getJsonObject(jsonTlsCaCerts, "client");

            if (jsonTlsClientCerts != null) {

                String keyfile = getJsonValueAsString(jsonTlsClientCerts.get("keyfile"));
                String certfile = getJsonValueAsString(jsonTlsClientCerts.get("certfile"));

                if (keyfile != null) {
                    props.put(CLIENT_KEY_FILE, keyfile);
                }

                if (certfile != null) {
                    props.put(CLIENT_CERT_FILE, certfile);
                }

                String keyBytes = getJsonValueAsString(jsonTlsClientCerts.get("keyPem"));
                String certBytes = getJsonValueAsString(jsonTlsClientCerts.get("certPem"));

                if (keyBytes != null) {
                    props.put(CLIENT_KEY_BYTES, keyBytes.getBytes());
                }

                if (certBytes != null) {
                    props.put(CLIENT_CERT_BYTES, certBytes.getBytes());
                }
            }
        }
    }

    // Creates a new OrgInfo instance from a JSON object
    private OrgInfo createOrg(String orgName, JsonObject jsonOrg, Map<String, JsonObject> foundCertificateAuthorities) throws NetworkConfigurationException {

        String msgPrefix = format("Organization %s", orgName);

        String mspId = getJsonValueAsString(jsonOrg.get("mspid"));

        OrgInfo org = new OrgInfo(orgName, mspId);

        // Peers
        JsonArray jsonPeers = getJsonValueAsArray(jsonOrg.get("peers"));
        if (jsonPeers != null) {
            for (JsonValue peer : jsonPeers) {
                final String peerName = getJsonValueAsString(peer);
                if (peerName != null) {
                    org.addPeerName(peerName);
                    final Node node = peers.get(peerName);
                    if (null != node) {
                        if (null == node.properties) {
                            node.properties = new Properties();
                        }
                        node.properties.put(Peer.PEER_ORGANIZATION_MSPID_PROPERTY, org.getMspId());

                    } else {
                        throw new NetworkConfigurationException(format("Organization %s has peer %s listed not found in any channel peer list.", orgName, peerName));
                    }
                }
            }
        }

        // CAs
        JsonArray jsonCertificateAuthorities = getJsonValueAsArray(jsonOrg.get("certificateAuthorities"));
        if (jsonCertificateAuthorities != null) {
            for (JsonValue jsonCA : jsonCertificateAuthorities) {

                String caName = getJsonValueAsString(jsonCA);

                if (caName != null) {
                    JsonObject jsonObject = foundCertificateAuthorities.get(caName);
                    if (jsonObject != null) {
                        org.addCertificateAuthority(createCA(caName, jsonObject, org));
                    } else {
                        throw new NetworkConfigurationException(format("%s: Certificate Authority %s is not defined", msgPrefix, caName));
                    }
                }
            }
        }

        String adminPrivateKeyString = extractPemString(jsonOrg, "adminPrivateKey", msgPrefix);
        String signedCert = extractPemString(jsonOrg, "signedCert", msgPrefix);

        if (!isNullOrEmpty(adminPrivateKeyString) && !isNullOrEmpty(signedCert)) {
            final PrivateKey privateKey;
            try {
                privateKey = getPrivateKeyFromString(adminPrivateKeyString);
            } catch (IOException ioe) {
                throw new NetworkConfigurationException(format("%s: Invalid private key", msgPrefix), ioe);
            }

            try {
                org.peerAdmin = new UserInfo(mspId, "PeerAdmin_" + mspId + "_" + orgName, null);
            } catch (Exception e) {
                throw new NetworkConfigurationException(e.getMessage(), e);
            }

            org.peerAdmin.setEnrollment(new X509Enrollment(privateKey, signedCert));
        }

        return org;
    }

    private static PrivateKey getPrivateKeyFromString(String data)
            throws IOException {

        final Reader pemReader = new StringReader(data);

        final PrivateKeyInfo pemPair;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            pemPair = (PrivateKeyInfo) pemParser.readObject();
        }

        return new JcaPEMKeyConverter().getPrivateKey(pemPair);
    }

    // Returns the PEM (as a String) from either a path or a pem field
    private static String extractPemString(JsonObject json, String fieldName, String msgPrefix) throws NetworkConfigurationException {

        String path = null;
        String pemString = null;

        JsonObject jsonField = getJsonValueAsObject(json.get(fieldName));
        if (jsonField != null) {
            path = getJsonValueAsString(jsonField.get("path"));
            pemString = getJsonValueAsString(jsonField.get("pem"));
        }

        if (path != null && pemString != null) {
            throw new NetworkConfigurationException(format("%s should not specify both %s path and pem", msgPrefix, fieldName));
        }

        if (path != null) {
            // Determine full pathname and ensure the file exists
            File pemFile = new File(path);
            String fullPathname = pemFile.getAbsolutePath();
            if (!pemFile.exists()) {
                throw new NetworkConfigurationException(format("%s: %s file %s does not exist", msgPrefix, fieldName, fullPathname));
            }
            try (FileInputStream stream = new FileInputStream(pemFile)) {
                pemString = IOUtils.toString(stream, StandardCharsets.UTF_8);
            } catch (IOException ioe) {
                throw new NetworkConfigurationException(format("Failed to read file: %s", fullPathname), ioe);
            }

        }

        return pemString;
    }

    // Creates a new CAInfo instance from a JSON object
    private CAInfo createCA(String name, JsonObject jsonCA, OrgInfo org) throws NetworkConfigurationException {

        String url = getJsonValueAsString(jsonCA.get("url"));
        Properties httpOptions = extractProperties(jsonCA, "httpOptions");

        List<UserInfo> regUsers = new ArrayList<>();
        List<JsonObject> registrars = getJsonValueAsList(jsonCA.get("registrar"), NetworkConfig::getJsonValueAsObject);
        for (JsonObject registrar : registrars) {
            String enrollId = getJsonValueAsString(registrar.get("enrollId"));
            String enrollSecret = getJsonValueAsString(registrar.get("enrollSecret"));
            try {
                regUsers.add(new UserInfo(org.mspId, enrollId, enrollSecret));
            } catch (Exception e) {
                throw new NetworkConfigurationException(e.getMessage(), e);
            }
        }

        CAInfo caInfo = new CAInfo(name, url, regUsers, httpOptions);

        String caName = getJsonValueAsString(jsonCA.get("caName"));
        if (caName != null) {
            caInfo.setCaName(caName);
        }

        Properties properties = new Properties();
        if ("false".equals(httpOptions.getProperty("verify"))) {
            properties.setProperty("allowAllHostNames", "true");
        }
        getTLSCerts(jsonCA, properties);
        caInfo.setProperties(properties);

        return caInfo;
    }

    // Extracts all defined properties of the specified field and returns a Properties object
    private static Properties extractProperties(JsonObject json, String fieldName) {
        Properties props = new Properties();

        // Extract any other grpc options
        JsonObject options = getJsonObject(json, fieldName);
        if (options != null) {

            for (Entry<String, JsonValue> entry : options.entrySet()) {
                String key = entry.getKey();
                JsonValue value = entry.getValue();
                props.setProperty(key, getJsonValue(value));
            }
        }
        return props;
    }

    // Returns the specified JsonValue in a suitable format
    // If it's a JsonString - it returns the string
    // If it's a number = it returns the string representation of that number
    // If it's TRUE or FALSE - it returns "true" and "false" respectively
    // If it's anything else it returns null
    private static String getJsonValue(JsonValue value) {
        String s = null;
        if (value != null) {
            s = getJsonValueAsString(value);
            if (s == null) {
                s = getJsonValueAsNumberString(value);
            }
            if (s == null) {
                Boolean b = getJsonValueAsBoolean(value);
                if (b != null) {
                    s = b ? "true" : "false";
                }
            }
        }
        return s;
    }

    // Returns the specified JsonValue as a JsonObject, or null if it's not an object
    private static JsonObject getJsonValueAsObject(JsonValue value) {
        return (value != null && value.getValueType() == ValueType.OBJECT) ? value.asJsonObject() : null;
    }

    // Returns the specified JsonValue as a JsonArray, or null if it's not an array
    private static JsonArray getJsonValueAsArray(JsonValue value) {
        return (value != null && value.getValueType() == ValueType.ARRAY) ? value.asJsonArray() : null;
    }

    private static <T> List<T> getJsonValueAsList(final JsonValue value, Function<JsonValue, T> map) {
        return getJsonValueAsList(value).stream()
                .map(map)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    // Returns the specified JsonValue as a List. Allows single or array
    private static List<JsonValue> getJsonValueAsList(final JsonValue value) {
        if (value == null) {
            return Collections.emptyList();
        }
        if (value.getValueType() == ValueType.ARRAY) {
            return value.asJsonArray();
        }
        return Collections.singletonList(value);
    }

    // Returns the specified JsonValue as a String, or null if it's not a string
    private static String getJsonValueAsString(JsonValue value) {
        return (value != null && value.getValueType() == ValueType.STRING) ? ((JsonString) value).getString() : null;
    }

    // Returns the specified JsonValue as a String, or null if it's not a string
    private static String getJsonValueAsNumberString(JsonValue value) {
        return (value != null && value.getValueType() == ValueType.NUMBER) ? value.toString() : null;
    }

    // Returns the specified JsonValue as a Boolean, or null if it's not a boolean
    private static Boolean getJsonValueAsBoolean(JsonValue value) {
        if (value != null) {
            if (value.getValueType() == ValueType.TRUE) {
                return true;
            } else if (value.getValueType() == ValueType.FALSE) {
                return false;
            }
        }
        return null;
    }

    // Returns the specified property as a JsonObject
    private static JsonObject getJsonObject(JsonObject object, String propName) {
        JsonObject obj = null;
        JsonValue val = object.get(propName);
        if (val != null && val.getValueType() == ValueType.OBJECT) {
            obj = val.asJsonObject();
        }
        return obj;
    }

    /**
     * Get the channel names found.
     *
     * @return A set of the channel names found in the configuration file or empty set if none found.
     */

    public Set<String> getChannelNames() {
        Set<String> result = new HashSet<>();

        JsonObject channels = getJsonObject(jsonConfig, "channels");
        if (channels != null) {
            result.addAll(channels.keySet());
        }

        return result;
    }

    // Holds a network "node" (eg. Peer, Orderer)
    private static class Node {

        private final String url;
        public final JsonObject jsonObject;
        private Properties properties;

        private Node(String url, Properties properties, JsonObject jsonObject) {
            this.url = url;
            this.properties = properties;
            this.jsonObject = jsonObject;
        }

        private String getUrl() {
            return url;
        }
    }

    /**
     * Holds details of a User
     */
    public static class UserInfo implements User {

        public void setName(String name) {
            this.name = name;
        }

        protected String name;
        protected String enrollSecret;
        protected String mspid;
        private Set<String> roles;
        private String account;
        private String affiliation;
        private Enrollment enrollment;

        public void setEnrollSecret(String enrollSecret) {
            this.enrollSecret = enrollSecret;
        }

        public String getMspid() {
            return mspid;
        }

        public void setMspid(String mspid) {
            this.mspid = mspid;
        }

        public void setRoles(Set<String> roles) {
            this.roles = roles;
        }

        public void setAccount(String account) {
            this.account = account;
        }

        public void setAffiliation(String affiliation) {
            this.affiliation = affiliation;
        }

        public void setEnrollment(Enrollment enrollment) {
            this.enrollment = enrollment;
        }

        UserInfo(String mspid, String name, String enrollSecret) {
            this.name = name;
            this.enrollSecret = enrollSecret;
            this.mspid = mspid;
        }

        public String getEnrollSecret() {
            return enrollSecret;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Set<String> getRoles() {
            return roles;
        }

        @Override
        public String getAccount() {
            return account;
        }

        @Override
        public String getAffiliation() {
            return affiliation;
        }

        @Override
        public Enrollment getEnrollment() {
            return enrollment;
        }

        @Override
        public String getMspId() {
            return mspid;
        }

    }

    /**
     * Holds details of an Organization
     */
    public static class OrgInfo {

        private final String name;
        private final String mspId;
        private final List<String> peerNames = new ArrayList<>();
        private final List<CAInfo> certificateAuthorities = new ArrayList<>();
        private UserInfo peerAdmin;

        OrgInfo(String orgName, String mspId) {
            this.name = orgName;
            this.mspId = mspId;
        }

        private void addPeerName(String peerName) {
            peerNames.add(peerName);
        }

        private void addCertificateAuthority(CAInfo ca) {
            certificateAuthorities.add(ca);
        }

        public String getName() {
            return name;
        }

        public String getMspId() {
            return mspId;
        }

        public List<String> getPeerNames() {
            return new LinkedList<>(peerNames);
        }

        public List<CAInfo> getCertificateAuthorities() {
            return new LinkedList<>(certificateAuthorities);
        }

        /**
         * Returns the associated admin user
         *
         * @return The admin user details
         */
        public UserInfo getPeerAdmin() {

            return peerAdmin;
        }

    }

    /**
     * Holds the details of a Certificate Authority
     */
    public static class CAInfo {
        private final String name;
        private final String url;
        private final Properties httpOptions;
        private String caName;          // The "optional" caName specified in the config, as opposed to its "config" name
        private Properties properties;

        private final List<UserInfo> registrars;

        CAInfo(String name, String url, List<UserInfo> registrars, Properties httpOptions) {
            this.name = name;
            this.url = url;
            this.httpOptions = httpOptions;
            this.registrars = registrars;
        }

        private void setCaName(String caName) {
            this.caName = caName;
        }

        public String getName() {
            return name;
        }

        public String getCAName() {
            return caName;
        }

        public String getUrl() {
            return url;
        }

        public Properties getHttpOptions() {
            return httpOptions;
        }

        void setProperties(Properties properties) {
            this.properties = properties;
        }

        public Properties getProperties() {
            return this.properties;
        }

        public Collection<UserInfo> getRegistrars() {
            return new LinkedList<>(registrars);
        }

    }

}
