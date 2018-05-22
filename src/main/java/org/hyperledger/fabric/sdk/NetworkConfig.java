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
import java.lang.reflect.InvocationTargetException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

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
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.NetworkConfigurationException;
import org.hyperledger.fabric.sdk.identity.SigningIdentity;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric.sdk.identity.X509SigningIdentity;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.yaml.snakeyaml.Yaml;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;

/**
 * Holds details of network and channel configurations typically loaded from an external config file.
 * <br>
 * Also contains convenience methods for utilizing the config details,
 * including the main {@link HFClient#getChannel(String)} method
 */

public class NetworkConfig {

    private final JsonObject jsonConfig;

    private OrgInfo clientOrganization;

    private Map<String, Node> orderers;
    private Map<String, Node> peers;
    private Map<String, Node> eventHubs;

    /**
     * Names of Peers found
     *
     * @return Collection of peer names found.
     */
    public Collection<String> getPeerNames() {
        if (peers == null) {
            return Collections.EMPTY_SET;
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
            return Collections.EMPTY_SET;
        } else {
            return new HashSet<>(orderers.keySet());
        }
    }

    /**
     * Names of EventHubs found
     *
     * @return Collection of eventhubs names found.
     */

    public Collection<String> getEventHubNames() {
        if (eventHubs == null) {
            return Collections.EMPTY_SET;
        } else {
            return new HashSet<>(eventHubs.keySet());
        }
    }

    private Properties getNodeProperties(String type, String name, Map<String, Node> nodes) throws InvalidArgumentException {
        if (isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Parameter name is null or empty.");
        }

        Node node = nodes.get(name);
        if (node == null) {
            throw new InvalidArgumentException(format("%s %s not found.", type, name));
        }

        if (null == node.properties) {
            return new Properties();
        } else {

            return (Properties) node.properties.clone();
        }

    }

    private void setNodeProperties(String type, String name, Map<String, Node> nodes, Properties properties) throws InvalidArgumentException {
        if (isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Parameter name is null or empty.");
        }
        if (properties == null) {
            throw new InvalidArgumentException("Parameter properties is null.");
        }

        Node node = nodes.get(name);
        if (node == null) {
            throw new InvalidArgumentException(format("%S %s not found.", type, name));
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
     * @throws InvalidArgumentException
     */
    public Properties getPeerProperties(String name) throws InvalidArgumentException {
        return getNodeProperties("Peer", name, peers);

    }

    /**
     * Get properties for a specific Orderer.
     *
     * @param name Name of orderer to get the properties for.
     * @return The orderer's properties.
     * @throws InvalidArgumentException
     */
    public Properties getOrdererProperties(String name) throws InvalidArgumentException {
        return getNodeProperties("Orderer", name, orderers);

    }

    /**
     * Get properties for a specific eventhub.
     *
     * @param name Name of eventhub to get the properties for.
     * @return The eventhubs's properties.
     * @throws InvalidArgumentException
     */
    public Properties getEventHubsProperties(String name) throws InvalidArgumentException {
        return getNodeProperties("EventHub", name, eventHubs);

    }

    /**
     * Set a specific peer's properties.
     *
     * @param name       The name of the peer's property to set.
     * @param properties The properties to set.
     * @throws InvalidArgumentException
     */
    public void setPeerProperties(String name, Properties properties) throws InvalidArgumentException {
        setNodeProperties("Peer", name, peers, properties);
    }

    /**
     * Set a specific orderer's properties.
     *
     * @param name       The name of the orderer's property to set.
     * @param properties The properties to set.
     * @throws InvalidArgumentException
     */
    public void setOrdererProperties(String name, Properties properties) throws InvalidArgumentException {
        setNodeProperties("Orderer", name, orderers, properties);
    }

    /**
     * Set a specific eventhub's properties.
     *
     * @param name       The name of the eventhub's property to set.
     * @param properties The properties to set.
     * @throws InvalidArgumentException
     */
    public void setEventHubProperties(String name, Properties properties) throws InvalidArgumentException {
        setNodeProperties("EventHub", name, eventHubs, properties);
    }

    // Organizations, keyed on org name (and not on mspid!)
    private Map<String, OrgInfo> organizations;

    private static final Log logger = LogFactory.getLog(NetworkConfig.class);

    private NetworkConfig(JsonObject jsonConfig) throws InvalidArgumentException, NetworkConfigurationException {

        this.jsonConfig = jsonConfig;

        // Extract the main details
        String configName = getJsonValueAsString(jsonConfig.get("name"));
        if (configName == null || configName.isEmpty()) {
            throw new InvalidArgumentException("Network config must have a name");
        }

        String configVersion = getJsonValueAsString(jsonConfig.get("version"));
        if (configVersion == null || configVersion.isEmpty()) {
            throw new InvalidArgumentException("Network config must have a version");
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
            throw new InvalidArgumentException("A client organization must be specified");
        }

        clientOrganization = getOrganizationInfo(orgName);
        if (clientOrganization == null) {
            throw new InvalidArgumentException("Client organization " + orgName + " is not defined");
        }

    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in a YAML file.
     *
     * @param configFile The file containing the network configuration
     * @return A new NetworkConfig instance
     * @throws InvalidArgumentException
     * @throws IOException
     */
    public static NetworkConfig fromYamlFile(File configFile) throws InvalidArgumentException, IOException, NetworkConfigurationException {
        return fromFile(configFile, false);
    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in a JSON file.
     *
     * @param configFile The file containing the network configuration
     * @return A new NetworkConfig instance
     * @throws InvalidArgumentException
     * @throws IOException
     */
    public static NetworkConfig fromJsonFile(File configFile) throws InvalidArgumentException, IOException, NetworkConfigurationException {
        return fromFile(configFile, true);
    }

    /**
     * Creates a new NetworkConfig instance configured with details supplied in YAML format
     *
     * @param configStream A stream opened on a YAML document containing network configuration details
     * @return A new NetworkConfig instance
     * @throws InvalidArgumentException
     */
    public static NetworkConfig fromYamlStream(InputStream configStream) throws InvalidArgumentException, NetworkConfigurationException {

        logger.trace("NetworkConfig.fromYamlStream...");

        // Sanity check
        if (configStream == null) {
            throw new InvalidArgumentException("configStream must be specified");
        }

        Yaml yaml = new Yaml();

        @SuppressWarnings ("unchecked")
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
     * @throws InvalidArgumentException
     */
    public static NetworkConfig fromJsonStream(InputStream configStream) throws InvalidArgumentException, NetworkConfigurationException {

        logger.trace("NetworkConfig.fromJsonStream...");

        // Sanity check
        if (configStream == null) {
            throw new InvalidArgumentException("configStream must be specified");
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
     * @throws InvalidArgumentException
     */
    public static NetworkConfig fromJsonObject(JsonObject jsonConfig) throws InvalidArgumentException, NetworkConfigurationException {

        // Sanity check
        if (jsonConfig == null) {
            throw new InvalidArgumentException("jsonConfig must be specified");
        }

        if (logger.isTraceEnabled()) {
            logger.trace(format("NetworkConfig.fromJsonObject: %s", jsonConfig.toString()));
        }

        return NetworkConfig.load(jsonConfig);
    }

    // Loads a NetworkConfig object from a Json or Yaml file
    private static NetworkConfig fromFile(File configFile, boolean isJson) throws InvalidArgumentException, IOException, NetworkConfigurationException {

        // Sanity check
        if (configFile == null) {
            throw new InvalidArgumentException("configFile must be specified");
        }

        if (logger.isTraceEnabled()) {
            logger.trace(format("NetworkConfig.fromFile: %s  isJson = %b", configFile.getAbsolutePath(), isJson));
        }

        NetworkConfig config;

        // Json file
        try (InputStream stream = new FileInputStream(configFile)) {
            config = isJson ? fromJsonStream(stream) : fromYamlStream(stream);
        }

        return config;
    }

    /**
     * Returns a new NetworkConfig instance and populates it from the specified JSON object
     *
     * @param jsonConfig The JSON object containing the config details
     * @return A populated NetworkConfig instance
     * @throws InvalidArgumentException
     */
    private static NetworkConfig load(JsonObject jsonConfig) throws InvalidArgumentException, NetworkConfigurationException {

        // Sanity check
        if (jsonConfig == null) {
            throw new InvalidArgumentException("config must be specified");
        }

        return new NetworkConfig(jsonConfig);
    }

    public OrgInfo getClientOrganization() {
        return clientOrganization;
    }

    public OrgInfo getOrganizationInfo(String orgName) {
        return organizations.get(orgName);
    }

    public Collection<OrgInfo> getOrganizationInfos() {
        return Collections.unmodifiableCollection(organizations.values());
    }

    /**
     * Returns the admin user associated with the client organization
     *
     * @return The admin user details
     * @throws NetworkConfigurationException
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
     * @throws NetworkConfigurationException
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
    Channel loadChannel(HFClient client, String channelName) throws NetworkConfigurationException {

        if (logger.isTraceEnabled()) {
            logger.trace(format("NetworkConfig.loadChannel: %s", channelName));
        }

        Channel channel = null;

        JsonObject channels = getJsonObject(jsonConfig, "channels");

        if (channels != null) {
            JsonObject jsonChannel = getJsonObject(channels, channelName);
            if (jsonChannel != null) {
                channel = client.getChannel(channelName);
                if (channel != null) {
                    // The channel already exists in the client!
                    // Note that by rights this should never happen as HFClient.loadChannelFromConfig should have already checked for this!
                    throw new NetworkConfigurationException(format("Channel %s is already configured in the client!", channelName));
                }
                channel = reconstructChannel(client, channelName, jsonChannel);
            } else {

                final Set<String> channelNames = getChannelNames();
                if (channelNames.isEmpty()) {
                    throw new NetworkConfigurationException("Channel configuration has no channels defined.");
                }
                final StringBuilder sb = new StringBuilder(1000);

                channelNames.forEach(s -> {
                    if (sb.length() != 0) {
                        sb.append(", ");
                    }
                    sb.append(s);
                });
                throw new NetworkConfigurationException(format("Channel %s not found in configuration file. Found channel names: %s ", channelName, sb.toString()));

            }

        } else {
            throw new NetworkConfigurationException("Channel configuration has no channels defined.");
        }

        return channel;
    }

    // Creates Node instances representing all the orderers defined in the config file
    private void createAllOrderers() throws NetworkConfigurationException {

        // Sanity check
        if (orderers != null) {
            throw new NetworkConfigurationException("INTERNAL ERROR: orderers has already been initialized!");
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

                Node orderer = createNode(ordererName, jsonOrderer, "url");
                if (orderer == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid orderer entry: %s", ordererName));
                }
                orderers.put(ordererName, orderer);
            }
        }

    }

    // Creates Node instances representing all the peers (and associated event hubs) defined in the config file
    private void createAllPeers() throws NetworkConfigurationException {

        // Sanity checks
        if (peers != null) {
            throw new NetworkConfigurationException("INTERNAL ERROR: peers has already been initialized!");
        }

        if (eventHubs != null) {
            throw new NetworkConfigurationException("INTERNAL ERROR: eventHubs has already been initialized!");
        }

        peers = new HashMap<>();
        eventHubs = new HashMap<>();

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

                Node peer = createNode(peerName, jsonPeer, "url");
                if (peer == null) {
                    throw new NetworkConfigurationException(format("Error loading config. Invalid peer entry: %s", peerName));
                }
                peers.put(peerName, peer);

                // Also create an event hub with the same name as the peer
                Node eventHub = createNode(peerName, jsonPeer, "eventUrl"); // may not be present
                if (null != eventHub) {
                    eventHubs.put(peerName, eventHub);
                }
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
            throw new NetworkConfigurationException("INTERNAL ERROR: organizations has already been initialized!");
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
    private Channel reconstructChannel(HFClient client, String channelName, JsonObject jsonChannel) throws NetworkConfigurationException {

        Channel channel = null;

        try {
            channel = client.newChannel(channelName);

            // orderers is an array of orderer name strings
            JsonArray ordererNames = getJsonValueAsArray(jsonChannel.get("orderers"));
            boolean foundOrderer = false;

            //out("Orderer names: " + (ordererNames == null ? "null" : ordererNames.toString()));
            if (ordererNames != null) {
                for (JsonValue jsonVal : ordererNames) {

                    String ordererName = getJsonValueAsString(jsonVal);
                    Orderer orderer = getOrderer(client, ordererName);
                    if (orderer == null) {
                        throw new NetworkConfigurationException(format("Error constructing channel %s. Orderer %s not defined in configuration", channelName, ordererName));
                    }
                    channel.addOrderer(orderer);
                    foundOrderer = true;
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

                    Peer peer = getPeer(client, peerName);
                    if (peer == null) {
                        throw new NetworkConfigurationException(format("Error constructing channel %s. Peer %s not defined in configuration", channelName, peerName));
                    }

                    // Set the various roles
                    PeerOptions peerOptions = PeerOptions.createPeerOptions();

                    for (PeerRole peerRole : PeerRole.values()) {
                        setPeerRole(channelName, peerOptions, jsonPeer, peerRole);
                    }

                    foundPeer = true;

                    // Add the event hub associated with this peer
                    EventHub eventHub = getEventHub(client, peerName);
                    if (eventHub != null) {
                        channel.addEventHub(eventHub);
                        if (peerOptions.peerRoles == null) { // means no roles were found but there is an event hub so define all roles but eventing.
                            peerOptions.setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.CHAINCODE_QUERY, PeerRole.LEDGER_QUERY));
                        }
                    }
                    channel.addPeer(peer, peerOptions);

                }

            }

            if (!foundPeer) {
                // peers is a required field
                throw new NetworkConfigurationException(format("Error constructing channel %s. At least one peer must be specified", channelName));
            }

        } catch (InvalidArgumentException e) {
            throw new IllegalArgumentException(e);
        }

        return channel;
    }

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

    private static Map<PeerRole, String> roleNameRemapHash = new HashMap<PeerRole, String>() {
        {
            put(PeerRole.SERVICE_DISCOVERY, "discover");
        }
    };

    private static String roleNameRemap(PeerRole peerRole) {
        String remap = roleNameRemapHash.get(peerRole);
        return remap == null ? peerRole.getPropertyName() : remap;
    }

    // Returns a new Orderer instance for the specified orderer name
    private Orderer getOrderer(HFClient client, String ordererName) throws InvalidArgumentException {
        Orderer orderer = null;
        Node o = orderers.get(ordererName);
        if (o != null) {
            orderer = client.newOrderer(o.getName(), o.getUrl(), o.getProperties());
        }
        return orderer;
    }

    // Creates a new Node instance from a JSON object
    private Node createNode(String nodeName, JsonObject jsonNode, String urlPropName) throws NetworkConfigurationException {

//        jsonNode.
//        if (jsonNode.isNull(urlPropName)) {
//            return  null;
//        }

        String url = jsonNode.getString(urlPropName, null);
        if (url == null) {
            return null;
        }

        Properties props = extractProperties(jsonNode, "grpcOptions");

        if (null != props) {
            String value = props.getProperty("grpc.keepalive_time_ms");
            if (null != value) {
                props.remove("grpc.keepalive_time_ms");
                props.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {new Long(value), TimeUnit.MILLISECONDS});
            }

            value = props.getProperty("grpc.keepalive_timeout_ms");
            if (null != value) {
                props.remove("grpc.keepalive_timeout_ms");
                props.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {new Long(value), TimeUnit.MILLISECONDS});
            }
        }

        // Extract the pem details
        getTLSCerts(nodeName, jsonNode, props);

        return new Node(nodeName, url, props);
    }

    private void getTLSCerts(String nodeName, JsonObject jsonOrderer, Properties props) {
        JsonObject jsonTlsCaCerts = getJsonObject(jsonOrderer, "tlsCACerts");
        if (jsonTlsCaCerts != null) {
            String pemFilename = getJsonValueAsString(jsonTlsCaCerts.get("path"));
            String pemBytes = getJsonValueAsString(jsonTlsCaCerts.get("pem"));

            if (pemFilename != null) {
                // let the sdk handle non existing errors could be they don't exist during parsing but are there later.
                props.put("pemFile", pemFilename);
            }

            if (pemBytes != null) {
                props.put("pemBytes", pemBytes.getBytes());
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
                String peerName = getJsonValueAsString(peer);
                if (peerName != null) {
                    org.addPeerName(peerName);
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

            PrivateKey privateKey = null;

            try {
                privateKey = getPrivateKeyFromString(adminPrivateKeyString);
            } catch (IOException ioe) {
                throw new NetworkConfigurationException(format("%s: Invalid private key", msgPrefix), ioe);
            }

            final PrivateKey privateKeyFinal = privateKey;

            try {
                org.peerAdmin = new UserInfo(CryptoSuite.Factory.getCryptoSuite(), mspId, "PeerAdmin_" + mspId + "_" + orgName, null);
            } catch (Exception e) {
                throw new NetworkConfigurationException(e.getMessage(), e);
            }
            org.peerAdmin.setEnrollment(new X509Enrollment(privateKeyFinal, signedCert));

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
                pemString = IOUtils.toString(stream, "UTF-8");
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

        String enrollId = null;
        String enrollSecret = null;

        List<JsonObject> registrars = getJsonValueAsList(jsonCA.get("registrar"));
        List<UserInfo> regUsers = new LinkedList<>();
        if (registrars != null) {

            for (JsonObject reg : registrars) {
                enrollId = getJsonValueAsString(reg.get("enrollId"));
                enrollSecret = getJsonValueAsString(reg.get("enrollSecret"));
                try {
                    regUsers.add(new UserInfo(CryptoSuite.Factory.getCryptoSuite(), org.mspId, enrollId, enrollSecret));
                } catch (Exception e) {
                    throw new NetworkConfigurationException(e.getMessage(), e);
                }
            }
        }

        CAInfo caInfo = new CAInfo(name, org.mspId, url, regUsers, httpOptions);

        String caName = getJsonValueAsString(jsonCA.get("caName"));
        if (caName != null) {
            caInfo.setCaName(caName);
        }

        Properties properties = new Properties();
        if (null != httpOptions && "false".equals(httpOptions.getProperty("verify"))) {
            properties.setProperty("allowAllHostNames", "true");
        }
        getTLSCerts(name, jsonCA, properties);
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

    // Returns a new Peer instance for the specified peer name
    private Peer getPeer(HFClient client, String peerName) throws InvalidArgumentException {
        Peer peer = null;
        Node p = peers.get(peerName);
        if (p != null) {
            peer = client.newPeer(p.getName(), p.getUrl(), p.getProperties());
        }
        return peer;
    }

    // Returns a new EventHub instance for the specified name
    private EventHub getEventHub(HFClient client, String name) throws InvalidArgumentException {
        EventHub ehub = null;
        Node e = eventHubs.get(name);
        if (e != null) {
            ehub = client.newEventHub(e.getName(), e.getUrl(), e.getProperties());
        }
        return ehub;
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

    // Returns the specified JsonValue as a List. Allows single or array
    private static List<JsonObject> getJsonValueAsList(JsonValue value) {
        if (value != null) {
            if (value.getValueType() == ValueType.ARRAY) {
                return value.asJsonArray().getValuesAs(JsonObject.class);

            } else if (value.getValueType() == ValueType.OBJECT) {
                List<JsonObject> ret = new ArrayList<>();
                ret.add(value.asJsonObject());

                return ret;
            }
        }
        return null;
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
        Set<String> ret = Collections.EMPTY_SET;

        JsonObject channels = getJsonObject(jsonConfig, "channels");
        if (channels != null) {
            final Set<String> channelNames = channels.keySet();
            if (channelNames != null && !channelNames.isEmpty()) {
                ret = new HashSet<>(channelNames);
            }
        }
        return ret;
    }

    // Holds a network "node" (eg. Peer, Orderer, EventHub)
    private class Node {

        private final String name;
        private final String url;
        private Properties properties;

        Node(String name, String url, Properties properties) {
            this.url = url;
            this.name = name;
            this.properties = properties;
        }

        private String getName() {
            return name;
        }

        private String getUrl() {
            return url;
        }

        private Properties getProperties() {
            return properties;
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
        private CryptoSuite suite;

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

        UserInfo(CryptoSuite suite, String mspid, String name, String enrollSecret) {
            this.suite = suite;
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
            return peerNames;
        }

        public List<CAInfo> getCertificateAuthorities() {
            return certificateAuthorities;
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
        private final String mspid;
        private String caName;          // The "optional" caName specified in the config, as opposed to its "config" name
        private Properties properties;

        private final List<UserInfo> registrars;

        CAInfo(String name, String mspid, String url, List<UserInfo> registrars, Properties httpOptions) {
            this.name = name;
            this.url = url;
            this.httpOptions = httpOptions;
            this.registrars = registrars;
            this.mspid = mspid;
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
