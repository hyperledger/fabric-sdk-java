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
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Collection;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.NetworkConfigurationException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


public class NetworkConfigTest {

    private static final String CHANNEL_NAME = "myChannel";
    private static final String CLIENT_ORG_NAME = "Org1";


    private static final String USER_NAME = "MockMe";
    private static final String USER_MSP_ID = "MockMSPID";

    @Rule
    public ExpectedException thrown = ExpectedException.none();


    @Test
    public void testLoadFromConfigNullStream() throws Exception {

        // Should not be able to instantiate a new instance of "Client" without a valid path to the configuration');
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("configStream must be specified");

        NetworkConfig.fromJsonStream((InputStream) null);
    }

    @Test
    public void testLoadFromConfigNullYamlFile() throws Exception {
        // Should not be able to instantiate a new instance of "Client" without a valid path to the configuration');
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("configFile must be specified");

        NetworkConfig.fromYamlFile((File) null);
    }

    @Test
    public void testLoadFromConfigNullJsonFile() throws Exception {
        // Should not be able to instantiate a new instance of "Client" without a valid path to the configuration');
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("configFile must be specified");

        NetworkConfig.fromJsonFile((File) null);
    }

    @Test
    public void testLoadFromConfigYamlFileNotExists() throws Exception {

        // Should not be able to instantiate a new instance of "Client" without an actual configuration file
        thrown.expect(FileNotFoundException.class);
        thrown.expectMessage("FileDoesNotExist.yaml");

        File f = new File("FileDoesNotExist.yaml");
        NetworkConfig.fromYamlFile(f);

    }

    @Test
    public void testLoadFromConfigJsonFileNotExists() throws Exception {

        // Should not be able to instantiate a new instance of "Client" without an actual configuration file
        thrown.expect(FileNotFoundException.class);
        thrown.expectMessage("FileDoesNotExist.json");

        File f = new File("FileDoesNotExist.json");
        NetworkConfig.fromJsonFile(f);

    }

    @Test
    public void testLoadFromConfigFileYamlBasic() throws Exception {

        File f = new File("src/test/fixture/sdkintegration/network_configs/network-config.yaml");
        NetworkConfig config = NetworkConfig.fromYamlFile(f);
        Assert.assertNotNull(config);
    }

    @Test
    public void testLoadFromConfigFileJsonBasic() throws Exception {

        File f = new File("src/test/fixture/sdkintegration/network_configs/network-config.json");
        NetworkConfig config = NetworkConfig.fromJsonFile(f);
        Assert.assertNotNull(config);
    }

    @Test
    public void testLoadFromConfigFileYaml() throws Exception {

        // Should be able to instantiate a new instance of "Client" with a valid path to the YAML configuration
        File f = new File("src/test/fixture/sdkintegration/network_configs/network-config.yaml");
        NetworkConfig config = NetworkConfig.fromYamlFile(f);
        //HFClient client = HFClient.loadFromConfig(f);
        Assert.assertNotNull(config);

        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        client.setUserContext(TestUtils.getMockUser(USER_NAME, USER_MSP_ID));

        Channel channel = client.loadChannelFromConfig("foo", config);
        Assert.assertNotNull(channel);
    }

    @Test
    public void testLoadFromConfigFileJson() throws Exception {

        // Should be able to instantiate a new instance of "Client" with a valid path to the JSON configuration
        File f = new File("src/test/fixture/sdkintegration/network_configs/network-config.json");
        NetworkConfig config = NetworkConfig.fromJsonFile(f);
        Assert.assertNotNull(config);

        //HFClient client = HFClient.loadFromConfig(f);
        //Assert.assertNotNull(client);

        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        client.setUserContext(TestUtils.getMockUser(USER_NAME, USER_MSP_ID));

        Channel channel = client.loadChannelFromConfig("mychannel", config);
        Assert.assertNotNull(channel);
    }

    @Test
    public void testLoadFromConfigNoOrganization() throws Exception {

        // Should not be able to instantiate a new instance of "Channel" without specifying a valid client organization
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("client organization must be specified");

        JsonObject jsonConfig = getJsonConfig1(0, 1, 0);

        NetworkConfig.fromJsonObject(jsonConfig);
    }

    @Test
    public void testGetClientOrg() throws Exception {

        JsonObject jsonConfig = getJsonConfig1(1, 0, 0);

        NetworkConfig config = NetworkConfig.fromJsonObject(jsonConfig);

        Assert.assertEquals(CLIENT_ORG_NAME, config.getClientOrganization().getName());
    }

    // TODO: At least one orderer must be specified
    @Ignore
    @Test
    public void testNewChannel() throws Exception {

        // Should be able to instantiate a new instance of "Channel" with the definition in the network configuration'
        JsonObject jsonConfig = getJsonConfig1(1, 0, 0);

        NetworkConfig config = NetworkConfig.fromJsonObject(jsonConfig);

        HFClient client = HFClient.createNewInstance();
        TestHFClient.setupClient(client);

        Channel channel = client.loadChannelFromConfig(CHANNEL_NAME, config);
        Assert.assertNotNull(channel);
        Assert.assertEquals(CHANNEL_NAME, channel.getName());
    }

    @Test
    public void testGetChannelNotExists() throws Exception {

        //thrown.expect(InvalidArgumentException.class);
        //thrown.expectMessage("Channel is not configured");

        // Should not be able to instantiate a new instance of "Channel" with an invalid channel name
        JsonObject jsonConfig = getJsonConfig1(1, 1, 1);

        NetworkConfig config = NetworkConfig.fromJsonObject(jsonConfig);

        HFClient client = HFClient.createNewInstance();
        TestHFClient.setupClient(client);

        Channel channel = client.loadChannelFromConfig("ThisChannelDoesNotExist", config);

        //HFClient client = HFClient.loadFromConfig(jsonConfig);
        //Channel channel = client.getChannel("ThisChannelDoesNotExist");
        Assert.assertNull("Expected null to be returned for channels that are not configured", channel);

    }

    @Test
    public void testGetChannelNoOrderersOrPeers() throws Exception {

        thrown.expect(NetworkConfigurationException.class);
        thrown.expectMessage("Error constructing");

        // Should not be able to instantiate a new instance of "Channel" with no orderers or peers configured
        JsonObject jsonConfig = getJsonConfig1(1, 0, 0);

        NetworkConfig config = NetworkConfig.fromJsonObject(jsonConfig);

        HFClient client = HFClient.createNewInstance();
        TestHFClient.setupClient(client);

        client.loadChannelFromConfig(CHANNEL_NAME, config);

        //HFClient client = HFClient.loadFromConfig(jsonConfig);
        //TestHFClient.setupClient(client);

        //client.getChannel(CHANNEL_NAME);
    }

    @Test
    public void testGetChannelNoOrderers() throws Exception {

        thrown.expect(NetworkConfigurationException.class);
        thrown.expectMessage("Error constructing");

        // Should not be able to instantiate a new instance of "Channel" with no orderers configured
        JsonObject jsonConfig = getJsonConfig1(1, 0, 1);

        //HFClient client = HFClient.loadFromConfig(jsonConfig);
        //TestHFClient.setupClient(client);


        //client.getChannel(CHANNEL_NAME);

        NetworkConfig config = NetworkConfig.fromJsonObject(jsonConfig);

        HFClient client = HFClient.createNewInstance();
        TestHFClient.setupClient(client);

        client.loadChannelFromConfig(CHANNEL_NAME, config);

    }

    @Test
    public void testGetChannelNoPeers() throws Exception {

        thrown.expect(NetworkConfigurationException.class);
        thrown.expectMessage("Error constructing");

        // Should not be able to instantiate a new instance of "Channel" with no peers configured
        JsonObject jsonConfig = getJsonConfig1(1, 1, 0);

        NetworkConfig config = NetworkConfig.fromJsonObject(jsonConfig);

        HFClient client = HFClient.createNewInstance();
        TestHFClient.setupClient(client);

        client.loadChannelFromConfig(CHANNEL_NAME, config);

        //HFClient client = HFClient.loadFromConfig(jsonConfig);
        //TestHFClient.setupClient(client);


        //client.getChannel(CHANNEL_NAME);

    }


    // TODO: ca-org1 not defined
    @Ignore
    @Test
    public void testGetChannel() throws Exception {

        // Should be able to instantiate a new instance of "Channel" with orderer, org and peer defined in the network configuration
        JsonObject jsonConfig = getJsonConfig1(4, 1, 1);

        NetworkConfig config = NetworkConfig.fromJsonObject(jsonConfig);

        HFClient client = HFClient.createNewInstance();
        TestHFClient.setupClient(client);

        Channel channel = client.loadChannelFromConfig(CHANNEL_NAME, config);

        //HFClient client = HFClient.loadFromConfig(jsonConfig);
        //TestHFClient.setupClient(client);

        //Channel channel = client.getChannel(CHANNEL_NAME);
        Assert.assertNotNull(channel);
        Assert.assertEquals(CHANNEL_NAME, channel.getName());

        Collection<Orderer> orderers = channel.getOrderers();
        Assert.assertNotNull(orderers);
        Assert.assertEquals(1, orderers.size());

        Orderer orderer = orderers.iterator().next();
        Assert.assertEquals("orderer1.example.com", orderer.getName());

        Collection<Peer> peers = channel.getPeers();
        Assert.assertNotNull(peers);
        Assert.assertEquals(1, peers.size());

        Peer peer = peers.iterator().next();
        Assert.assertEquals("peer0.org1.example.com", peer.getName());

    }


    private static JsonObject getJsonConfig1(int nOrganizations, int nOrderers, int nPeers) {

        // Sanity check
        if (nPeers > nOrganizations) {
            // To keep things simple we require a maximum of 1 peer per organization
            throw new RuntimeException("Number of peers cannot exceed number of organizations!");
        }

        JsonObjectBuilder mainConfig = Json.createObjectBuilder();
        mainConfig.add("name", "myNetwork");
        mainConfig.add("description", "My Test Network");
        mainConfig.add("x-type", "hlf@^1.0.0");
        mainConfig.add("version", "1.0.0");

        JsonObjectBuilder client = Json.createObjectBuilder();
        if (nOrganizations > 0) {
            client.add("organization", CLIENT_ORG_NAME);
        }
        mainConfig.add("client", client);

        JsonArray orderers = nOrderers > 0 ? createJsonArray("orderer1.example.com") : null;
        JsonArray chaincodes = (nOrderers > 0 && nPeers > 0) ? createJsonArray("example02:v1", "marbles:1.0") : null;

        JsonObject peers = null;
        if (nPeers > 0) {
            JsonObjectBuilder builder = Json.createObjectBuilder();
            builder.add("peer0.org1.example.com", createJsonChannelPeer("Org1", true, true, true, true));
            if (nPeers > 1) {
                builder.add("peer0.org2.example.com", createJsonChannelPeer("Org2", true, false, true, false));
            }
            peers = builder.build();
        }

        JsonObject channel1 = createJsonChannel(
                orderers,
                peers,
                chaincodes
        );

        String channelName = CHANNEL_NAME;

        JsonObject channels = Json.createObjectBuilder()
                .add(channelName, channel1)
                .build();

        mainConfig.add("channels", channels);

        if (nOrganizations > 0) {

            // Add some organizations to the config
            JsonObjectBuilder builder = Json.createObjectBuilder();

            for (int i = 1; i <= nOrganizations; i++) {
                String orgName = "Org" + i;
                JsonObject org = createJsonOrg(
                        orgName + "MSP",
                        createJsonArray("peer0.org" + i + ".example.com"),
                        createJsonArray("ca-org" + i),
                        createJsonArray(createJsonUser("admin" + i, "adminpw" + i)),
                        "-----BEGIN PRIVATE KEY----- <etc>",
                        "-----BEGIN CERTIFICATE----- <etc>"
                );
                builder.add(orgName, org);
            }

            mainConfig.add("organizations", builder.build());
        }

        if (nOrderers > 0) {
            // Add some orderers to the config
            JsonObjectBuilder builder = Json.createObjectBuilder();

            for (int i = 1; i <= nOrderers; i++) {
                String ordererName = "orderer" + i + ".example.com";
                int port = (6 + i) * 1000 + 50;         // 7050, 8050, etc
                JsonObject orderer = createJsonOrderer(
                        "grpcs://localhost:" + port,
                        Json.createObjectBuilder()
                            .add("ssl-target-name-override", "orderer" + i + ".example.com")
                            .build(),
                        Json.createObjectBuilder()
                            .add("pem", "-----BEGIN CERTIFICATE----- <etc>")
                            .build()
                );
                builder.add(ordererName, orderer);
            }
            mainConfig.add("orderers", builder.build());
        }


        if (nPeers > 0) {
            // Add some peers to the config
            JsonObjectBuilder builder = Json.createObjectBuilder();

            for (int i = 1; i <= nPeers; i++) {
                String peerName = "peer0.org" + i + ".example.com";

                int port1 = (6 + i) * 1000 + 51;         // 7051, 8051, etc
                int port2 = (6 + i) * 1000 + 53;         // 7053, 8053, etc

                int orgNo = i;
                int peerNo = 0;

                JsonObject peer = createJsonPeer(
                        "grpcs://localhost:" + port1,
                        "grpcs://localhost:" + port2,
                        Json.createObjectBuilder()
                            .add("ssl-target-name-override", "peer" + peerNo + ".org" + orgNo + ".example.com")
                            .build(),
                        Json.createObjectBuilder()
                            .add("path", "test/fixtures/channel/crypto-config/peerOrganizations/org" + orgNo + ".example.com/peers/peer" + peerNo + ".org" + orgNo + ".example.com/tlscacerts/org" + orgNo + ".example.com-cert.pem")
                            .build(),
                            createJsonArray(channelName)
                );
                builder.add(peerName, peer);
            }
            mainConfig.add("peers", builder.build());
        }

        // CAs
        JsonObjectBuilder builder = Json.createObjectBuilder();

        String caName = "ca-org1";
        JsonObject ca = Json.createObjectBuilder()
                .add("url", "https://localhost:7054")
                .build();
        builder.add(caName, ca);

        mainConfig.add("certificateAuthorities", builder.build());


        JsonObject config = mainConfig.build();

        return config;
    }



    private static JsonObject createJsonChannelPeer(String name, Boolean endorsingPeer, Boolean chaincodeQuery, Boolean ledgerQuery, Boolean eventSource) {

        return Json.createObjectBuilder()
            .add("name", name)
            .add("endorsingPeer", endorsingPeer)
            .add("chaincodeQuery", chaincodeQuery)
            .add("ledgerQuery", ledgerQuery)
            .add("eventSource", eventSource)
            .build();
    }

    private static JsonObject createJsonChannel(JsonArray orderers, JsonObject peers, JsonArray chaincodes) {

        JsonObjectBuilder builder = Json.createObjectBuilder();

        if (orderers != null) {
            builder.add("orderers", orderers);
        }

        if (peers != null) {
            builder.add("peers", peers);
        }

        if (chaincodes != null) {
            builder.add("chaincodes", chaincodes);
        }

        return builder.build();
    }

    private static JsonObject createJsonOrg(String mspid, JsonArray peers, JsonArray certificateAuthorities, JsonArray users, String adminPrivateKeyPem, String signedCertPem) {

        return Json.createObjectBuilder()
                .add("mspid", mspid)
                .add("peers", peers)
                .add("certificateAuthorities", certificateAuthorities)
                .add("users", users)
                .add("adminPrivateKeyPEM", adminPrivateKeyPem)
                .add("signedCertPEM", signedCertPem)
                .build();
    }

    private static JsonObject createJsonUser(String enrollId, String enrollSecret) {

        return Json.createObjectBuilder()
                .add("enrollId", enrollId)
                .add("enrollSecret", enrollSecret)
                .build();
    }


    private static JsonObject createJsonOrderer(String url, JsonObject grpcOptions, JsonObject tlsCaCerts) {

        return Json.createObjectBuilder()
                .add("url", url)
                .add("grpcOptions", grpcOptions)
                .add("tlsCaCerts", tlsCaCerts)
                .build();
    }

    private static JsonObject createJsonPeer(String url, String eventUrl, JsonObject grpcOptions, JsonObject tlsCaCerts, JsonArray channels) {

        return Json.createObjectBuilder()
            .add("url", url)
            .add("eventUrl", eventUrl)
            .add("grpcOptions", grpcOptions)
            .add("tlsCaCerts", tlsCaCerts)
            .add("channels", channels)
            .build();
    }


    private static JsonArray createJsonArray(String... elements) {

        JsonArrayBuilder builder = Json.createArrayBuilder();

        for (String ele: elements) {
            builder.add(ele);
        }

        return builder.build();
    }

    private static JsonArray createJsonArray(JsonValue... elements) {

        JsonArrayBuilder builder = Json.createArrayBuilder();

        for (JsonValue ele: elements) {
            builder.add(ele);
        }

        return builder.build();
    }

}
