/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdkintegration;

import java.io.File;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.UpdateChannelConfiguration;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Update channel scenario
 * See http://hyperledger-fabric.readthedocs.io/en/master/configtxlator.html
 * for details.
 */
public class UpdateChannelIT {

    private static final TestConfig testConfig = TestConfig.getConfig();

    private static final String ORIGINAL_BATCH_TIMEOUT = "\"timeout\": \"2s\""; // Batch time out in configtx.yaml
    private static final String UPDATED_BATCH_TIMEOUT = "\"timeout\": \"5s\"";  // What we want to change it to.

    private static final String FOO_CHANNEL_NAME = "foo";

    private final TestConfigHelper configHelper = new TestConfigHelper();

    private Collection<SampleOrg> testSampleOrgs;

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException {

        out("\n\n\nRUNNING: UpdateChannelIT\n");

        configHelper.clearConfig();
        configHelper.customizeConfig();

        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
    }

    @After
    public void clearConfig() {
        try {
            configHelper.clearConfig();
        } catch (Exception e) {
        }
    }

    @Test
    public void setup() {

        try {

            ////////////////////////////
            // Setup client

            //Create instance of client.
            HFClient client = HFClient.createNewInstance();

            client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            ////////////////////////////
            //Set up USERS

            //Persistence is not part of SDK. Sample file store is for demonstration purposes only!
            //   MUST be replaced with more robust application implementation  (Database, LDAP)
            File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
            sampleStoreFile.deleteOnExit();

            final SampleStore sampleStore = new SampleStore(sampleStoreFile);

            //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface

            ////////////////////////////
            // get users for all orgs

            for (SampleOrg sampleOrg : testSampleOrgs) {

                final String orgName = sampleOrg.getName();
                sampleOrg.setPeerAdmin(sampleStore.getMember(orgName + "Admin", orgName));
            }

            ////////////////////////////
            //Reconstruct and run the channels
            SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
            Channel fooChannel = reconstructChannel(FOO_CHANNEL_NAME, client, sampleOrg);

            // Getting foo channels current configuration bytes.
            final byte[] channelConfigurationBytes = fooChannel.getChannelConfigurationBytes();

            HttpClient httpclient = HttpClients.createDefault();
            HttpPost httppost = new HttpPost("http://localhost:7059/protolator/decode/common.Config");
            httppost.setEntity(new ByteArrayEntity(channelConfigurationBytes));

            HttpResponse response = httpclient.execute(httppost);
            int statuscode = response.getStatusLine().getStatusCode();
            out("Got %s status for decoding current channel config bytes", statuscode);
            assertEquals(200, statuscode);

            String responseAsString = EntityUtils.toString(response.getEntity());

            //responseAsString is JSON but use just string operations for this test.

            if (!responseAsString.contains(ORIGINAL_BATCH_TIMEOUT)) {

                fail(format("Did not find expected batch timeout '%s', in:%s", ORIGINAL_BATCH_TIMEOUT, responseAsString));
            }

            //Now modify the batch timeout
            String updateString = responseAsString.replace(ORIGINAL_BATCH_TIMEOUT, UPDATED_BATCH_TIMEOUT);

            httppost = new HttpPost("http://localhost:7059/protolator/encode/common.Config");
            httppost.setEntity(new StringEntity(updateString));

            response = httpclient.execute(httppost);
            statuscode = response.getStatusLine().getStatusCode();
            out("Got %s status for encoding the new desired channel config bytes", statuscode);
            assertEquals(200, statuscode);
            byte[] newConfigBytes = EntityUtils.toByteArray(response.getEntity());

            // Now send to configtxlator multipart form post with original config bytes, updated config bytes and channel name.
            httppost = new HttpPost("http://localhost:7059/configtxlator/compute/update-from-configs");

            HttpEntity multipartEntity = MultipartEntityBuilder.create()
                    .setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                    .addBinaryBody("original", channelConfigurationBytes, ContentType.APPLICATION_OCTET_STREAM, "originalFakeFilename")
                    .addBinaryBody("updated", newConfigBytes, ContentType.APPLICATION_OCTET_STREAM, "updatedFakeFilename")
                    .addBinaryBody("channel", fooChannel.getName().getBytes()).build();

            httppost.setEntity(multipartEntity);

            response = httpclient.execute(httppost);
            statuscode = response.getStatusLine().getStatusCode();
            out("Got %s status for updated config bytes needed for updateChannelConfiguration ", statuscode);
            assertEquals(200, statuscode);

            byte[] updateBytes = EntityUtils.toByteArray(response.getEntity());

            UpdateChannelConfiguration updateChannelConfiguration = new UpdateChannelConfiguration(updateBytes);

            //To change the channel we need to sign with orderer admin certs which crypto gen stores:

            // private key: src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/keystore/f1a9a940f57419a18a83a852884790d59b378281347dd3d4a88c2b820a0f70c9_sk
            //certificate:  src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/signcerts/Admin@example.com-cert.pem

            final String sampleOrgName = sampleOrg.getName();
            final SampleUser ordererAdmin = sampleStore.getMember(sampleOrgName + "OrderAdmin", sampleOrgName, "OrdererMSP",
                    Util.findFileSk(Paths.get("src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/keystore/").toFile()),
                    Paths.get("src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/signcerts/Admin@example.com-cert.pem").toFile());

            client.setUserContext(ordererAdmin);

            //Ok now do actual channel update.
            fooChannel.updateChannelConfiguration(updateChannelConfiguration, client.getUpdateChannelConfigurationSignature(updateChannelConfiguration, ordererAdmin));

            //Let's add some additional verification...

            final byte[] modChannelBytes = fooChannel.getChannelConfigurationBytes();

            //Now decode the new channel config bytes to json...
            httppost = new HttpPost("http://localhost:7059/protolator/decode/common.Config");
            httppost.setEntity(new ByteArrayEntity(modChannelBytes));

            response = httpclient.execute(httppost);
            statuscode = response.getStatusLine().getStatusCode();
            assertEquals(200, statuscode);

            responseAsString = EntityUtils.toString(response.getEntity());

            if (!responseAsString.contains(UPDATED_BATCH_TIMEOUT)) {
                //If it doesn't have the updated time out it failed.
                fail(format("Did not find updated expected batch timeout '%s', in:%s", UPDATED_BATCH_TIMEOUT, responseAsString));
            }

            if (responseAsString.contains(ORIGINAL_BATCH_TIMEOUT)) { //Should not have been there anymore!

                fail(format("Found original batch timeout '%s', when it was not expected in:%s", ORIGINAL_BATCH_TIMEOUT, responseAsString));
            }

            out("\n");

            out("That's all folks!");

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    private Channel reconstructChannel(String name, HFClient client, SampleOrg sampleOrg) throws Exception {

        client.setUserContext(sampleOrg.getPeerAdmin());
        Channel newChannel = client.newChannel(name);

        for (String orderName : sampleOrg.getOrdererNames()) {
            newChannel.addOrderer(client.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName),
                    testConfig.getOrdererProperties(orderName)));
        }

        for (String peerName : sampleOrg.getPeerNames()) {
            String peerLocation = sampleOrg.getPeerLocation(peerName);
            Peer peer = client.newPeer(peerName, peerLocation, testConfig.getPeerProperties(peerName));

            //Query the actual peer for which channels it belongs to and check it belongs to this channel
            Set<String> channels = client.queryChannels(peer);
            if (!channels.contains(name)) {
                throw new AssertionError(format("Peer %s does not appear to belong to channel %s", peerName, name));
            }

            newChannel.addPeer(peer);
            sampleOrg.addPeer(peer);
        }

        for (String eventHubName : sampleOrg.getEventHubNames()) {
            EventHub eventHub = client.newEventHub(eventHubName, sampleOrg.getEventHubLocation(eventHubName),
                    testConfig.getEventHubProperties(eventHubName));
            newChannel.addEventHub(eventHub);
        }

        newChannel.initialize();

        return newChannel;
    }

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

}
