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
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

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
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.QueuedBlockEvent;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.UpdateChannelConfiguration;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Update channel scenario
 * See http://hyperledger-fabric.readthedocs.io/en/master/configtxlator.html
 * for details.
 */
public class UpdateChannelIT {

    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final String CONFIGTXLATOR_LOCATION = testConfig.getFabricConfigTxLaterLocation();

    private static final String ORIGINAL_BATCH_TIMEOUT = "\"timeout\": \"2s\""; // Batch time out in configtx.yaml
    private static final String UPDATED_BATCH_TIMEOUT = "\"timeout\": \"5s\"";  // What we want to change it to.

    private static final String FOO_CHANNEL_NAME = "foo";
    private static final String PEER_0_ORG_1_EXAMPLE_COM_7051 = "peer0.org1.example.com:7051";
    private static final String REGX_S_HOST_PEER_0_ORG_1_EXAMPLE_COM = "(?s).*\"host\":[ \t]*\"peer0\\.org1\\.example\\.com\".*";
    private static final String REGX_S_ANCHOR_PEERS = "(?s).*\"*AnchorPeers\":[ \t]*\\{.*";

    private final TestConfigHelper configHelper = new TestConfigHelper();

    private Collection<SampleOrg> testSampleOrgs;

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException {

        out("\n\n\nRUNNING: UpdateChannelIT\n");
        resetConfig();
        configHelper.customizeConfig();
//        assertEquals(256, Config.getConfig().getSecurityLevel());

        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
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
            byte[] channelConfigurationBytes = fooChannel.getChannelConfigurationBytes();

            HttpClient httpclient = HttpClients.createDefault();
//            HttpPost httppost = new HttpPost(CONFIGTXLATOR_LOCATION + "/protolator/decode/common.Config");
//            httppost.setEntity(new ByteArrayEntity(channelConfigurationBytes));

            String responseAsString = configTxlatorDecode(httpclient, channelConfigurationBytes);

            //responseAsString is JSON but use just string operations for this test.

            if (!responseAsString.contains(ORIGINAL_BATCH_TIMEOUT)) {

                fail(format("Did not find expected batch timeout '%s', in:%s", ORIGINAL_BATCH_TIMEOUT, responseAsString));
            }

            //Now modify the batch timeout
            String updateString = responseAsString.replace(ORIGINAL_BATCH_TIMEOUT, UPDATED_BATCH_TIMEOUT);

            HttpPost httppost = new HttpPost(CONFIGTXLATOR_LOCATION + "/protolator/encode/common.Config");
            httppost.setEntity(new StringEntity(updateString));

            HttpResponse response = httpclient.execute(httppost);

            int statuscode = response.getStatusLine().getStatusCode();
            out("Got %s status for encoding the new desired channel config bytes", statuscode);
            assertEquals(200, statuscode);
            byte[] newConfigBytes = EntityUtils.toByteArray(response.getEntity());

            // Now send to configtxlator multipart form post with original config bytes, updated config bytes and channel name.
            httppost = new HttpPost(CONFIGTXLATOR_LOCATION + "/configtxlator/compute/update-from-configs");

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
                    Util.findFileSk(Paths.get("src/test/fixture/sdkintegration/e2e-2Orgs/" + testConfig.getFabricConfigGenVers() + "/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/keystore/").toFile()),
                    Paths.get("src/test/fixture/sdkintegration/e2e-2Orgs/" + testConfig.getFabricConfigGenVers() + "/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/signcerts/Admin@example.com-cert.pem").toFile());

            client.setUserContext(ordererAdmin);

            //Ok now do actual channel update.
            fooChannel.updateChannelConfiguration(updateChannelConfiguration, client.getUpdateChannelConfigurationSignature(updateChannelConfiguration, ordererAdmin));

            Thread.sleep(3000); // give time for events to happen

            //Let's add some additional verification...

            client.setUserContext(sampleOrg.getPeerAdmin());

            final byte[] modChannelBytes = fooChannel.getChannelConfigurationBytes();

            responseAsString = configTxlatorDecode(httpclient, modChannelBytes);

            if (!responseAsString.contains(UPDATED_BATCH_TIMEOUT)) {
                //If it doesn't have the updated time out it failed.
                fail(format("Did not find updated expected batch timeout '%s', in:%s", UPDATED_BATCH_TIMEOUT, responseAsString));
            }

            if (responseAsString.contains(ORIGINAL_BATCH_TIMEOUT)) { //Should not have been there anymore!

                fail(format("Found original batch timeout '%s', when it was not expected in:%s", ORIGINAL_BATCH_TIMEOUT, responseAsString));
            }

            assertTrue(eventCountFilteredBlock > 0); // make sure we got blockevent that were tested.updateChannelConfiguration
            assertTrue(eventCountBlock > 0); // make sure we got blockevent that were tested.

            //Should be no anchor peers defined.
            assertFalse(responseAsString.matches(REGX_S_HOST_PEER_0_ORG_1_EXAMPLE_COM));
            assertFalse(responseAsString.matches(REGX_S_ANCHOR_PEERS));

            // Get config update for adding an anchor peer.
            Channel.AnchorPeersConfigUpdateResult configUpdateAnchorPeers = fooChannel.getConfigUpdateAnchorPeers(fooChannel.getPeers().iterator().next(), sampleOrg.getPeerAdmin(),
                    Arrays.asList(PEER_0_ORG_1_EXAMPLE_COM_7051), null);

            assertNotNull(configUpdateAnchorPeers.getUpdateChannelConfiguration());
            assertTrue(configUpdateAnchorPeers.getPeersAdded().contains(PEER_0_ORG_1_EXAMPLE_COM_7051));

            //Now add anchor peer to channel configuration.
            fooChannel.updateChannelConfiguration(configUpdateAnchorPeers.getUpdateChannelConfiguration(),
                    client.getUpdateChannelConfigurationSignature(configUpdateAnchorPeers.getUpdateChannelConfiguration(), sampleOrg.getPeerAdmin()));
            Thread.sleep(3000); // give time for events to happen

            // Getting foo channels current configuration bytes to check with configtxlator
            channelConfigurationBytes = fooChannel.getChannelConfigurationBytes();
            responseAsString = configTxlatorDecode(httpclient, channelConfigurationBytes);

            // Check is anchor peer in config block?
            assertTrue(responseAsString.matches(REGX_S_HOST_PEER_0_ORG_1_EXAMPLE_COM));
            assertTrue(responseAsString.matches(REGX_S_ANCHOR_PEERS));

            //Should see what's there.
            configUpdateAnchorPeers = fooChannel.getConfigUpdateAnchorPeers(fooChannel.getPeers().iterator().next(), sampleOrg.getPeerAdmin(),
                    null, null);

            assertNull(configUpdateAnchorPeers.getUpdateChannelConfiguration()); // not updating anything.
            assertTrue(configUpdateAnchorPeers.getCurrentPeers().contains(PEER_0_ORG_1_EXAMPLE_COM_7051)); // peer should   be there.
            assertTrue(configUpdateAnchorPeers.getPeersRemoved().isEmpty()); // not removing any
            assertTrue(configUpdateAnchorPeers.getPeersAdded().isEmpty()); // not adding anything.
            assertTrue(configUpdateAnchorPeers.getUpdatedPeers().isEmpty()); // not updating anyting.

            //Now remove the anchor peer -- get the config update block.
            configUpdateAnchorPeers = fooChannel.getConfigUpdateAnchorPeers(fooChannel.getPeers().iterator().next(), sampleOrg.getPeerAdmin(),
                    null, Arrays.asList(PEER_0_ORG_1_EXAMPLE_COM_7051));

            assertNotNull(configUpdateAnchorPeers.getUpdateChannelConfiguration());
            assertTrue(configUpdateAnchorPeers.getCurrentPeers().contains(PEER_0_ORG_1_EXAMPLE_COM_7051)); // peer should still be there.
            assertTrue(configUpdateAnchorPeers.getPeersRemoved().contains(PEER_0_ORG_1_EXAMPLE_COM_7051)); // peer to remove.
            assertTrue(configUpdateAnchorPeers.getPeersAdded().isEmpty()); // not adding anything.
            assertTrue(configUpdateAnchorPeers.getUpdatedPeers().isEmpty());  // no peers should be left.

            // Now do the actual update.
            fooChannel.updateChannelConfiguration(configUpdateAnchorPeers.getUpdateChannelConfiguration(),
                    client.getUpdateChannelConfigurationSignature(configUpdateAnchorPeers.getUpdateChannelConfiguration(), sampleOrg.getPeerAdmin()));
            Thread.sleep(3000); // give time for events to happen
            // Getting foo channels current configuration bytes to check with configtxlator.
            channelConfigurationBytes = fooChannel.getChannelConfigurationBytes();
            responseAsString = configTxlatorDecode(httpclient, channelConfigurationBytes);

            assertFalse(responseAsString.matches(REGX_S_HOST_PEER_0_ORG_1_EXAMPLE_COM)); // should be gone!
            assertTrue(responseAsString.matches(REGX_S_ANCHOR_PEERS)); //ODDLY we still want this even if it's empty!

            //Should see what's there.
            configUpdateAnchorPeers = fooChannel.getConfigUpdateAnchorPeers(fooChannel.getPeers().iterator().next(), sampleOrg.getPeerAdmin(),
                    null, null);

            // processing of queued blocks should be done on a separate thread and processed relatively quickly to avoid queues from becoming full,
            // But we're just testing/demoing here.
            assertEquals(3, fooChannel.getBlockListenerHandles().size());  // 1 event type block listener and 2 queued type.
            fooChannel.unregisterBlockListener(listenerHandler1);
            fooChannel.unregisterBlockListener(listenerHandler2);
            assertEquals(1, fooChannel.getBlockListenerHandles().size()); // now there's only one.

            assertEquals(8, blockingQueue1.size());
            assertEquals(8, blockingQueue2.size());
            assertEquals(8, eventQueueCaputure.size());

            Collection<QueuedBlockEvent> drain1 = new ArrayList<>();
            blockingQueue1.drainTo(drain1);
            Collection<? super QueuedBlockEvent> drain2 = new ArrayList<>();
            blockingQueue2.drainTo(drain2);

            Collection<? super BlockEvent> eventQDrain = new ArrayList<>();
            eventQueueCaputure.drainTo(eventQDrain);

            QueuedBlockEvent[] drain1Array = drain1.toArray(new QueuedBlockEvent[drain1.size()]);
            QueuedBlockEvent[] drain2Array = drain2.toArray(new QueuedBlockEvent[drain2.size()]);
            BlockEvent[] drainEventQArray = eventQDrain.toArray(new BlockEvent[eventQDrain.size()]);

            for (int i = drain1Array.length - 1; i > -1; --i) {
                final long blockNumber = drain1Array[i].getBlockEvent().getBlockNumber();
                final String url = drain1Array[i].getBlockEvent().getPeer().getUrl();

                assertEquals(blockNumber, drain2Array[i].getBlockEvent().getBlockNumber());
                assertEquals(url, drain2Array[i].getBlockEvent().getPeer().getUrl());
                assertEquals(blockNumber, drainEventQArray[i].getBlockNumber());
                assertEquals(url, drainEventQArray[i].getPeer().getUrl());
            }

            assertNull(configUpdateAnchorPeers.getUpdateChannelConfiguration()); // not updating anything.
            assertTrue(configUpdateAnchorPeers.getCurrentPeers().isEmpty()); // peer should be now gone.
            assertTrue(configUpdateAnchorPeers.getPeersRemoved().isEmpty()); // not removing any
            assertTrue(configUpdateAnchorPeers.getPeersAdded().isEmpty()); // not adding anything.
            assertTrue(configUpdateAnchorPeers.getUpdatedPeers().isEmpty());  // no peers should be left

            out("That's all folks!");

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    private String configTxlatorDecode(HttpClient httpclient, byte[] channelConfigurationBytes) throws IOException {
        HttpPost httppost = new HttpPost(CONFIGTXLATOR_LOCATION + "/protolator/decode/common.Config");
        httppost.setEntity(new ByteArrayEntity(channelConfigurationBytes));

        HttpResponse response = httpclient.execute(httppost);
        int statuscode = response.getStatusLine().getStatusCode();
        //  out("Got %s status for decoding current channel config bytes", statuscode);
        assertEquals(200, statuscode);
        return EntityUtils.toString(response.getEntity());
    }

    int eventCountFilteredBlock = 0;
    int eventCountBlock = 0;

    private Channel reconstructChannel(String name, HFClient client, SampleOrg sampleOrg) throws Exception {

        client.setUserContext(sampleOrg.getPeerAdmin());
        Channel newChannel = client.newChannel(name);

        for (String orderName : sampleOrg.getOrdererNames()) {
            newChannel.addOrderer(client.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName),
                    testConfig.getOrdererProperties(orderName)));
        }

        assertTrue(sampleOrg.getPeerNames().size() > 1); // need at least two for testing.

        int i = 0;
        for (String peerName : sampleOrg.getPeerNames()) {
            String peerLocation = sampleOrg.getPeerLocation(peerName);
            Peer peer = client.newPeer(peerName, peerLocation, testConfig.getPeerProperties(peerName));

            //Query the actual peer for which channels it belongs to and check it belongs to this channel
            Set<String> channels = client.queryChannels(peer);
            if (!channels.contains(name)) {
                throw new AssertionError(format("Peer %s does not appear to belong to channel %s", peerName, name));
            }
            Channel.PeerOptions peerOptions = createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.CHAINCODE_QUERY,
                    Peer.PeerRole.ENDORSING_PEER, Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.EVENT_SOURCE));

            if (i % 2 == 0) {
                peerOptions.registerEventsForFilteredBlocks(); // we need a mix of each type for testing.
            } else {
                peerOptions.registerEventsForBlocks();
            }
            ++i;

            newChannel.addPeer(peer, peerOptions);
        }

        //For testing of blocks which are not transactions.
        newChannel.registerBlockListener(blockEvent -> {
            eventQueueCaputure.add(blockEvent); // used with the other queued to make sure same.
            // Note peer eventing will always start with sending the last block so this will get the last endorser block
            int transactions = 0;
            int nonTransactions = 0;
            for (BlockInfo.EnvelopeInfo envelopeInfo : blockEvent.getEnvelopeInfos()) {

                if (BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE == envelopeInfo.getType()) {
                    ++transactions;
                } else {
                    assertEquals(BlockInfo.EnvelopeType.ENVELOPE, envelopeInfo.getType());
                    ++nonTransactions;
                }

            }
            assertTrue(format("nontransactions %d, transactions %d", nonTransactions, transactions), nonTransactions < 2); // non transaction blocks only have one envelope
            assertTrue(format("nontransactions %d, transactions %d", nonTransactions, transactions), nonTransactions + transactions > 0); // has to be one.
            assertFalse(format("nontransactions %d, transactions %d", nonTransactions, transactions), nonTransactions > 0 && transactions > 0); // can't have both.

            if (nonTransactions > 0) { // this is an update block -- don't care about others here.

                if (blockEvent.isFiltered()) {
                    ++eventCountFilteredBlock; // make sure we're seeing non transaction events.
                } else {
                    ++eventCountBlock;
                }
                assertEquals(0, blockEvent.getTransactionCount());
                assertEquals(1, blockEvent.getEnvelopeCount());
                for (TransactionEvent transactionEvent : blockEvent.getTransactionEvents()) {
                    fail("Got transaction event in a block update"); // only events for update should not have transactions.
                }
            }
        });

        // Register Queued block listeners just for testing use both ways.
        // Ideally an application would have it's own independent thread to monitor and take off elements as fast as they can.
        // This would wait forever however if event could not be put in the queue like if the capacity is at a maximum. For LinkedBlockingQueue so unlikely
        listenerHandler1 = newChannel.registerBlockListener(blockingQueue1);
        assertNotNull(listenerHandler1);
        // This is the same but put a timeout on it.  If its not queued in time like if the queue is full it would generate a log warning and ignore the event.
        listenerHandler2 = newChannel.registerBlockListener(blockingQueue2, 1L, TimeUnit.SECONDS);
        assertNotNull(listenerHandler2);

        newChannel.initialize();

        return newChannel;
    }

    // Handles to unregister handlers.
    String listenerHandler1;
    String listenerHandler2;

    BlockingQueue<QueuedBlockEvent> blockingQueue1 = new LinkedBlockingQueue<>(); // really this is unbounded.
    BlockingQueue<QueuedBlockEvent> blockingQueue2 = new ArrayBlockingQueue<>(1000); // application should  pull off queue so not to go full.

    // Have the event handler put into this queue so we can compare.
    BlockingQueue<BlockEvent> eventQueueCaputure = new LinkedBlockingQueue<>();

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

}
