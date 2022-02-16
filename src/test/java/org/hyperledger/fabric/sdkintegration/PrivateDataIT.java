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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.hyperledger.fabric.protos.ledger.rwset.Rwset;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.BlockchainInfo;
import org.hyperledger.fabric.sdk.ChaincodeCollectionConfiguration;
import org.hyperledger.fabric.sdk.ChaincodeEvent;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.ChaincodeResponse.Status;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.CollectionConfigPackage;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test end to end scenario
 */
public class PrivateDataIT {

    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final int DEPLOYWAITTIME = testConfig.getDeployWaitTime();

    private static final boolean IS_FABRIC_V10 = testConfig.isRunningAgainstFabric10();
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TESTUSER_1_NAME = "user1";

    private static final String BAR_CHANNEL_NAME = "bar";
    private final TestConfigHelper configHelper = new TestConfigHelper();
    SampleStore sampleStore;
    private Collection<SampleOrg> testSampleOrgs;

    String testName = "PrivateDataIT";

    //src/test/fixture/sdkintegration/gocc/samplePrivateData/src/github.com/private_data_cc/private_data_cc.go
    Path CHAIN_CODE_FILEPATH = IntegrationSuite.getGoChaincodePath("samplePrivateData");
    String CHAIN_CODE_NAME = "private_data_cc1_go";
    String CHAIN_CODE_PATH = "github.com/private_data_cc";

    String CHAIN_CODE_VERSION = "1";
    TransactionRequest.Type CHAIN_CODE_LANG = TransactionRequest.Type.GO_LANG;

    ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
            .setVersion(CHAIN_CODE_VERSION)
            .setPath(CHAIN_CODE_PATH).build();

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException {

        out("\n\n\nRUNNING: %s.\n", testName);

        //      configHelper.clearConfig();
        resetConfig();
        configHelper.customizeConfig();
        //      assertEquals(256, Config.getConfig().getSecurityLevel());

        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        //Set up hfca for each sample org

        for (SampleOrg sampleOrg : testSampleOrgs) {
            String caURL = sampleOrg.getCALocation();
            sampleOrg.setCAClient(HFCAClient.createNewInstance(caURL, null));
        }
    }

    File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");

    @Test
    public void setup() throws Exception {

        try {

            sampleStore = new SampleStore(sampleStoreFile);

            setupUsers(sampleStore);
            runFabricTest(sampleStore);

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    /**
     * Will register and enroll users persisting them to samplestore.
     *
     * @param sampleStore
     * @throws Exception
     */
    public void setupUsers(SampleStore sampleStore) {
        //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface

        ////////////////////////////
        // get users for all orgs
        for (SampleOrg sampleOrg : testSampleOrgs) {
            final String orgName = sampleOrg.getName();

            SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
            sampleOrg.setAdmin(admin); // The admin of this org.

            // No need to enroll or register all done in End2endIt !
            SampleUser user = sampleStore.getMember(TESTUSER_1_NAME, orgName);
            sampleOrg.addUser(user);  //Remember user belongs to this Org

            sampleOrg.setPeerAdmin(sampleStore.getMember(orgName + "Admin", orgName));
        }
    }

    public void runFabricTest(final SampleStore sampleStore) throws Exception {
        ////////////////////////////
        // Setup client

        //Create instance of client.
        HFClient client = HFClient.createNewInstance();

        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        client.setUserContext(sampleStore.getMember(TEST_ADMIN_NAME, "peerOrg2"));

        SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg2");

        Channel barChannel = sampleStore.getChannel(client, BAR_CHANNEL_NAME);

        barChannel.initialize();
        runChannel(client, barChannel, sampleOrg, 10);
        assertFalse(barChannel.isShutdown());
        assertTrue(barChannel.isInitialized());

        if (testConfig.isFabricVersionAtOrAfter("1.3")) {
            Set<String> expect = new HashSet<>(Arrays.asList("COLLECTION_FOR_A", "COLLECTION_FOR_B"));
            Set<String> got = new HashSet<>();

            CollectionConfigPackage queryCollectionsConfig = barChannel.queryCollectionsConfig(CHAIN_CODE_NAME, barChannel.getPeers().iterator().next(), sampleOrg.getPeerAdmin());
            for (CollectionConfigPackage.CollectionConfig collectionConfig : queryCollectionsConfig.getCollectionConfigs()) {
                got.add(collectionConfig.getName());

            }
            assertEquals(expect, got);

            byte[] replayChannelBytes = barChannel.serializeChannel();
            barChannel.shutdown(true);

            Channel replayChannel = client.deSerializeChannel(replayChannelBytes);
            out("doing testPeerServiceEventingReplay,0,-1");
            testPeerServiceEventingReplay(client, replayChannel, 0L, -1L, expect);

            //Now do it again starting at block 1
            replayChannel = client.deSerializeChannel(replayChannelBytes);
            out("doing testPeerServiceEventingReplay,1,-1");
            testPeerServiceEventingReplay(client, replayChannel, 1L, -1L, expect);

            //Now do it again starting at block 2 to 3
            replayChannel = client.deSerializeChannel(replayChannelBytes);
            out("doing testPeerServiceEventingReplay,2,3");
            testPeerServiceEventingReplay(client, replayChannel, 2L, 3L, expect);
        }

        out("That's all folks!");
    }

    // Disable MethodLength as this method is for instructional purposes and hence
    // we don't want to split it into smaller pieces
    // CHECKSTYLE:OFF: MethodLength
    void runChannel(HFClient client, Channel channel, SampleOrg sampleOrg, final int delta) {
        final String channelName = channel.getName();

        try {

            client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));

            out("Running Channel %s with a delta %d", channelName, delta);

            out("ChaincodeID: ", chaincodeID);

            client.setUserContext(sampleOrg.getPeerAdmin());
            ///////////////
            ////
            InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
            installProposalRequest.setChaincodeID(chaincodeID);
            ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
            installProposalRequest.setChaincodeSourceLocation(CHAIN_CODE_FILEPATH.toFile());
            installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);
            installProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
            installProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);

            out("Sending install proposal for channel: %s", channel.getName());

            ////////////////////////////
            // only a client from the same org as the peer can issue an install request
            int numInstallProposal = 0;

            Collection<ProposalResponse> responses;
            final Collection<ProposalResponse> successful = new LinkedList<>();
            final Collection<ProposalResponse> failed = new LinkedList<>();
            Collection<Peer> peersFromOrg = channel.getPeers();
            numInstallProposal = numInstallProposal + peersFromOrg.size();

            responses = client.sendInstallProposal(installProposalRequest, peersFromOrg);

            for (ProposalResponse response : responses) {
                if (response.getStatus() == Status.SUCCESS) {
                    out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                    successful.add(response);
                } else {
                    failed.add(response);
                }
            }

            out("Received %d install proposal responses. Successful+verified: %d . Failed: %d", numInstallProposal, successful.size(), failed.size());

            if (failed.size() > 0) {
                ProposalResponse first = failed.iterator().next();
                fail("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
            }

            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setChaincodeID(chaincodeID);
            instantiateProposalRequest.setProposalWaitTime(DEPLOYWAITTIME);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs(new String[] {});
            instantiateProposalRequest.setChaincodeCollectionConfiguration(ChaincodeCollectionConfiguration.fromYamlFile(new File("src/test/fixture/collectionProperties/PrivateDataIT.yaml")));

            out("Sending instantiate proposal");

            Collection<ProposalResponse> responses2;

            responses2 = channel.sendInstantiationProposal(instantiateProposalRequest);

            successful.clear();
            failed.clear();
            for (ProposalResponse response : responses2) {
                if (response.getStatus() == Status.SUCCESS) {
                    out("Successful upgrade proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                    successful.add(response);
                } else {
                    failed.add(response);
                }
            }

            out("Received %d upgrade proposal responses. Successful+verified: %d . Failed: %d", channel.getPeers().size(), successful.size(), failed.size());

            if (failed.size() > 0) {
                ProposalResponse first = failed.iterator().next();
                throw new AssertionError("Not enough endorsers for upgrade :"
                        + successful.size() + ".  " + first.getMessage());
            }

            out("Sending instantiate proposal to orderer.");
            channel.sendTransaction(successful, sampleOrg.getPeerAdmin()).thenApply(transactionEvent -> {
                try {
                    out("instantiate proposal completed.");

                    //Now lets run the new chaincode which should *double* the results we asked to move.
                    // return setAmount(client, channel, chaincodeID, "50", null).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
                    return setAmount(client, channel, chaincodeID, 50, null).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
                } catch (CompletionException e) {
                    return e;
                } catch (Exception e) {
                    return new CompletionException(e);
                }
            }).thenApply(transactionEvent -> {

                try {
                    out("Got back acknowledgement from setAmount from all peers.");
                    waitOnFabric(10000);

                    //  Thread.sleep(8000);

                    ///Check if we still get the same value on the ledger
                    out("delta is %s", delta);
                    queryChaincodeForExpectedValue(client, channel, "" + (250), chaincodeID);

                    //Now lets run the new chaincode which should *double* the results we asked to move.
                    return moveAmount(client, channel, chaincodeID, "50", null).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
                } catch (CompletionException e) {
                    return e;
                } catch (Exception e) {
                    return new CompletionException(e);
                }

            }).exceptionally(e -> {
                if (e instanceof CompletionException && e.getCause() != null) {
                    e = e.getCause();
                }
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {

                        e.printStackTrace(System.err);
                        fail(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()));
                    }
                }

                e.printStackTrace(System.err);
                fail(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()));

                return null;
            }).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        queryChaincodeForExpectedValue(client, channel, "" + 300, chaincodeID);

        out("Running for Channel %s done", channelName);

    }

    CompletableFuture<BlockEvent.TransactionEvent> moveAmount(HFClient client, Channel channel, ChaincodeID chaincodeID, String moveAmount, User user) {

        try {
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();

            ///////////////
            /// Send transaction proposal to all peers
            TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
            transactionProposalRequest.setChaincodeID(chaincodeID);
            transactionProposalRequest.setFcn("move");

            // Private data needs to be sent via Transient field to prevent identifiable
            //information being sent to the orderer.
            Map<String, byte[]> transientMap = new HashMap<>();
            transientMap.put("A", "a".getBytes(UTF_8)); //test using bytes .. end2end uses Strings.
            transientMap.put("B", "b".getBytes(UTF_8));
            transientMap.put("moveAmount", moveAmount.getBytes(UTF_8));
            transactionProposalRequest.setTransientMap(transientMap);

            transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
            if (user != null) { // specific user use that
                transactionProposalRequest.setUserContext(user);
            }
            out("sending transaction proposal to all peers with arguments: move(a,b,%s)", moveAmount);

            Collection<ProposalResponse> invokePropResp = channel.sendTransactionProposal(transactionProposalRequest);
            for (ProposalResponse response : invokePropResp) {
                if (response.getStatus() == Status.SUCCESS) {
                    out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                    successful.add(response);
                } else {
                    failed.add(response);
                }
            }

            out("Received %d transaction proposal responses for moveAmount. Successful+verified: %d . Failed: %d",
                    invokePropResp.size(), successful.size(), failed.size());
            if (failed.size() > 0) {
                ProposalResponse firstTransactionProposalResponse = failed.iterator().next();

                throw new ProposalException(format("Not enough endorsers for invoke(move a,b,%s):%d endorser error:%s. Was verified:%b",
                        moveAmount, firstTransactionProposalResponse.getStatus().getStatus(), firstTransactionProposalResponse.getMessage(), firstTransactionProposalResponse.isVerified()));

            }
            out("Successfully received transaction proposal responses.");

            ////////////////////////////
            // Send transaction to orderer
            out("Sending chaincode transaction(move a,b,%s) to orderer.", moveAmount);
            if (user != null) {
                return channel.sendTransaction(successful, user);
            }
            return channel.sendTransaction(successful);
        } catch (Exception e) {

            throw new CompletionException(e);

        }

    }

    CompletableFuture<BlockEvent.TransactionEvent> setAmount(HFClient client, Channel channel, ChaincodeID chaincodeID, int delta, User user) {

        try {
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();

            ///////////////
            /// Send transaction proposal to all peers
            TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
            transactionProposalRequest.setChaincodeID(chaincodeID);
            transactionProposalRequest.setFcn("set");

            Map<String, byte[]> transientMap = new HashMap<>();
            transientMap.put("A", "a".getBytes(UTF_8));   // test using bytes as args. End2end uses Strings.
            transientMap.put("AVal", "500".getBytes(UTF_8));
            transientMap.put("B", "b".getBytes(UTF_8));
            String arg3 = "" + (200 + delta);
            transientMap.put("BVal", arg3.getBytes(UTF_8));
            transactionProposalRequest.setTransientMap(transientMap);

            transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
            if (user != null) { // specific user use that
                transactionProposalRequest.setUserContext(user);
            }

            Collection<ProposalResponse> invokePropResp = channel.sendTransactionProposal(transactionProposalRequest);
            for (ProposalResponse response : invokePropResp) {
                if (response.getStatus() == Status.SUCCESS) {
                    out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                    successful.add(response);
                } else {
                    failed.add(response);
                }
            }

            out("Received %d transaction proposal responses for setAmount. Successful+verified: %d . Failed: %d",
                    invokePropResp.size(), successful.size(), failed.size());
            if (failed.size() > 0) {
                ProposalResponse firstTransactionProposalResponse = failed.iterator().next();

                throw new ProposalException(format("Not enough endorsers for set(move a,b,%s):%d endorser error:%s. Was verified:%b",
                        0, firstTransactionProposalResponse.getStatus().getStatus(), firstTransactionProposalResponse.getMessage(), firstTransactionProposalResponse.isVerified()));

            }
            out("Successfully received transaction proposal responses for setAmount. Now sending to orderer.");

            ////////////////////////////
            // Send transaction to orderer

            if (user != null) {
                return channel.sendTransaction(successful, user);
            }
            return channel.sendTransaction(successful);
        } catch (Exception e) {

            throw new CompletionException(e);

        }

    }

    /**
     * This code test the replay feature of the new peer event services.
     * Instead of the default of starting the eventing peer to retrieve the newest block it sets it
     * retrieve starting from the start parameter.
     *
     * @param client hlf client that con connect to the Fabric network
     * @param replayTestChannel channel object to subscribe and replay events
     * @param start index from where block events are to be read
     * @param stop index upto where the block events are to be read
     * @throws InvalidArgumentException in case of an error.
     */
    private void testPeerServiceEventingReplay(HFClient client, Channel replayTestChannel, final long start, final long stop, Set<String> collections) throws InvalidArgumentException {

        assertFalse(replayTestChannel.isInitialized()); //not yet initialized
        assertFalse(replayTestChannel.isShutdown()); // not yet shutdown.

        //Remove all peers just have one ledger peer and one eventing peer.
        List<Peer> savedPeers = new ArrayList<>(replayTestChannel.getPeers());
        for (Peer peer : savedPeers) {
            replayTestChannel.removePeer(peer);
        }
        assertTrue(savedPeers.size() > 1); //need at least two
        Peer eventingPeer = savedPeers.remove(0);
        eventingPeer = client.newPeer(eventingPeer.getName(), eventingPeer.getUrl(), eventingPeer.getProperties());
        Peer ledgerPeer = savedPeers.remove(0);
        ledgerPeer = client.newPeer(ledgerPeer.getName(), ledgerPeer.getUrl(), ledgerPeer.getProperties());

        assertTrue(replayTestChannel.getPeers().isEmpty()); // no more peers.
        assertTrue(replayTestChannel.getPeers(EnumSet.of(Peer.PeerRole.CHAINCODE_QUERY, Peer.PeerRole.ENDORSING_PEER)).isEmpty()); // just checking :)
        assertTrue(replayTestChannel.getPeers(EnumSet.of(Peer.PeerRole.LEDGER_QUERY)).isEmpty()); // just checking

        assertNotNull(client.getChannel(replayTestChannel.getName())); // should be known by client.

        // Register for receiving blocks with the private data
        final Channel.PeerOptions eventingPeerOptions = createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.EVENT_SOURCE));
        eventingPeerOptions.registerEventsForPrivateData();

        if (-1L == stop) { //the height of the blockchain

            replayTestChannel.addPeer(eventingPeer, eventingPeerOptions.startEvents(start)); // Eventing peer start getting blocks from block 0
        } else {
            replayTestChannel.addPeer(eventingPeer, eventingPeerOptions
                    .startEvents(start).stopEvents(stop)); // Eventing peer start getting blocks from block 0
        }
        //add a ledger peer
        replayTestChannel.addPeer(ledgerPeer, createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.LEDGER_QUERY)));

        CompletableFuture<Long> done = new CompletableFuture<>(); // future to set when done.
        // some variable used by the block listener being set up.
        final AtomicLong bcount = new AtomicLong(0);
        final AtomicLong stopValue = new AtomicLong(stop == -1L ? Long.MAX_VALUE : stop);
        final Channel finalChannel = replayTestChannel;

        final Map<Long, BlockEvent> blockEvents = Collections.synchronizedMap(new HashMap<>(100));

        final String blockListenerHandle = replayTestChannel.registerBlockListener(blockEvent -> { // register a block listener

            try {
                final long blockNumber = blockEvent.getBlockNumber();
                BlockEvent seen = blockEvents.put(blockNumber, blockEvent);
                assertNull(format("Block number %d seen twice", blockNumber), seen);

                assertEquals(format("Wrong type of block seen block number %d. expected block with private data but got %s",
                                blockNumber, blockEvent.getType()), BlockInfo.Type.BLOCK_WITH_PRIVATE_DATA, blockEvent.getType());
                final long count = bcount.getAndIncrement(); //count starts with 0 not 1 !

                if (count == 0 && stop == -1L) {
                    final BlockchainInfo blockchainInfo = finalChannel.queryBlockchainInfo();

                    long lh = blockchainInfo.getHeight();
                    stopValue.set(lh - 1L);  // blocks 0L 9L are on chain height 10 .. stop on 9
                    if (bcount.get() + start > stopValue.longValue()) { // test with latest count.
                        done.complete(bcount.get()); // report back latest count.
                    }

                } else {
                    if (bcount.longValue() + start > stopValue.longValue()) {
                        done.complete(count);
                    }
                }
            } catch (AssertionError | Exception e) {
                e.printStackTrace();
                done.completeExceptionally(e);
            }

        });

        try {
            replayTestChannel.initialize(); // start it all up.
            done.get(30, TimeUnit.SECONDS); // give a timeout here.
            Thread.sleep(1000); // sleep a little to see if more blocks trickle in .. they should not
            replayTestChannel.unregisterBlockListener(blockListenerHandle);

            final long expectNumber = stopValue.longValue() - start + 1L; // Start 2 and stop is 3  expect 2

            assertEquals(format("Didn't get number we expected %d but got %d block events. Start: %d, end: %d, height: %d",
                    expectNumber, blockEvents.size(), start, stop, stopValue.longValue()), expectNumber, blockEvents.size());

            for (long i = stopValue.longValue(); i >= start; i--) { //make sure all are there.
                final BlockEvent blockEvent = blockEvents.get(i);
                assertNotNull(format("Missing block event for block number %d. Start= %d", i, start), blockEvent);
            }

            // lightweight test just see if we get reasonable values for traversing the block.

            int transactionEventCounts = 0;
            int chaincodeEventsCounts = 0;

            for (long i = stopValue.longValue(); i >= start; i--) {

                final BlockEvent blockEvent = blockEvents.get(i);
                assertEquals(BlockInfo.Type.BLOCK_WITH_PRIVATE_DATA, blockEvent.getType()); // check again

                assertNotNull(blockEvent.getBlock()); // should have block.
                assertNull(blockEvent.getFilteredBlock()); // should not have filtered block.
                assertNotNull(blockEvent.getBlockAndPrivateData()); // should have block and private data.
                Map<Long, Rwset.TxPvtReadWriteSet> privateDataMap = blockEvent.getBlockAndPrivateData().getPrivateDataMapMap();
                assertNotNull(privateDataMap); // should have private data

                // get all the collections from the privateDataMap
                // collection should be set already
                for (Map.Entry<Long, Rwset.TxPvtReadWriteSet> privateData : privateDataMap.entrySet()) {
                    Rwset.TxPvtReadWriteSet pvtReadWriteSet = privateData.getValue();
                    for (Rwset.NsPvtReadWriteSet nsPvtReadWriteSet : pvtReadWriteSet.getNsPvtRwsetList()) {
                        for (Rwset.CollectionPvtReadWriteSet pvtReadWriteSet1 : nsPvtReadWriteSet.getCollectionPvtRwsetList()) {
                            assertTrue(collections.contains(pvtReadWriteSet1.getCollectionName()));
                        }
                    }
                }

                assertEquals(replayTestChannel.getName(), blockEvent.getChannelId());

                for (BlockInfo.EnvelopeInfo envelopeInfo : blockEvent.getEnvelopeInfos()) {
                    if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {

                        BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;
                        assertTrue(envelopeInfo.isValid()); // only have valid blocks.
                        assertEquals(envelopeInfo.getValidationCode(), 0);

                        ++transactionEventCounts;
                        for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo ta : transactionEnvelopeInfo.getTransactionActionInfos())  {
                            ChaincodeEvent event = ta.getEvent();
                            if (event != null) {
                                assertNotNull(event.getChaincodeId());
                                assertNotNull(event.getEventName());
                                chaincodeEventsCounts++;
                            }

                        }

                    } else {
                        assertEquals("Only non transaction block should be block 0.", blockEvent.getBlockNumber(), 0);

                    }

                }

            }

            assertTrue(transactionEventCounts > 0);

            if (expectNumber > 4) { // this should be enough blocks with CC events.

                assertTrue(chaincodeEventsCounts > 0);
            }

            replayTestChannel.shutdown(true); //all done.
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    private void queryChaincodeForExpectedValue(HFClient client, Channel channel, final String expect, ChaincodeID chaincodeID) {

        out("Now query chaincode %s on channel %s for the value of b expecting to see: %s", chaincodeID, channel.getName(), expect);
        Collection<ProposalResponse> queryProposals;
        try {
            QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
            queryByChaincodeRequest.setFcn("query");
            queryByChaincodeRequest.setChaincodeID(chaincodeID);

            Map<String, byte[]> tmap = new HashMap<>();
            tmap.put("B", "b".getBytes(UTF_8)); // test using bytes as args. End2end uses Strings.
            queryByChaincodeRequest.setTransientMap(tmap);

            queryProposals = channel.queryByChaincode(queryByChaincodeRequest);
        } catch (Exception e) {
            throw new CompletionException(e);
        }

        for (ProposalResponse proposalResponse : queryProposals) {
            if (!proposalResponse.isVerified() || proposalResponse.getStatus() != Status.SUCCESS) {
                fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                        ". Messages: " + proposalResponse.getMessage()
                        + ". Was verified : " + proposalResponse.isVerified());
            } else {
                String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                out("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                assertEquals(format("Failed compare on channel %s chaincode id %s expected value:'%s', but got:'%s'",
                        channel.getName(), chaincodeID, expect, payload), expect, payload);
            }
        }
    }

    private void waitOnFabric() {

        waitOnFabric(0);
    }

    ///// NO OP ... leave in case it's needed.
    private void waitOnFabric(int additional) {

    }

}
