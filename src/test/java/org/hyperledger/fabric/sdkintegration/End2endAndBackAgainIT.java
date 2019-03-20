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

package org.hyperledger.fabric.sdkintegration;

import java.io.File;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.hyperledger.fabric.protos.common.Configtx;
import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.BlockchainInfo;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.ChaincodeEvent;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.ChaincodeResponse.Status;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.Channel.PeerOptions;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.UpgradeProposalRequest;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.testRemovingAddingPeersOrderers;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test end to end scenario
 */
public class End2endAndBackAgainIT {

    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final int DEPLOYWAITTIME = testConfig.getDeployWaitTime();
    private static final boolean IS_FABRIC_V10 = testConfig.isRunningAgainstFabric10();
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TESTUSER_1_NAME = "user1";
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private static final String FOO_CHANNEL_NAME = "foo";
    private static final String BAR_CHANNEL_NAME = "bar";
    private final TestConfigHelper configHelper = new TestConfigHelper();
    String testTxID = null;  // save the CC invoke TxID and use in queries
    SampleStore sampleStore;
    private Collection<SampleOrg> testSampleOrgs;

    String testName = "End2endAndBackAgainIT";

    String CHAIN_CODE_FILEPATH = "sdkintegration/gocc/sample_11";
    String CHAIN_CODE_NAME = "example_cc_go";
    String CHAIN_CODE_PATH = "github.com/example_cc";
    String CHAIN_CODE_VERSION_11 = "11";
    String CHAIN_CODE_VERSION = "1";
    TransactionRequest.Type CHAIN_CODE_LANG = TransactionRequest.Type.GO_LANG;

    ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
            .setVersion(CHAIN_CODE_VERSION)
            .setPath(CHAIN_CODE_PATH).build();
    ChaincodeID chaincodeID_11 = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
            .setVersion(CHAIN_CODE_VERSION_11)
            .setPath(CHAIN_CODE_PATH).build();

    private static boolean checkInstalledChaincode(HFClient client, Peer peer, String ccName, String ccPath, String ccVersion) throws InvalidArgumentException, ProposalException {

        out("Checking installed chaincode: %s, at version: %s, on peer: %s", ccName, ccVersion, peer.getName());
        List<ChaincodeInfo> ccinfoList = client.queryInstalledChaincodes(peer);

        boolean found = false;

        for (ChaincodeInfo ccifo : ccinfoList) {

            if (ccPath != null) {
                found = ccName.equals(ccifo.getName()) && ccPath.equals(ccifo.getPath()) && ccVersion.equals(ccifo.getVersion());
                if (found) {
                    break;
                }
            }

            found = ccName.equals(ccifo.getName()) && ccVersion.equals(ccifo.getVersion());
            if (found) {
                break;
            }

        }

        return found;
    }

    private static boolean checkInstantiatedChaincode(Channel channel, Peer peer, String ccName, String ccPath, String ccVersion) throws InvalidArgumentException, ProposalException {
        out("Checking instantiated chaincode: %s, at version: %s, on peer: %s", ccName, ccVersion, peer.getName());
        List<ChaincodeInfo> ccinfoList = channel.queryInstantiatedChaincodes(peer);

        boolean found = false;

        for (ChaincodeInfo ccifo : ccinfoList) {

            if (ccPath != null) {
                found = ccName.equals(ccifo.getName()) && ccPath.equals(ccifo.getPath()) && ccVersion.equals(ccifo.getVersion());
                if (found) {
                    break;
                }
            }

            found = ccName.equals(ccifo.getName()) && ccVersion.equals(ccifo.getVersion());
            if (found) {
                break;
            }

        }

        return found;
    }

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

        ////////////////////////////
        //Reconstruct and run the channels
        SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
        Channel fooChannel = reconstructChannel(FOO_CHANNEL_NAME, client, sampleOrg);
        runChannel(client, fooChannel, sampleOrg, 0);
        assertFalse(fooChannel.isShutdown());
        assertTrue(fooChannel.isInitialized());
        fooChannel.shutdown(true); //clean up resources no longer needed.
        assertTrue(fooChannel.isShutdown());
        out("\n");

        sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
        Channel barChannel = reconstructChannel(BAR_CHANNEL_NAME, client, sampleOrg);
        runChannel(client, barChannel, sampleOrg, 100); //run a newly constructed foo channel with different b value!
        assertFalse(barChannel.isShutdown());
        assertTrue(barChannel.isInitialized());

        if (!testConfig.isRunningAgainstFabric10()) { //Peer eventing service support started with v1.1

            // Now test replay feature of V1.1 peer eventing services.
            byte[] replayChannelBytes = barChannel.serializeChannel();
            barChannel.shutdown(true);

            Channel replayChannel = client.deSerializeChannel(replayChannelBytes);

            out("doing testPeerServiceEventingReplay,0,-1,false");
            testPeerServiceEventingReplay(client, replayChannel, 0L, -1L, false);

            replayChannel = client.deSerializeChannel(replayChannelBytes);
            out("doing testPeerServiceEventingReplay,0,-1,true"); // block 0 is import to test
            testPeerServiceEventingReplay(client, replayChannel, 0L, -1L, true);

            //Now do it again starting at block 1
            replayChannel = client.deSerializeChannel(replayChannelBytes);
            out("doing testPeerServiceEventingReplay,1,-1,false");
            testPeerServiceEventingReplay(client, replayChannel, 1L, -1L, false);

            //Now do it again starting at block 2 to 3
            replayChannel = client.deSerializeChannel(replayChannelBytes);
            out("doing testPeerServiceEventingReplay,2,3,false");
            testPeerServiceEventingReplay(client, replayChannel, 2L, 3L, false);

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

            //This is for testing only and can be ignored.
            testRemovingAddingPeersOrderers(client, channel);

//            final boolean changeContext = false; // BAR_CHANNEL_NAME.equals(channel.getName()) ? true : false;
            final boolean changeContext = BAR_CHANNEL_NAME.equals(channel.getName());

            out("Running Channel %s with a delta %d", channelName, delta);

            out("ChaincodeID: ", chaincodeID);
            ////////////////////////////
            // Send Query Proposal to all peers see if it's what we expect from end of End2endIT
            //
            queryChaincodeForExpectedValue(client, channel, "" + (300 + delta), chaincodeID);

            //Set user context on client but use explicit user contest on each call.
            if (changeContext) {
                client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));

            }

            // exercise v1 of chaincode

            moveAmount(client, channel, chaincodeID, "25", changeContext ? sampleOrg.getPeerAdmin() : null).thenApply((BlockEvent.TransactionEvent transactionEvent) -> {
                try {

                    waitOnFabric();
                    client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));

                    queryChaincodeForExpectedValue(client, channel, "" + (325 + delta), chaincodeID);

                    //////////////////
                    // Start of upgrade first must install it.

                    client.setUserContext(sampleOrg.getPeerAdmin());
                    ///////////////
                    ////
                    InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
                    installProposalRequest.setChaincodeID(chaincodeID);
                    ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
                    installProposalRequest.setChaincodeSourceLocation(Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());
                    installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION_11);
                    installProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
                    installProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);

                    if (changeContext) {
                        installProposalRequest.setUserContext(sampleOrg.getPeerAdmin());
                    }

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

                    //////////////////
                    // Upgrade chaincode to ***double*** our move results.

                    if (changeContext) {
                        installProposalRequest.setUserContext(sampleOrg.getPeerAdmin());
                    }

                    UpgradeProposalRequest upgradeProposalRequest = client.newUpgradeProposalRequest();
                    upgradeProposalRequest.setChaincodeID(chaincodeID_11);
                    upgradeProposalRequest.setProposalWaitTime(DEPLOYWAITTIME);
                    upgradeProposalRequest.setFcn("init");
                    upgradeProposalRequest.setArgs(new String[] {});    // no arguments don't change the ledger see chaincode.

                    ChaincodeEndorsementPolicy chaincodeEndorsementPolicy;

                    chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
                    chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));

                    upgradeProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
                    Map<String, byte[]> tmap = new HashMap<>();
                    tmap.put("test", "data".getBytes());
                    upgradeProposalRequest.setTransientMap(tmap);

                    if (changeContext) {
                        upgradeProposalRequest.setUserContext(sampleOrg.getPeerAdmin());
                    }

                    out("Sending upgrade proposal");

                    Collection<ProposalResponse> responses2;

                    responses2 = channel.sendUpgradeProposal(upgradeProposalRequest);

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

                    if (changeContext) {
                        return channel.sendTransaction(successful, sampleOrg.getPeerAdmin()).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

                    } else {

                        return channel.sendTransaction(successful).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

                    }

                } catch (CompletionException e) {
                    throw e;
                } catch (Exception e) {
                    throw new CompletionException(e);
                }

            }).thenApply(transactionEvent -> {
                try {
                    waitOnFabric(10000);

                    out("Chaincode has been upgraded to version %s", CHAIN_CODE_VERSION_11);

                    //Check to see if peers have new chaincode and old chaincode is gone.

                    client.setUserContext(sampleOrg.getPeerAdmin());
                    for (Peer peer : channel.getPeers()) {

                        if (!checkInstalledChaincode(client, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION_11)) {

                            fail(format("Peer %s is missing installed chaincode name:%s, path:%s, version: %s",
                                    peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION_11));

                        }

                        //should be instantiated too..
                        if (!checkInstantiatedChaincode(channel, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION_11)) {

                            fail(format("Peer %s is missing instantiated chaincode name:%s, path:%s, version: %s",
                                    peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION_11));

                        }

                        if (checkInstantiatedChaincode(channel, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {

                            fail(format("Peer %s still has old instantiated chaincode name:%s, path:%s, version: %s",
                                    peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION));
                        }

                    }

                    client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));

                    ///Check if we still get the same value on the ledger
                    out("delta is %s", delta);
                    queryChaincodeForExpectedValue(client, channel, "" + (325 + delta), chaincodeID);

                    //Now lets run the new chaincode which should *double* the results we asked to move.
                    return moveAmount(client, channel, chaincodeID_11, "50",
                            changeContext ? sampleOrg.getPeerAdmin() : null).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS); // really move 100
                } catch (CompletionException e) {
                    throw e;
                } catch (Exception e) {
                    throw new CompletionException(e);
                }

            }).thenApply(transactionEvent -> {

                waitOnFabric(10000);

                queryChaincodeForExpectedValue(client, channel, "" + (425 + delta), chaincodeID_11);

                return null;
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
            transactionProposalRequest.setArgs(new byte[][] {//test using bytes .. end2end uses Strings.
                    "a".getBytes(UTF_8), "b".getBytes(UTF_8), moveAmount.getBytes(UTF_8)});
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

            out("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
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

    private Channel reconstructChannel(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        out("Reconstructing %s channel", name);

        client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));

        Channel newChannel;

        if (BAR_CHANNEL_NAME.equals(name)) { // bar channel was stored in samplestore in End2endIT testcase.

            /**
             *  sampleStore.getChannel uses {@link HFClient#deSerializeChannel(byte[])}
             */
            newChannel = sampleStore.getChannel(client, name);

            if (!IS_FABRIC_V10) {
                // Make sure there is one of each type peer at the very least. see End2end for how peers were constructed.
                assertFalse(newChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty());
                assertFalse(newChannel.getPeers(PeerRole.NO_EVENT_SOURCE).isEmpty());

            }

            out("Retrieved channel %s from sample store.", name);

        } else {

            newChannel = client.newChannel(name);

            for (String ordererName : sampleOrg.getOrdererNames()) {
                newChannel.addOrderer(client.newOrderer(ordererName, sampleOrg.getOrdererLocation(ordererName),
                        testConfig.getOrdererProperties(ordererName)));
            }

            boolean everyOther = false;

            for (String peerName : sampleOrg.getPeerNames()) {
                String peerLocation = sampleOrg.getPeerLocation(peerName);
                Properties peerProperties = testConfig.getPeerProperties(peerName);
                Peer peer = client.newPeer(peerName, peerLocation, peerProperties);
                final PeerOptions peerEventingOptions = // we have two peers on one use block on other use filtered
                        everyOther ?
                                createPeerOptions().registerEventsForBlocks().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE)) :
                                createPeerOptions().registerEventsForFilteredBlocks().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE));

                newChannel.addPeer(peer, IS_FABRIC_V10 ?
                        createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY)) : peerEventingOptions);

                everyOther = !everyOther;
            }

            //Peers should have all roles. Do some sanity checks that they do.

            //Should have two peers with event sources.
            assertEquals(2, newChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).size());
            //Check some other roles too..
            assertEquals(2, newChannel.getPeers(EnumSet.of(PeerRole.CHAINCODE_QUERY, PeerRole.LEDGER_QUERY)).size());
            assertEquals(2, newChannel.getPeers(PeerRole.ALL).size());  //really same as newChannel.getPeers()

        }

        //Just some sanity check tests
        assertTrue(newChannel == client.getChannel(name));
        assertTrue(client == TestUtils.getField(newChannel, "client"));
        assertEquals(name, newChannel.getName());
        assertEquals(2, newChannel.getPeers().size());
        assertEquals(1, newChannel.getOrderers().size());
        assertFalse(newChannel.isShutdown());
        assertFalse(newChannel.isInitialized());
        byte[] serializedChannelBytes = newChannel.serializeChannel();

        //Just checks if channel can be serialized and deserialized .. otherwise this is just a waste :)
        // Get channel back.

        newChannel.shutdown(true);
        newChannel = client.deSerializeChannel(serializedChannelBytes);

        assertEquals(2, newChannel.getPeers().size());

        assertEquals(1, newChannel.getOrderers().size());

        assertNotNull(client.getChannel(name));
        assertEquals(newChannel, client.getChannel(name));
        assertFalse(newChannel.isInitialized());
        assertFalse(newChannel.isShutdown());
        assertEquals(TESTUSER_1_NAME, client.getUserContext().getName());
        newChannel.initialize();
        assertTrue(newChannel.isInitialized());
        assertFalse(newChannel.isShutdown());

        //Begin tests with de-serialized channel.

        //Query the actual peer for which channels it belongs to and check it belongs to this channel
        for (Peer peer : newChannel.getPeers()) {
            Set<String> channels = client.queryChannels(peer);
            if (!channels.contains(name)) {
                throw new AssertionError(format("Peer %s does not appear to belong to channel %s", peer.getName(), name));
            }
        }

        //Just see if we can get channelConfiguration. Not required for the rest of scenario but should work.
        final byte[] channelConfigurationBytes = newChannel.getChannelConfigurationBytes();
        Configtx.Config channelConfig = Configtx.Config.parseFrom(channelConfigurationBytes);

        assertNotNull(channelConfig);

        Configtx.ConfigGroup channelGroup = channelConfig.getChannelGroup();

        assertNotNull(channelGroup);

        Map<String, Configtx.ConfigGroup> groupsMap = channelGroup.getGroupsMap();

        assertNotNull(groupsMap.get("Orderer"));

        assertNotNull(groupsMap.get("Application"));

        //Before return lets see if we have the chaincode on the peers that we expect from End2endIT
        //And if they were instantiated too. this requires peer admin user

        client.setUserContext(sampleOrg.getPeerAdmin());

        for (Peer peer : newChannel.getPeers()) {

            if (!checkInstalledChaincode(client, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {

                fail(format("Peer %s is missing chaincode name: %s, path:%s, version: %s",
                        peer.getName(), CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION));

            }

            if (!checkInstantiatedChaincode(newChannel, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {

                fail(format("Peer %s is missing instantiated chaincode name: %s, path:%s, version: %s",
                        peer.getName(), CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION));

            }

        }

        client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME));

        assertTrue(newChannel.isInitialized());
        assertFalse(newChannel.isShutdown());

        out("Finished reconstructing channel %s.", name);

        return newChannel;
    }

    /**
     * This code test the replay feature of the new peer event services.
     * Instead of the default of starting the eventing peer to retrieve the newest block it sets it
     * retrieve starting from the start parameter. Also checks with block and filterblock replays.
     * Depends on end2end and end2endAndBackagain of have fully run to have the blocks need to work with.
     *
     * @param client
     * @param replayTestChannel
     * @param start
     * @param stop
     * @param useFilteredBlocks
     * @throws InvalidArgumentException
     */

    private void testPeerServiceEventingReplay(HFClient client, Channel replayTestChannel, final long start, final long stop,
                                               final boolean useFilteredBlocks) throws InvalidArgumentException {

        if (testConfig.isRunningAgainstFabric10()) {
            return; // not supported for v1.0
        }

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
        assertTrue(replayTestChannel.getPeers(EnumSet.of(PeerRole.CHAINCODE_QUERY, PeerRole.ENDORSING_PEER)).isEmpty()); // just checking :)
        assertTrue(replayTestChannel.getPeers(EnumSet.of(PeerRole.LEDGER_QUERY)).isEmpty()); // just checking

        assertNotNull(client.getChannel(replayTestChannel.getName())); // should be known by client.

        final PeerOptions eventingPeerOptions = createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.EVENT_SOURCE));
        if (useFilteredBlocks) {
            eventingPeerOptions.registerEventsForFilteredBlocks();
        }

        if (-1L == stop) { //the height of the blockchain

            replayTestChannel.addPeer(eventingPeer, eventingPeerOptions.startEvents(start)); // Eventing peer start getting blocks from block 0
        } else {
            replayTestChannel.addPeer(eventingPeer, eventingPeerOptions
                    .startEvents(start).stopEvents(stop)); // Eventing peer start getting blocks from block 0
        }
        //add a ledger peer
        replayTestChannel.addPeer(ledgerPeer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.LEDGER_QUERY)));

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

                assertTrue(format("Wrong type of block seen block number %d. expected filtered block %b but got %b",
                        blockNumber, useFilteredBlocks, blockEvent.isFiltered()),
                        useFilteredBlocks ? blockEvent.isFiltered() : !blockEvent.isFiltered());
                final long count = bcount.getAndIncrement(); //count starts with 0 not 1 !

                //out("Block count: %d, block number: %d  received from peer: %s", count, blockNumber, blockEvent.getPeer().getName());

                if (count == 0 && stop == -1L) {
                    final BlockchainInfo blockchainInfo = finalChannel.queryBlockchainInfo();

                    long lh = blockchainInfo.getHeight();
                    stopValue.set(lh - 1L);  // blocks 0L 9L are on chain height 10 .. stop on 9
                    //  out("height: %d", lh);
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

            //light weight test just see if we get reasonable values for traversing the block. Test just whats common between
            // Block and FilteredBlock.

            int transactionEventCounts = 0;
            int chaincodeEventsCounts = 0;

            for (long i = stopValue.longValue(); i >= start; i--) {

                final BlockEvent blockEvent = blockEvents.get(i);
//                out("blockwalker %b, start: %d, stop: %d, i: %d, block %d", useFilteredBlocks, start, stopValue.longValue(), i, blockEvent.getBlockNumber());
                assertEquals(useFilteredBlocks, blockEvent.isFiltered()); // check again

                if (useFilteredBlocks) {
                    assertNull(blockEvent.getBlock()); // should not have raw block event.
                    assertNotNull(blockEvent.getFilteredBlock()); // should have raw filtered block.
                } else {
                    assertNotNull(blockEvent.getBlock()); // should not have raw block event.
                    assertNull(blockEvent.getFilteredBlock()); // should have raw filtered block.
                }

                assertEquals(replayTestChannel.getName(), blockEvent.getChannelId());

                for (BlockInfo.EnvelopeInfo envelopeInfo : blockEvent.getEnvelopeInfos()) {
                    if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {

                        BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;
                        assertTrue(envelopeInfo.isValid()); // only have valid blocks.
                        assertEquals(envelopeInfo.getValidationCode(), 0);

                        ++transactionEventCounts;
                        for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo ta : transactionEnvelopeInfo.getTransactionActionInfos()) {
                            //    out("\nTA:", ta + "\n\n");
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
        QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
        queryByChaincodeRequest.setArgs("b".getBytes(UTF_8)); // test using bytes as args. End2end uses Strings.
        queryByChaincodeRequest.setFcn("query");
        queryByChaincodeRequest.setChaincodeID(chaincodeID);

        Collection<ProposalResponse> queryProposals;

        try {
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
