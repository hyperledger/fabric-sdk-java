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
import java.util.Collection;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.ChainCodeID;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.UpgradeProposalRequest;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Test end to end scenario
 */
public class End2endAndBackAgainIT {

    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TESTUSER_1_NAME = "user1";
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private final int gossipWaitTime = testConfig.getGossipWaitTime();

    private static final String CHAIN_CODE_NAME = "example_cc_go";
    private static final String CHAIN_CODE_PATH = "github.com/example_cc";
    private static final String CHAIN_CODE_VERSION = "1";
    private static final String CHAIN_CODE_VERSION_11 = "11";


    final ChainCodeID chainCodeID = ChainCodeID.newBuilder().setName(CHAIN_CODE_NAME)
            .setVersion(CHAIN_CODE_VERSION)
            .setPath(CHAIN_CODE_PATH).build();
    final ChainCodeID chainCodeID_11 = ChainCodeID.newBuilder().setName(CHAIN_CODE_NAME)
            .setVersion(CHAIN_CODE_VERSION_11)
            .setPath(CHAIN_CODE_PATH).build();

    private static final String FOO_CHAIN_NAME = "foo";
    private static final String BAR_CHAIN_NAME = "bar";

    private Hashtable<String, HFCAClient> fabricCAs = new Hashtable<>();

    String testTxID = null;  // save the CC invoke TxID and use in queries


    private final TestConfigHelper configHelper = new TestConfigHelper();

    private Collection<SampleOrg> testSampleOrgs;

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException {

        out("\n\n\nRUNNING: End2endAndBackAgainIT\n");

        configHelper.clearConfig();
        configHelper.customizeConfig();

        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        //Set up hfca for each sample org

        for (SampleOrg sampleOrg : testSampleOrgs) {
            String caURL = sampleOrg.getCALocation();
            sampleOrg.setCAClient(new HFCAClient(caURL, null));
        }
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

            // client.setMemberServices(peerOrg1FabricCA);

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

                HFCAClient ca = sampleOrg.getCAClient();
                final String orgName = sampleOrg.getName();
                client.setMemberServices(ca);
                SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
                sampleOrg.setAdmin(admin); // The admin of this org.

                // No need to enroll or register all done in End2endIt !
                SampleUser user = sampleStore.getMember(TESTUSER_1_NAME, orgName);
                sampleOrg.addUser(user);//Remember user belongs to this Org

            }

            ////////////////////////////
            //Reconstruct and run the chains
            SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
            runChain(client, reconstructChain(FOO_CHAIN_NAME, client, sampleOrg), sampleOrg, 0);
            out("\n");
            sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
            runChain(client, reconstructChain(BAR_CHAIN_NAME, client, sampleOrg), sampleOrg, 100); //run a newly constructed foo chain with different b value!
            //runChain(client, constructChain(MYCHANNEL_CHAIN_NAME, client, "peerOrg2"), true, "peerOrg1", 0);
            out("That's all folks!");

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }


    void runChain(HFClient client, Chain chain, SampleOrg sampleOrg, final int delta) {

        final String chainName = chain.getName();
        out("Running Chain %s with a delta %d", chainName, delta);
        chain.setTransactionWaitTime(testConfig.getInvokeWaitTime());
        chain.setDeployWaitTime(testConfig.getDeployWaitTime());

        try {
            client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME)); // select the user for all subsequent requests
        } catch (InvalidArgumentException e) {
            throw new RuntimeException(e);
        }

        ////////////////////////////
        // Send Query Proposal to all peers see if it's what we expect from end of End2endIT
        //
        queryChainCodeForExpectedValue(client, chain, "" + (300 + delta), chainCodeID);

        // exercise v1 of chaincode
        try {
            moveAmount(client, chain, chainCodeID, "25").thenApply(transactionEvent -> {

                waitOnFabric();

                queryChainCodeForExpectedValue(client, chain, "" + (325 + delta), chainCodeID);

                //////////////////
                // Start of upgrade first must install it.

                ///////////////
                ////
                InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
                installProposalRequest.setChaincodeID(chainCodeID);
                ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
                installProposalRequest.setChaincodeSourceLocation(new File(TEST_FIXTURES_PATH + "/sdkintegration/gocc/sample_11"));
                installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION_11);

                out("Sending install proposal");

                ////////////////////////////
                // only a client from the same org as the peer can issue an install request
                int numInstallProposal = 0;
                //    Set<String> orgs = orgPeers.keySet();
                //   for (SampleOrg org : testSampleOrgs) {
                try {
                    client.setUserContext(sampleOrg.getAdmin());
                } catch (InvalidArgumentException e) {
                    throw new CompletionException(e);
                }

                Collection<ProposalResponse> responses;
                final Collection<ProposalResponse> successful = new LinkedList<>();
                final Collection<ProposalResponse> failed = new LinkedList<>();
                Collection<Peer> peersFromOrg = chain.getPeers();
                numInstallProposal = numInstallProposal + peersFromOrg.size();
                try {
                    responses = chain.sendInstallProposal(installProposalRequest);
                } catch (Exception e) {
                    throw new CompletionException(e);
                }

                for (ProposalResponse response : responses) {
                    if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                        out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                        successful.add(response);
                    } else {
                        failed.add(response);
                    }
                }
                //   }
                out("Received %d install proposal responses. Successful+verified: %d . Failed: %d", numInstallProposal, successful.size(), failed.size());

                if (failed.size() > 0) {
                    ProposalResponse first = failed.iterator().next();
                    fail("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
                }

                //////////////////
                // Upgrade chaincode to ***double*** our move results.

                UpgradeProposalRequest upgradeProposalRequest = client.newUpgradeProposalRequest();
                upgradeProposalRequest.setChaincodeID(chainCodeID_11);
                upgradeProposalRequest.setFcn("init");
                upgradeProposalRequest.setArgs(new String[]{});// no arguments don't change the ledger see chaincode.

                ChaincodeEndorsementPolicy chaincodeEndorsementPolicy;
                try {
                    chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
                    chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
                } catch (Exception e) {
                    throw new CompletionException(e);
                }
                upgradeProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);

                out("Sending upgrade proposal");

                Collection<ProposalResponse> responses2;

                try {
                    responses2 = chain.sendUpgradeProposal(upgradeProposalRequest);
                } catch (Exception e1) {
                    throw new CompletionException(e1);
                }

                successful.clear();
                failed.clear();
                for (ProposalResponse response : responses2) {
                    if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                        out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                        successful.add(response);
                    } else {
                        failed.add(response);
                    }
                }
                //   }
                out("Received %d upgrade proposal responses. Successful+verified: %d . Failed: %d", chain.getPeers().size(), successful.size(), failed.size());

                if (failed.size() > 0) {
                    ProposalResponse first = failed.iterator().next();
                    throw new CompletionException(new AssertionError("Not enough endorsers for upgrade :"
                            + successful.size() + ".  " + first.getMessage()));
                }

                return chain.sendTransaction(successful, chain.getOrderers());


            }).thenApply(transactionEvent -> {
                waitOnFabric(10000);
                out("Chain code has been upgraded.");

                //Check to see if peers have new chaincode and old chain code is gone.
                try {

                    for (Peer peer : chain.getPeers()) {

                        if (!checkInstalledChaincode(client, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION_11)) {
                            throw new CompletionException(new AssertionError(format("Peer %s is missing chaincode name:%s, path:%s, version: %s",
                                    peer.getName(), CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_PATH)));
                        }

                        //should be instantiated too..

                        if (!checkInstantiatedChaincode(chain, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION_11)) {

                            throw new CompletionException(new AssertionError(format("Peer %s is missing instantiated chaincode name:%s, path:%s, version: %s",
                                    peer.getName(), CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_PATH)));
                        }

                        if (checkInstantiatedChaincode(chain, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {

                            throw new CompletionException(new AssertionError(format("Peer %s still has old instantiated chaincode name:%s, path:%s, version: %s",
                                    peer.getName(), CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_PATH)));
                        }

                    }
                } catch (Exception e) {

                    throw new CompletionException(e);

                }

                ///Check if we still get the same value on the ledger
                out("delta is %s", delta);
                queryChainCodeForExpectedValue(client, chain, "" + (325 + delta), chainCodeID);

                //Now lets run the new chaincode which should *double* the results we asked to move.

                return moveAmount(client, chain, chainCodeID_11, "50"); // really move 100


            }).thenApply(transactionEvent -> {

                waitOnFabric(10000);

                queryChainCodeForExpectedValue(client, chain, "" + (425 + delta), chainCodeID_11);

                return null;
            }).exceptionally(e -> {
                if (e instanceof CompletionException && e.getCause() != null) {
                    e = e.getCause();
                }
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {
                        fail(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()));
                    }
                }
                fail(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()));

                return null;
            }).get(12000, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        out("Running for Chain %s done", chainName);

    }


    CompletableFuture<BlockEvent.TransactionEvent> moveAmount(HFClient client, Chain chain, ChainCodeID chainCodeID, String moveAmount) {

        try {
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();

            ///////////////
            /// Send transaction proposal to all peers
            TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
            transactionProposalRequest.setChaincodeID(chainCodeID);
            transactionProposalRequest.setFcn("invoke");
            transactionProposalRequest.setArgs(new String[]{"move", "a", "b", moveAmount});
            out("sending transaction proposal to all peers with arguments: move(a,b,%s)", moveAmount);

            Collection<ProposalResponse> invokePropResp = chain.sendTransactionProposal(transactionProposalRequest, chain.getPeers());
            for (ProposalResponse response : invokePropResp) {
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
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
            out("Sending chain code transaction(move a,b,%s) to orderer.", moveAmount);
            return chain.sendTransaction(successful, chain.getOrderers());
        } catch (Exception e) {

            throw new CompletionException(e);

        }

    }


    private Chain reconstructChain(String name, HFClient client, SampleOrg sampleOrg) throws Exception {

        client.setUserContext(sampleOrg.getAdmin());
        Chain newChain = client.newChain(name);

        for (String orderName : sampleOrg.getOrdererNames()) {
            newChain.addOrderer(client.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName),
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

            newChain.addPeer(peer);
            sampleOrg.addPeer(peer);
        }

        for (String eventHubName : sampleOrg.getEventHubNames()) {
            EventHub eventHub = client.newEventHub(eventHubName, sampleOrg.getEventHubLocation(eventHubName),
                    testConfig.getEventHubProperties(eventHubName));
            newChain.addEventHub(eventHub);
        }

        newChain.initialize();

        //Before return lets see if we have the chaincode on the peers that we expect from End2endIT
        //And if they were instantiated too.

        for (Peer peer : newChain.getPeers()) {

            if (!checkInstalledChaincode(client, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {
                throw new AssertionError(format("Peer %s is missing chaincode name: %s, path:%s, version: %s",
                        peer.getName(), CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_PATH));
            }

            if (!checkInstantiatedChaincode(newChain, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {

                throw new AssertionError(format("Peer %s is missing instantiated chaincode name: %s, path:%s, version: %s",
                        peer.getName(), CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_PATH));
            }

        }

        return newChain;
    }


    private void queryChainCodeForExpectedValue(HFClient client, Chain chain, final String expect, ChainCodeID chainCodeID) {

        out("Now query chaincode on chain %s for the value of b expecting to see: %s", chain.getName(), expect);
        QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
        queryByChaincodeRequest.setArgs(new String[]{"query", "b"});
        queryByChaincodeRequest.setFcn("invoke");
        queryByChaincodeRequest.setChaincodeID(chainCodeID);

        Collection<ProposalResponse> queryProposals;

        try {
            queryProposals = chain.queryByChaincode(queryByChaincodeRequest);
        } catch (Exception e) {
            throw new CompletionException(e);
        }

        for (ProposalResponse proposalResponse : queryProposals) {
            if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                        ". Messages: " + proposalResponse.getMessage()
                        + ". Was verified : " + proposalResponse.isVerified());
            } else {
                String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                out("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                assertEquals(payload, expect);
            }
        }
    }


    private void waitOnFabric() {

        waitOnFabric(0);
    }

    private void waitOnFabric(int additional) {
        // wait a few seconds for the peers to catch up with each other via the gossip network.
        // Another way would be to wait on all the peers event hubs for the event containing the transaction TxID
        try {
            out("Wait %d milliseconds for peers to sync with each other", gossipWaitTime + additional);
            TimeUnit.MILLISECONDS.sleep(gossipWaitTime + additional);
        } catch (InterruptedException e) {
            fail("should not have jumped out of sleep mode. No other threads should be running");
        }
    }


    private static boolean checkInstalledChaincode(HFClient client, Peer peer, String cc_name, String cc_path, String cc_version) throws InvalidArgumentException, ProposalException {
        List<ChaincodeInfo> ccinfoList = client.queryInstalledChaincodes(peer);

        boolean found = false;

        for (ChaincodeInfo ccifo : ccinfoList) {

            found = cc_name.equals(ccifo.getName()) && cc_path.equals(ccifo.getPath()) && cc_version.equals(ccifo.getVersion());
            if (true == found) break;

        }

        return found;
    }


    private static boolean checkInstantiatedChaincode(Chain chain, Peer peer, String cc_name, String cc_path, String cc_version) throws InvalidArgumentException, ProposalException {
        List<ChaincodeInfo> ccinfoList = chain.queryInstantiatedChaincodes(peer);

        boolean found = false;

        for (ChaincodeInfo ccifo : ccinfoList) {
            found = cc_name.equals(ccifo.getName()) && cc_path.equals(ccifo.getPath()) && cc_version.equals(ccifo.getVersion());
            if (true == found) break;

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

}
