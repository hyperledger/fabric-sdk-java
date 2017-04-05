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
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.commons.codec.binary.Hex;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.BlockchainInfo;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.ChainCodeID;
import org.hyperledger.fabric.sdk.ChainConfiguration;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionInfo;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test end to end scenario
 */
public class End2endIT {

    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final String TEST_ADMIN_NAME = "admin";
    private static final String TESTUSER_1_NAME = "user1";
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private final int gossipWaitTime = testConfig.getGossipWaitTime();

    private static final String CHAIN_CODE_NAME = "example_cc_go";
    private static final String CHAIN_CODE_PATH = "github.com/example_cc";
    private static final String CHAIN_CODE_VERSION = "1";

    private static final String FOO_CHAIN_NAME = "foo";
    private static final String BAR_CHAIN_NAME = "bar";


    String testTxID = null;  // save the CC invoke TxID and use in queries


    private final TestConfigHelper configHelper = new TestConfigHelper();

    private Collection<SampleOrg> testSampleOrgs;

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException {

        configHelper.clearConfig();
        configHelper.customizeConfig();

        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        //Set up hfca for each sample org

        for (SampleOrg sampleOrg : testSampleOrgs) {
            sampleOrg.setCAClient(new HFCAClient(sampleOrg.getCALocation(), sampleOrg.getCAProperties()));
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
            if (sampleStoreFile.exists()) { //For testing start fresh
                sampleStoreFile.delete();
            }

            final SampleStore sampleStore = new SampleStore(sampleStoreFile);
            //  sampleStoreFile.deleteOnExit();

            //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface

            ////////////////////////////
            // get users for all orgs

            for (SampleOrg sampleOrg : testSampleOrgs) {

                HFCAClient ca = sampleOrg.getCAClient();
                final String orgName = sampleOrg.getName();
                final String mspid = sampleOrg.getMSPID();
                client.setMemberServices(ca);
                SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
                if (!admin.isEnrolled()) {  //Preregistered admin only needs to be enrolled with Fabric caClient.

                    admin.setEnrollment(ca.enroll(admin.getName(), "adminpw"));
                    admin.setMPSID(mspid);
                    sampleOrg.setAdmin(admin); // The admin of this org.
                }

                SampleUser user = sampleStore.getMember(TESTUSER_1_NAME, sampleOrg.getName());
                if (!user.isRegistered()) {  // users need to be registered AND enrolled
                    RegistrationRequest rr = new RegistrationRequest(user.getName(), "org1.department1");
                    user.setEnrollmentSecret(ca.register(rr, admin));
                }
                if (!user.isEnrolled()) {
                    user.setEnrollment(ca.enroll(user.getName(), user.getEnrollmentSecret()));
                    user.setMPSID(mspid);
                }
                sampleOrg.addUser(user);//Remember user belongs to this Org

            }

            ////////////////////////////
            //Construct and run the chains
            SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
            runChain(client, constructChain(FOO_CHAIN_NAME, client, sampleOrg), true, sampleOrg, 0);
            out("\n");
            sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
            runChain(client, constructChain(BAR_CHAIN_NAME, client, sampleOrg), true, sampleOrg, 100); //run a newly constructed foo chain with different b value!
            //runChain(client, constructChain(MYCHANNEL_CHAIN_NAME, client, "peerOrg2"), true, "peerOrg1", 0);
            out("That's all folks!");


        } catch (Exception e) {
            e.printStackTrace();

            fail(e.getMessage());
        }


    }


    void runChain(HFClient client, Chain chain, boolean installChainCode, SampleOrg sampleOrg, int delta) {

        try {

            final String chainName = chain.getName();
            out("Running Chain %s", chainName);
            chain.setTransactionWaitTime(testConfig.getInvokeWaitTime());
            chain.setDeployWaitTime(testConfig.getDeployWaitTime());

            Collection<Peer> channelPeers = chain.getPeers();
            Collection<Orderer> orderers = chain.getOrderers();
            final ChainCodeID chainCodeID;
            Collection<ProposalResponse> responses;
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();

            chainCodeID = ChainCodeID.newBuilder().setName(CHAIN_CODE_NAME)
                    .setVersion(CHAIN_CODE_VERSION)
                    .setPath(CHAIN_CODE_PATH).build();

            if (installChainCode) {
                ////////////////////////////
                // Install Proposal Request
                //

                out("Creating install proposal");

                InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
                installProposalRequest.setChaincodeID(chainCodeID);
                ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
                installProposalRequest.setChaincodeSourceLocation(new File(TEST_FIXTURES_PATH + "/sdkintegration/gocc/sample1"));
                installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);

                out("Sending install proposal");

                ////////////////////////////
                // only a client from the same org as the peer can issue an install request
                int numInstallProposal = 0;
                //    Set<String> orgs = orgPeers.keySet();
                //   for (SampleOrg org : testSampleOrgs) {
                client.setUserContext(sampleOrg.getAdmin());
                Set<Peer> peersFromOrg = sampleOrg.getPeers();
                numInstallProposal = numInstallProposal + peersFromOrg.size();
                responses = chain.sendInstallProposal(installProposalRequest, peersFromOrg);

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
            }
            //  final ChainCodeID chainCodeID = firstInstallProposalResponse.getChainCodeID();
            // Note install chain code does not require transaction no need to
            // send to Orderers

            ///////////////
            //// Instantiate chain code.
            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setChaincodeID(chainCodeID);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs(new String[]{"a", "500", "b", "" + (200 + delta)});

            /*
              policy OR(Org1MSP.member, Org2MSP.member) meaning 1 signature from someone in either Org1 or Org2
              See README.md Chaincode endorsement policies section for more details.
            */
            ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
            chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
            instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);

            out("Sending instantiateProposalRequest to all peers with arguments: a and b set to 100 and %s respectively", "" + (200 + delta));
            successful.clear();
            failed.clear();

            responses = chain.sendInstantiationProposal(instantiateProposalRequest, chain.getPeers());
            for (ProposalResponse response : responses) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);
                    out("Succesful instantiate proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                } else {
                    failed.add(response);
                }
            }
            out("Received %d instantiate proposal responses. Successful+verified: %d . Failed: %d", responses.size(), successful.size(), failed.size());
            if (failed.size() > 0) {
                ProposalResponse first = failed.iterator().next();
                fail("Not enough endorsers for instantiate :" + successful.size() + "endorser failed with " + first.getMessage() + ". Was verified:" + first.isVerified());
            }

            ///////////////
            /// Send instantiate transaction to orderer
            out("Sending instantiateTransaction to orderer with a and b set to 100 and %s respectively", "" + (200 + delta));
            chain.sendTransaction(successful, orderers).thenApply(transactionEvent -> {

                assertTrue(transactionEvent.isValid()); // must be valid to be here.
                out("Finished instantiate transaction with transaction id %s", transactionEvent.getTransactionID());

                // wait a few seconds for the peers to catch up with each other via the gossip network.
                // We need the instantiate to be committed at all peers before we can do transaction on all peers
                try {
                    out("Wait %d milliseconds for peers to sync with each other", gossipWaitTime);
                    TimeUnit.MILLISECONDS.sleep(gossipWaitTime);
                } catch (InterruptedException e) {
                    fail("should not have jumped out of sleep mode. No other threads should be running");
                }

                try {
                    successful.clear();
                    failed.clear();
                    client.setUserContext(sampleOrg.getUser(TESTUSER_1_NAME)); // select the user for all subsequent requests

                    ///////////////
                    /// Send transaction proposal to all peers
                    TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
                    transactionProposalRequest.setChaincodeID(chainCodeID);
                    transactionProposalRequest.setFcn("invoke");
                    transactionProposalRequest.setArgs(new String[]{"move", "a", "b", "100"});
                    out("sending transactionProposal to all peers with arguments: move(a,b,100)");

                    Collection<ProposalResponse> transactionPropResp = chain.sendTransactionProposal(transactionProposalRequest, chain.getPeers());
                    for (ProposalResponse response : transactionPropResp) {
                        if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                            out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                            successful.add(response);
                        } else {
                            failed.add(response);
                        }
                    }
                    out("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                            transactionPropResp.size(), successful.size(), failed.size());
                    if (failed.size() > 0) {
                        ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
                        fail("Not enough endorsers for invoke(move a,b,100):" + failed.size() + " endorser error: " +
                                firstTransactionProposalResponse.getMessage() +
                                ". Was verified: " + firstTransactionProposalResponse.isVerified());
                    }
                    out("Successfully received transaction proposal responses.");

                    ////////////////////////////
                    // Send Transaction Transaction to orderer
                    out("Sending chain code transaction(move a,b,100) to orderer.");
                    return chain.sendTransaction(successful, orderers).get(120, TimeUnit.SECONDS);

                } catch (Exception e) {
                    out("Caught an exception while invoking chaincode");
                    e.printStackTrace();
                    fail("Failed invoking chaincode with error : " + e.getMessage());
                }

                return null;

            }).thenApply(transactionEvent -> {
                try {

                    assertTrue(transactionEvent.isValid()); // must be valid to be here.
                    out("Finished transaction with transaction id %s", transactionEvent.getTransactionID());
                    testTxID = transactionEvent.getTransactionID(); // used in the channel queries later

                    // wait a few seconds for the peers to catch up with each other via the gossip network.
                    // Another way would be to wait on all the peers event hubs for the event containing the TxID
                    try {
                        out("Wait %d milliseconds for peers to sync with each other", gossipWaitTime);
                        TimeUnit.MILLISECONDS.sleep(gossipWaitTime);
                    } catch (InterruptedException e) {
                        fail("should not have jumped out of sleep mode. No other threads should be running");
                    }

                    ////////////////////////////
                    // Send Query Proposal to all peers
                    //
                    String expect = "" + (300 + delta);
                    out("Now query chain code for the value of b.");
                    QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
                    queryByChaincodeRequest.setArgs(new String[]{"query", "b"});
                    queryByChaincodeRequest.setFcn("invoke");
                    queryByChaincodeRequest.setChaincodeID(chainCodeID);

                    Collection<ProposalResponse> queryProposals = chain.queryByChaincode(queryByChaincodeRequest, chain.getPeers());
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

                    return null;
                } catch (Exception e) {
                    out("Caught exception while running query");
                    e.printStackTrace();
                    fail("Failed during chaincode query with error : " + e.getMessage());
                }

                return null;
            }).exceptionally(e -> {
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {
                        fail(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()));
                    }
                }
                fail(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()));

                return null;
            }).get(120, TimeUnit.SECONDS);

            // Channel queries

            // We can only send channel queries to peers that are in the same org as the SDK user context
            // Get the peers from the current org being used and pick one randomly to send the queries to.
            Set<Peer> peerSet = sampleOrg.getPeers();
            Peer queryPeer = peerSet.iterator().next();
            out("Using peer %s for channel queries", queryPeer.getName());

            BlockchainInfo channelInfo = chain.queryBlockchainInfo(queryPeer);
            out("Channel info for : " + chainName);
            out("Channel height: " + channelInfo.getHeight());
            String chainCurrentHash = Hex.encodeHexString(channelInfo.getCurrentBlockHash());
            String chainPreviousHash = Hex.encodeHexString(channelInfo.getPreviousBlockHash());
            out("Channel current block hash: " + chainCurrentHash);
            out("Channel previous block hash: " + chainPreviousHash);

            // Query by block number. Should return latest block, i.e. block number 2
            BlockInfo returnedBlock = chain.queryBlockByNumber(queryPeer, channelInfo.getHeight() - 1);
            String previousHash = Hex.encodeHexString(returnedBlock.getPreviousHash());
            out("queryBlockByNumber returned correct block with blockNumber " + returnedBlock.getBlockNumber()
                    + " \n previous_hash " + previousHash);
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
            assertEquals(chainPreviousHash, previousHash);

            // Query by block hash. Using latest block's previous hash so should return block number 1
            byte[] hashQuery = returnedBlock.getPreviousHash();
            returnedBlock = chain.queryBlockByHash(queryPeer, hashQuery);
            out("queryBlockByHash returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 2, returnedBlock.getBlockNumber());

            // Query block by TxID. Since it's the last TxID, should be block 2
            returnedBlock = chain.queryBlockByTransactionID(queryPeer, testTxID);
            out("queryBlockByTxID returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());

            // query transaction by ID
            TransactionInfo txInfo = chain.queryTransactionByID(queryPeer, testTxID);
            out("QueryTransactionByID returned TransactionInfo: txID " + txInfo.getTransactionID()
                    + "\n     validation code " + txInfo.getValidationCode().getNumber());
            /*
             * TODO printing out too many error messages right now
            boolean shouldNotFail = true;
            try {
                txInfo = chain.queryTransactionByID("fake", peer);
            } catch (Exception ee) {
                shouldNotFail = false;
            }
            if (shouldNotFail) {
                fail("Should have failed on queryTransactionByID using fake txID");
            }
            */

            out("Running for Chain %s done", chainName);

        } catch (Exception e) {
            out("Caught an exception running chain %s", chain.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }


    private Chain constructChain(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        //////////////////////////// TODo Needs to be made out of bounds and here chain just retrieved
        //Construct the chain
        //

        out("Constructing chain %s", name);

        Collection<Orderer> orderers = new LinkedList<>();

        for (String orderName : sampleOrg.getOrdererNames()) {
            orderers.add(client.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName),
                    testConfig.getOrdererProperties(orderName)));
        }

        //Just pick the first orderer in the list to create the chain.

        Orderer anOrderer = orderers.iterator().next();
        orderers.remove(anOrderer);

        ChainConfiguration chainConfiguration = new ChainConfiguration(new File(TEST_FIXTURES_PATH + "/sdkintegration/e2e-2Orgs/channel/" + name + ".tx"));

        client.setUserContext(sampleOrg.getAdmin());
        Chain newChain = client.newChain(name, anOrderer, chainConfiguration);

        out("Created chain %s", name);

        for (String peerName : sampleOrg.getPeerNames()) {
            String peerLocation = sampleOrg.getPeerLocation(peerName);
            Peer peer = client.newPeer(peerName, peerLocation, testConfig.getPeerProperties(peerName));
            newChain.joinPeer(peer);
            out("Peer %s joined chain %s", peerName, name);
            sampleOrg.addPeer(peer);
        }

        for (Orderer orderer : orderers) { //add remaining orderers if any.
            newChain.addOrderer(orderer);
        }

        for (String eventHubName : sampleOrg.getEventHubNames()) {
            EventHub eventHub = client.newEventHub(eventHubName, sampleOrg.getEventHubLocation(eventHubName),
                    testConfig.getEventHubProperties(eventHubName));
            newChain.addEventHub(eventHub);
        }

        newChain.initialize();

        out("Finished initialization chain %s", name);

        return newChain;

    }


    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

}
