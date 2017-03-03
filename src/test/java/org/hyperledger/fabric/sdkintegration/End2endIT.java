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
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.concurrent.TimeUnit;

import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.ChainCodeID;
import org.hyperledger.fabric.sdk.ChainConfiguration;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.FileKeyValStore;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.InvokeProposalRequest;
import org.hyperledger.fabric.sdk.MemberServicesFabricCAImpl;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryProposalRequest;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.events.EventHub;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;

/**
 * Test end to end scenario
 */
public class End2endIT {

    TestConfig testConfig = TestConfig.getConfig();


    static final String CHAIN_CODE_NAME = "example_cc.go";
    static final String CHAIN_CODE_PATH = "github.com/example_cc";
    static final String CHAIN_CODE_VERSION = "1.0";


    static final String TEST_CHAIN_NAME = "testchainid";
    static final String FOO_CHAIN_NAME = "foo";
    static final String CHAIN_NAME = FOO_CHAIN_NAME;
    //static final String CHAIN_NAME = TEST_CHAIN_NAME;

    final static Collection<String> PEER_LOCATIONS = Arrays.asList("grpc://localhost:7051");


    final static Collection<String> ORDERER_LOCATIONS = Arrays.asList("grpc://localhost:7050"); //Vagrant maps to this

    final static Collection<String> EVENTHUB_LOCATIONS = Arrays.asList("grpc://localhost:7053"); //Vagrant maps to this

    final static String FABRIC_CA_SERVICES_LOCATION = "http://localhost:7054";

    private final TestConfigHelper configHelper = new TestConfigHelper();

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        configHelper.clearConfig();
        configHelper.customizeConfig();
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

            HFClient client = HFClient.createNewInstance();

            ////////////////////////////
            // Setup client

            File fileStore = new File(System.getProperty("user.home") + "/test.properties");
            if (fileStore.exists()) {
                fileStore.delete();
            }
            client.setKeyValStore(new FileKeyValStore(fileStore));
            client.setMemberServices(new MemberServicesFabricCAImpl(FABRIC_CA_SERVICES_LOCATION, null));
            User user = client.enroll("admin", "adminpw");
            client.setUserContext(user);


            ////////////////////////////
            //Construct the chains
            //

            runChain(client, constructChain(client), true, 0);// Run test chai


            out("\n");
            runChain(client, constructFooChain(client), false, 100);//run a newly constructed foo chain with different b value!

            out("That's all folks!");



        }catch (Exception e){
            e.printStackTrace();

            Assert.fail(e.getMessage());
        }


    }


    void runChain(HFClient client, Chain chain, boolean installChainCode, int delta) {
        try {
            final String chainName = chain.getName();
            out("Running Chain %s", chainName);
            chain.setInvokeWaitTime(testConfig.getInvokeWaitTime());
            chain.setDeployWaitTime(testConfig.getDeployWaitTime());


            chain.initialize();

            Collection<Peer> peers = chain.getPeers();
            Collection<Orderer> orderers = chain.getOrderers();
            final ChainCodeID chainCodeID;
            Collection<ProposalResponse> responses;
            Collection<ProposalResponse> successful  = new LinkedList<>();
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

                responses = chain.sendInstallProposal(installProposalRequest, peers);

                for (ProposalResponse response : responses) {
                    if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                        successful.add(response);

                    } else {
                        failed.add(response);
                    }

                }
                out("Received %d install proposal responses. Successful+verified: %d . Failed: %d", responses.size(), successful.size(), failed.size());

                if (successful.size() < 1) { // TODO choose this as an arbitrary limit right now.
                    if (failed.size() == 0) {
                        Assert.fail("No endorsers found for CC install");
                    }
                    ProposalResponse first = failed.iterator().next();
                    Assert.fail("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
                }
                ProposalResponse firstInstallProposalResponse = successful.iterator().next();
            }
            //  final ChainCodeID chainCodeID = firstInstallProposalResponse.getChainCodeID();
            // Note install chain code does not require transaction no need to
            // send to Orderers

            ///////////////
            //// Instantiate chain code.

            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();

            instantiateProposalRequest.setChaincodeID(chainCodeID);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs(new String[]{"a", "100", "b", ""+(200 + delta)});

            ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy(new File("src/test/resources/policyBitsAdmin"));
            instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);

            out("Sending instantiateProposalRequest code with a and b set to 100 and %s respectively", ""+(200 + delta) );

            responses = chain.sendInstantiationProposal(instantiateProposalRequest, peers);

            successful.clear();
            failed.clear();

            for (ProposalResponse response : responses) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);
                } else {
                    failed.add(response);
                }
            }
            out("Received %d instantiate proposal responses. Successful+verified: %d . Failed: %d", responses.size(), successful.size(), failed.size());

            if (successful.size() < 1) { // TODO choose this as an arbitrary limit right now.
                if (failed.size() == 0) {
                    throw new Exception("No endorsers found for CC instantiate proposal");
                }
                ProposalResponse first = failed.iterator().next();

                throw new Exception("Not enough endorsers for instantiate  :" + successful.size() + ".  " + first.getMessage() + ". Was verified:" + first.isVerified());
            }


            /// Send instantiate transaction.
            chain.sendTransaction(successful, orderers).thenApply(transactionEvent -> {


                Assert.assertTrue(transactionEvent.isValid()); // must be valid to be here.
                out("Finished instantiate transaction with transaction id %s", transactionEvent.getTransactionID());

                try {

                    out("Successfully completed chaincode instantiation.");

                    out("Creating invoke proposal");

                    InvokeProposalRequest invokeProposalRequest = client.newInvokeProposalRequest();

                    invokeProposalRequest.setChaincodeID(chainCodeID);
                    invokeProposalRequest.setFcn("invoke");
                    invokeProposalRequest.setArgs(new String[]{"move", "a", "b", "100"});

                    Collection<ProposalResponse> invokePropResp = chain.sendInvokeProposal(invokeProposalRequest, peers);


                    successful.clear();
                    failed.clear();

                    for (ProposalResponse response : invokePropResp) {

                        if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                            successful.add(response);
                        } else {
                            failed.add(response);
                        }

                    }
                    out("Received %d invoke proposal responses. Successful+verified: %d . Failed: %d",
                            invokePropResp.size(), successful.size(), failed.size());


                    if (successful.size() < 1) {  //choose this as an arbitrary limit right now.

                        if (failed.size() == 0) {
                            throw new Exception("No endorsers found ");

                        }
                        ProposalResponse firstInvokeProposalResponse = failed.iterator().next();


                        throw new Exception("Not enough endorsers :" + successful.size() + ".  " +
                                firstInvokeProposalResponse.getMessage() +
                                ". Was verified: " + firstInvokeProposalResponse.isVerified());


                    }
                    out("Successfully received invoke proposal response.");

                    ////////////////////////////
                    // Invoke Transaction
                    //

                    out("Invoking chain code transaction to move 100 from a to b.");

                    return chain.sendTransaction(successful, orderers).get(120, TimeUnit.SECONDS);


                } catch (Exception e) {

                    throw new RuntimeException(e);

                }


            }).thenApply(transactionEvent -> {
                try {

                    Assert.assertTrue(transactionEvent.isValid()); // must be valid to be here.
                    out("Finished invoke transaction with transaction id %s", transactionEvent.getTransactionID());

                    ////////////////////////////
                    // Query Proposal
                    //


                    out("Now query chain code for the value of b.");


                    // InvokeProposalRequest qr = InvokeProposalRequest.newInstance();
                    QueryProposalRequest queryProposalRequest = client.newQueryProposalRequest();

                    queryProposalRequest.setArgs(new String[]{"query", "b"});
                    queryProposalRequest.setFcn("invoke");
                    queryProposalRequest.setChaincodeID(chainCodeID);


                    Collection<ProposalResponse> queryProposals = chain.sendQueryProposal(queryProposalRequest, peers);

                    for (ProposalResponse proposalResponse : queryProposals) {
                        if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                            return new Exception("Failed invoke proposal.  status: " + proposalResponse.getStatus() +
                                    ". messages: " + proposalResponse.getMessage()
                                    + ". Was verified : " + proposalResponse.isVerified());

                        }

                    }

                    out("Successfully received query response.");

                    String payload = queryProposals.iterator().next().getProposalResponse().getResponse().getPayload().toStringUtf8();

                    out("Query payload of b returned %s", payload);

                    final String expect = "" +(300 + delta);


                    Assert.assertEquals(payload, expect);

                    if (!payload.equals("300")) {
                        return new Exception("Expected " + expect + " for value b but got: " + payload);
                    }


                    return null;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            }).exceptionally(e -> {
                System.err.println("Bad status value for proposals transaction: " + e.getMessage());
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {

                        Assert.fail(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()));
                    }
                }
                Assert.fail(format("Transaction  failed  %s", e.getMessage()));
                return null;
            }).get(120, TimeUnit.SECONDS);
            out("Running for Chain %s done", chainName);


        } catch (Exception e) {
            out("Caught an exception running chain %s", chain.getName());
            e.printStackTrace();

            Assert.fail(e.getMessage());

        }
    }


    private static Chain constructChain(HFClient client) throws Exception {
        //////////////////////////// TODo Needs to be made out of bounds and here chain just retrieved
        //Construct the chain
        //

        Chain newChain = client.newChain(TEST_CHAIN_NAME);

        for (String peerloc : PEER_LOCATIONS) {
            Peer peer = client.newPeer(peerloc);
            peer.setName("peer1");
            newChain.addPeer(peer);
        }

        for (String orderloc : ORDERER_LOCATIONS) {
            Orderer orderer = client.newOrderer(orderloc);
            newChain.addOrderer(orderer);
        }

        for (String eventHubLoc : EVENTHUB_LOCATIONS) {
            EventHub eventHub = client.newEventHub(eventHubLoc);
            newChain.addEventHub(eventHub);
        }

        return newChain;

    }

    private static Chain constructFooChain(HFClient client) throws Exception {
        //////////////////////////// TODo Needs to be made out of bounds and here chain just retrieved
        //Construct the chain
        //


        Collection<Orderer> orderers = new LinkedList<>();

        for (String orderloc : ORDERER_LOCATIONS) {
            orderers.add(client.newOrderer(orderloc));

        }

        //Just pick the first order in the list to create the chain.

        Orderer anOrderer = orderers.iterator().next();
        orderers.remove(anOrderer);

        ChainConfiguration chainConfiguration = new ChainConfiguration(new File("src/test/fixture/foo.configtx"));

        Chain newChain = client.newChain(FOO_CHAIN_NAME, anOrderer, chainConfiguration);

        int i = 0;
        for (String peerloc : PEER_LOCATIONS) {
            Peer peer = client.newPeer(peerloc);
            peer.setName("peer_" + i);
            newChain.joinPeer(peer); // have Peers join the chain

        }

        for (String orderloc : ORDERER_LOCATIONS) {
            Orderer orderer = client.newOrderer(orderloc);
            newChain.addOrderer(orderer);
        }

        for (String eventHubLoc : EVENTHUB_LOCATIONS) {
            EventHub eventHub = client.newEventHub(eventHubLoc);
            newChain.addEventHub(eventHub);
        }


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
