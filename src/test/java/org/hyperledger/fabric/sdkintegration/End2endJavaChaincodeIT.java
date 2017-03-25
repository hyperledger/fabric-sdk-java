/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.ChainCodeID;
import org.hyperledger.fabric.sdk.EventHub;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Test end to end scenario
 */
public class End2endJavaChaincodeIT {

    static final String CHAIN_CODE_NAME = "example_cc_java";
    static final String CHAIN_CODE_PATH = "github.com/example_cc";
    static final String CHAIN_CODE_VERSION = "1";


    static final String CHAIN_NAME = "testchainid";

    final static Collection<String> PEER_LOCATIONS = Arrays.asList("grpc://localhost:7051");


    final static Collection<String> ORDERER_LOCATIONS = Arrays.asList("grpc://localhost:7050"); //Vagrant maps to this

    final static Collection<String> EVENTHUB_LOCATIONS = Arrays.asList("grpc://localhost:7053"); //Vagrant maps to this

    final static String FABRIC_CA_SERVICES_LOCATION = "http://localhost:7054";

    private TestConfigHelper configHelper = new TestConfigHelper();

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
        ;
    }

    @Test
    @Ignore
    public void setup() {

        try {
            HFClient client = HFClient.createNewInstance();

            //     client.setUserContext(new FSUser("admin"));
            File fileStore = new File(System.getProperty("user.home") + "/test.properties");
            if (fileStore.exists()) {
                fileStore.delete();
            }



            //////////////////////////// TODo Needs to be made out of bounds and here chain just retrieved
            //Construct the chain
            //

            constructChain(client);

            Chain chain = client.getChain(CHAIN_NAME);

            chain.setTransactionWaitTime(1000);
            chain.setDeployWaitTime(12000);


            chain.initialize();

            Collection<Peer> peers = chain.getPeers();
            Collection<Orderer> orderers = chain.getOrderers();

            ////////////////////////////
            //Install Proposal Request
            //

            out("Creating install proposal");

            InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
            installProposalRequest.setChaincodeName(CHAIN_CODE_NAME);
            installProposalRequest.setChaincodePath(CHAIN_CODE_PATH);
            installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);


            Collection<ProposalResponse> responses = chain.sendInstallProposal(installProposalRequest, peers);


            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();


            for (ProposalResponse response : responses) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);

                } else {
                    failed.add(response);
                }

            }
            out("Received %d install proposal responses. Successful+verified: %d . Failed: %d", responses.size(), successful.size(), failed.size());

            if (successful.size() < 1) {  //choose this as an arbitrary limit right now.

                if (failed.size() == 0) {
                    throw new Exception("No endorsers found ");

                }
                ProposalResponse first = failed.iterator().next();

                throw new Exception("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
            }
            ProposalResponse firstInstallProposalResponse = successful.iterator().next();
            final ChainCodeID chainCodeID = firstInstallProposalResponse.getChainCodeID();
            //Note install chain code does not require transaction no need to send to Orderers

            ///////////////
            //// Instantiate chain code.


            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();


            instantiateProposalRequest.setChaincodeID(chainCodeID);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs(new String[]{"Jane", "500", "John", "1000"});
            out("Sending instantiateProposalRequest Jane with a and John set to 500 and 1000 respectively");

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

            if (successful.size() < 1) {  //choose this as an arbitrary limit right now.

                if (failed.size() == 0) {
                    throw new Exception("No endorsers found ");

                }
                ProposalResponse first = failed.iterator().next();

                throw new Exception("Not enough endorsers for instantiate  :" + successful.size() + ".  " + first.getMessage());
            }


            /// Send instantiate transaction.
            chain.sendTransaction(successful, orderers).thenApply(block -> {

                try {

                    out("Successfully completed chaincode instantiation.");

                    out("Creating invoke proposal");

                    TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();

                    transactionProposalRequest.setChaincodeID(chainCodeID);
                    transactionProposalRequest.setFcn("invoke");
                    transactionProposalRequest.setArgs(new String[]{"move", "Jane", "John", "200"});

                    Collection<ProposalResponse> invokePropResp = chain.sendTransactionProposal(transactionProposalRequest, peers);


                    successful.clear();
                    failed.clear();

                    for (ProposalResponse response : invokePropResp) {

                        if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                            successful.add(response);
                        } else {
                            failed.add(response);
                        }

                    }
                    out("Received %d invoke proposal responses. Successful+verified: %d . Failed: %d", invokePropResp.size(), successful.size(), failed.size());


                    if (successful.size() < 1) {  //choose this as an arbitrary limit right now.

                        if (failed.size() == 0) {
                            throw new Exception("No endorsers found ");

                        }
                        ProposalResponse firstInvokeProposalResponse = failed.iterator().next();


                        throw new Exception("Not enough endorsers :" + successful.size() + ".  " + firstInvokeProposalResponse.getMessage());


                    }
                    out("Successfully received invoke proposal response.");

                    ////////////////////////////
                    // Invoke Transaction
                    //

                    out("Invoking chain code to move 200 from Jane to John.");

                    return chain.sendTransaction(successful, orderers).get(20, TimeUnit.SECONDS);


                } catch (Exception e) {

                    throw new RuntimeException(e);

                }


            }).thenApply(block -> {
                try {
                    out("Successfully ordered invoke chain code. BlockClass" + block.getClass());


                    ////////////////////////////
                    // Query Proposal
                    //


                    out("Now query chain code for the value of John.");

                    // TransactionProposalRequest qr = TransactionProposalRequest.newInstance();
                    QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();

                    queryByChaincodeRequest.setArgs(new String[]{"query", "John"});
                    queryByChaincodeRequest.setFcn("invoke");
                    queryByChaincodeRequest.setChaincodeID(chainCodeID);

                    Collection<ProposalResponse> queryProposals = chain.queryByChaincode(queryByChaincodeRequest, peers);

                    for (ProposalResponse proposalResponse : queryProposals) {
                        if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                            return new Exception("Failed invoke proposal.  status: " + proposalResponse.getStatus() + ". messages: " + proposalResponse.getMessage());

                        }

                    }

                    out("Successfully received query response.");

                    String payload = queryProposals.iterator().next().getProposalResponse().getResponse().getPayload().toStringUtf8();

                    out("Query payload of John returned %s", payload);

                    Assert.assertEquals(payload, "1200");

                    if (!payload.equals("1200")) {
                        return new Exception("Expected 1200 for value John but got: " + payload);
                    }


                    return null;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            }).exceptionally(e -> {
                System.err.println("Bad status value for proposals transaction: " + e.getMessage());
                System.exit(8);
                return null;
            }).get(40, TimeUnit.SECONDS);
            out("That's all folks!");


        } catch (Exception e) {
            out("Caught an exception");
            e.printStackTrace();

            Assert.fail(e.getMessage());

        }

    }


    private static void constructChain(HFClient client) throws Exception {
        //////////////////////////// TODo Needs to be made out of bounds and here chain just retrieved
        //Construct the chain
        //

        Chain newChain = client.newChain(CHAIN_NAME);

        int i=0;

        for (String peerloc : PEER_LOCATIONS) {
            Peer peer = client.newPeer("peer_" + i++, peerloc);
            newChain.addPeer(peer);
        }

        for (String orderloc : ORDERER_LOCATIONS) {
            Orderer orderer = client.newOrderer("myorderer", orderloc);
            newChain.addOrderer(orderer);
        }

        for (String eventHub : EVENTHUB_LOCATIONS) {
            EventHub orderer = client.newEventHub("myeventhub", eventHub);
            newChain.addEventHub(orderer);
        }

    }


    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(String.format(format, args));
        System.err.flush();
        System.out.flush();

    }

}
