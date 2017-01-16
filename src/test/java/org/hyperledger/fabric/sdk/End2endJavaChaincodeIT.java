package org.hyperledger.fabric.sdk;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;

/**
 * Test end to end scenario
 */
public class End2endJavaChaincodeIT {

    static final String CHAIN_CODE_NAME = "simplesample";
    static final String CHAIN_CODE_PATH = "src/test/fixture/java-chaincode/SimpleSample/root/chaincode";
    static final String CHAIN_NAME = "chain1";

    final static Collection<String> PEER_LOCATIONS = Arrays.asList("grpc://localhost:7051");

    //final static Collection<String> ORDERER_LOCATIONS = Arrays.asList("grpc://localhost:5005");// NonVagrant
    final static Collection<String> ORDERER_LOCATIONS = Arrays.asList("grpc://localhost:5151"); //Vagrant maps to this

    final static String MEMBER_SERVICES_LOCATION = "grpc://localhost:7054";

    private static final int ORDER_WAIT_TIME = 14;

    @Test
    @Ignore
    public void setup() {

        HFClient client = HFClient.createNewInstance();
        try {

            //////////////////////////// TODo Needs to be made out of bounds and here chain just retrieved
            //Construct the chain
            //

            constructChain(client);

            client.setUserContext(new User("admin")); // User will be defined by pluggable

            Chain chain = client.getChain(CHAIN_NAME);


            chain.setInvokeWaitTime(1000);
            chain.setDeployWaitTime(12000);

            chain.setMemberServicesUrl(MEMBER_SERVICES_LOCATION, null);

            chain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home") + "/test.properties"));
            User admin = chain.enroll("admin", "Xurw3yU9zI0l");

            chain.initialize();

            Collection<Peer> peers = chain.getPeers();
            Collection<Orderer> orderers = chain.getOrderers();

            ////////////////////////////
            //Deploy Proposal Request
            //

            DeploymentProposalRequest deploymentProposalRequest = client.newDeploymentProposalRequest();
            deploymentProposalRequest.setChaincodeName(CHAIN_CODE_NAME);
            deploymentProposalRequest.setChaincodePath(CHAIN_CODE_PATH);
            deploymentProposalRequest.setChaincodeLanguage(TransactionRequest.Type.JAVA);
            deploymentProposalRequest.setFcn("init");
            deploymentProposalRequest.setArgs(new String[]{"Jane", "500", "John", "1000"});
            out("Deploying chain code with Jane and John set to 500 and 1000 respectively");


            Collection<ProposalResponse> responses = chain.sendDeploymentProposal(deploymentProposalRequest, peers);

            //////////////////////
            //Deploy Transaction
            //

            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();


            for (ProposalResponse response : responses) {
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);

                } else {
                    failed.add(response);
                }

            }
            out("Received %d successful proposal responses.", successful.size());

            if (successful.size() < 1) {  //choose this as an arbitrary limit right now.

                if (failed.size() == 0) {
                    throw new Exception("No endorsers found ");

                }
                ProposalResponse first = failed.iterator().next();

                throw new Exception("Not enough endorsers :" + successful.size() + ".  " + first.getProposalResponse().getResponse().getMessage());
            }
            ProposalResponse firstDeployProposalResponse = successful.iterator().next();
            final ChainCodeID chainCodeID = firstDeployProposalResponse.getChainCodeID();


            Collection<TransactionResponse> deploytransactionResponses = chain.sendTransaction(successful, orderers);
            TransactionResponse deployTransactionResponse = deploytransactionResponses.iterator().next();


            ////////////////////////////
            // Invoke Endorsement Request
            //

            if (deployTransactionResponse.getStatus() != TransactionResponse.Status.SUCCESS) {

                System.err.println("Bad status value for proposals transaction: " + deployTransactionResponse.getStatus());
                System.exit(8);

            }

            out("Successfully ordered deployment endorsement.");
            out("Need to wait for %d seconds", ORDER_WAIT_TIME);
            Thread.sleep(ORDER_WAIT_TIME * 1000);

            InvokeProposalRequest invokeProposalRequest = client.newInvokeProposalRequest();

            invokeProposalRequest.setChaincodeID(chainCodeID);
            invokeProposalRequest.setFcn("invoke");
            invokeProposalRequest.setArgs(new String[]{"move", "Jane", "John", "200"});

            Collection<ProposalResponse> invokePropResp = chain.sendInvokeProposal(invokeProposalRequest, peers);

            successful.clear();
            failed.clear();

            for (ProposalResponse response : responses) {

                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);
                } else {
                    failed.add(response);
                }

            }
            out("Received %d successful proposal responses.", successful.size());


            if (successful.size() < 1) {  //choose this as an arbitrary limit right now.

                if (failed.size() == 0) {
                    throw new Exception("No endorsers found ");

                }
                firstDeployProposalResponse = failed.iterator().next();


                throw new Exception("Not enough endorsers :" + successful.size() + ".  " + firstDeployProposalResponse.getMessage());


            }
            out("Successfully received invoke proposal response.");

            ////////////////////////////
            // Invoke Transaction
            //

            out("Invoking chain code to move 200 from Jane to John.");

            Collection<TransactionResponse> invokeTransactionResponses = chain.sendTransaction(invokePropResp, orderers);
            TransactionResponse invokeTransactionResponse = invokeTransactionResponses.iterator().next();
            if (invokeTransactionResponse.getStatus() != TransactionResponse.Status.SUCCESS) {

                System.err.println("Bad status value for invoke " + invokeTransactionResponse.getStatus());
                System.exit(8);

            }

            out("Successfully ordered invoke chain code.");
            out("Need to wait for %d seconds", ORDER_WAIT_TIME);

            ////////////////////////////
            // Query Proposal
            //


            out("Now query chain code for the value of John.");
            Thread.sleep(ORDER_WAIT_TIME * 1000);

            // InvokeProposalRequest qr = InvokeProposalRequest.newInstance();
            QueryProposalRequest queryProposalRequest = client.newQueryProposalRequest();

            queryProposalRequest.setArgs(new String[]{"query", "John"});
            queryProposalRequest.setFcn("invoke");
            queryProposalRequest.setChaincodeID(chainCodeID);


            Collection<ProposalResponse> queryProposals = chain.sendQueryProposal(queryProposalRequest, peers);


            for (ProposalResponse proposalResponse : queryProposals) {
                if (proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {

                    throw new Exception("Failed invoke proposal.  status: " + proposalResponse.getStatus() + ". messages: " + proposalResponse.getMessage());
                }

            }

            out("Successfully received query response.");

            String payload = queryProposals.iterator().next().getPayload().toStringUtf8();

            out("Query payload of John returned %s", payload);

            Assert.assertEquals(payload, "1200");

            if (!payload.equals("1200")) {
                throw new Exception("Expected 1200 for value John but got: " + payload);
            }

        } catch (Exception e) {
            out("Caught an excpetion");
            e.printStackTrace();

            Assert.fail(e.getMessage());

        }
        out("That's all folks!");


    }


    private static void constructChain(HFClient client) throws Exception {
        //////////////////////////// TODo Needs to be made out of bounds and here chain just retrieved
        //Construct the chain
        //

        Chain newChain = client.newChain(CHAIN_NAME);

        for (String peerloc : PEER_LOCATIONS) {
            Peer peer = client.newPeer(peerloc);
            peer.setName("peer1");
            newChain.addPeer(peer);
        }

        for (String orderloc : ORDERER_LOCATIONS) {
            Orderer orderer = client.newOrderer(orderloc);
            newChain.addOrderer(orderer);
        }

    }


    static void out(String format, Object... args) {

        System.out.println(String.format(format, (Object[]) args));

    }

}
