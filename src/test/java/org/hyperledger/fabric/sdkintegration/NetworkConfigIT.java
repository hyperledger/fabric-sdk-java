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

package org.hyperledger.fabric.sdkintegration;

import java.io.File;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import org.hyperledger.fabric.protos.peer.Query.ChaincodeInfo;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.ChaincodeResponse.Status;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.NetworkConfig;
import org.hyperledger.fabric.sdk.NetworkConfig.CAInfo;
import org.hyperledger.fabric.sdk.NetworkConfig.UserInfo;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.SDKUtils;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric.sdk.testutils.TestUtils.MockUser;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.BeforeClass;
import org.junit.Test;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.getMockUser;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Integration test for the Network Configuration YAML (/JSON) file
 * <p>
 * This test requires that End2endIT has previously been run in order to set up the channel.
 * It has no dependencies on any of the other integration tests.
 * That is, it can be run with or without having run the other End to End tests (apart from End2EndIT).
 * <br>
 * Furthermore, it can be executed multiple times without having to restart the blockchain.
 * <p>
 * One other requirement is that the network configuration file matches the topology
 * that is set up by End2endIT.
 * <p>
 * It first examines the "foo" channel and checks that CHAIN_CODE_NAME has been instantiated on the channel,
 * and if not it deploys the chaincode with that name.
 */
public class NetworkConfigIT {

    private static final TestConfig testConfig = TestConfig.getConfig();

    private static final String TEST_ORG = "Org1";

    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private static final String CHAIN_CODE_PATH = "github.com/example_cc";

    private static final String CHAIN_CODE_NAME = "cc-NetworkConfigTest-001";

    private static final String CHAIN_CODE_VERSION = "1";

    private static final String FOO_CHANNEL_NAME = "foo";

    private static final TestConfigHelper configHelper = new TestConfigHelper();

    private static NetworkConfig networkConfig;

    private static Map<String, User> orgRegisteredUsers = new HashMap<>();

    @BeforeClass
    public static void doMainSetup() throws Exception {
        out("\n\n\nRUNNING: NetworkConfigIT.\n");

        resetConfig();
        configHelper.customizeConfig();

        // Use the appropriate TLS/non-TLS network config file
        networkConfig = NetworkConfig.fromYamlFile(testConfig.getTestNetworkConfigFileYAML());

        networkConfig.getOrdererNames().forEach(ordererName -> {
            try {
                Properties ordererProperties = networkConfig.getOrdererProperties(ordererName);
                Properties testProp = testConfig.getEndPointProperties("orderer", ordererName);
                ordererProperties.setProperty("clientCertFile", testProp.getProperty("clientCertFile"));
                ordererProperties.setProperty("clientKeyFile", testProp.getProperty("clientKeyFile"));
                networkConfig.setOrdererProperties(ordererName, ordererProperties);

            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }
        });

        networkConfig.getPeerNames().forEach(peerName -> {
            try {
                Properties peerProperties = networkConfig.getPeerProperties(peerName);
                Properties testProp = testConfig.getEndPointProperties("peer", peerName);
                peerProperties.setProperty("clientCertFile", testProp.getProperty("clientCertFile"));
                peerProperties.setProperty("clientKeyFile", testProp.getProperty("clientKeyFile"));
                networkConfig.setPeerProperties(peerName, peerProperties);

            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }
        });


        //Check if we get access to defined CAs!
        NetworkConfig.OrgInfo org = networkConfig.getOrganizationInfo("Org1");
        CAInfo caInfo = org.getCertificateAuthorities().get(0);

        HFCAClient hfcaClient = HFCAClient.createNewInstance(caInfo);
        assertEquals(hfcaClient.getCAName(), caInfo.getCAName());
        HFCAInfo info = hfcaClient.info(); //makes actual REST call.
        assertEquals(caInfo.getCAName(), info.getCAName());

        Collection<UserInfo> registrars = caInfo.getRegistrars();
        assertTrue(!registrars.isEmpty());
        UserInfo registrar = registrars.iterator().next();
        registrar.setEnrollment(hfcaClient.enroll(registrar.getName(), registrar.getEnrollSecret()));
        MockUser mockuser = getMockUser(org.getName() + "_mock_" + System.nanoTime(), registrar.getMspId());
        RegistrationRequest rr = new RegistrationRequest(mockuser.getName(), "org1.department1");
        mockuser.setEnrollmentSecret(hfcaClient.register(rr, registrar));
        mockuser.setEnrollment(hfcaClient.enroll(mockuser.getName(), mockuser.getEnrollmentSecret()));
        orgRegisteredUsers.put(org.getName(), mockuser);

        org = networkConfig.getOrganizationInfo("Org2");
        caInfo = org.getCertificateAuthorities().get(0);

        hfcaClient = HFCAClient.createNewInstance(caInfo);
        assertEquals(hfcaClient.getCAName(), caInfo.getCAName());
        info = hfcaClient.info(); //makes actual REST call.
        assertEquals(info.getCAName(), "");

        registrars = caInfo.getRegistrars();
        assertTrue(!registrars.isEmpty());
        registrar = registrars.iterator().next();
        registrar.setEnrollment(hfcaClient.enroll(registrar.getName(), registrar.getEnrollSecret()));
        mockuser = getMockUser(org.getName() + "_mock_" + System.nanoTime(), registrar.getMspId());
        rr = new RegistrationRequest(mockuser.getName(), "org1.department1");
        mockuser.setEnrollmentSecret(hfcaClient.register(rr, registrar));
        mockuser.setEnrollment(hfcaClient.enroll(mockuser.getName(), mockuser.getEnrollmentSecret()));
        orgRegisteredUsers.put(org.getName(), mockuser);

        deployChaincodeIfRequired();
    }

    // Determines whether or not the chaincode has been deployed and deploys it if necessary
    private static void deployChaincodeIfRequired() throws Exception {

        ////////////////////////////
        // Setup client
        HFClient client = getTheClient();

        Channel channel = constructChannel(client, FOO_CHANNEL_NAME);

        // Use any old peer...
        Peer peer = channel.getPeers().iterator().next();
        if (!checkInstantiatedChaincode(channel, peer, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION)) {

            // The chaincode we require does not exist, so deploy it...
            deployChaincode(client, channel, CHAIN_CODE_NAME, CHAIN_CODE_PATH, CHAIN_CODE_VERSION);
        }

    }

    // Returns a new client instance
    private static HFClient getTheClient() throws Exception {

        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        User peerAdmin = getAdminUser(TEST_ORG);
        client.setUserContext(peerAdmin);

        return client;
    }

    private static User getAdminUser(String orgName) throws Exception {

        return networkConfig.getPeerAdmin(orgName);
    }

    @Test
    public void testUpdate1() throws Exception {

        // Setup client and channel instances
        HFClient client = getTheClient();
        Channel channel = constructChannel(client, FOO_CHANNEL_NAME);

        final ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
                .setVersion(CHAIN_CODE_VERSION)
                .setPath(CHAIN_CODE_PATH).build();

        final String channelName = channel.getName();

        out("Running testUpdate1 - Channel %s", channelName);

        int moveAmount = 5;
        String originalVal = queryChaincodeForCurrentValue(client, channel, chaincodeID);
        String newVal = "" + (Integer.parseInt(originalVal) + moveAmount);

        out("Original value = %s", originalVal);

        //user registered user
        client.setUserContext(orgRegisteredUsers.get("Org1")); // only using org1

        // Move some assets
        moveAmount(client, channel, chaincodeID, "a", "b", "" + moveAmount, null).thenApply(transactionEvent -> {
            // Check that they were moved
            queryChaincodeForExpectedValue(client, channel, newVal, chaincodeID);
            return null;

        }).thenApply(transactionEvent -> {
            // Move them back
            try {
                return moveAmount(client, channel, chaincodeID, "b", "a", "" + moveAmount, null).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }).thenApply(transactionEvent -> {
            // Check that they were moved back
            queryChaincodeForExpectedValue(client, channel, originalVal, chaincodeID);
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

        channel.shutdown(true); // Force channel to shutdown clean up resources.

        out("testUpdate1 - done");
        out("That's all folks!");
    }

    private static void queryChaincodeForExpectedValue(HFClient client, Channel channel, final String expect, ChaincodeID chaincodeID) {

        out("Now query chaincode on channel %s for the value of b expecting to see: %s", channel.getName(), expect);

        String value = queryChaincodeForCurrentValue(client, channel, chaincodeID);
        assertEquals(expect, value);
    }

    // Returns the current value of b's assets
    private static String queryChaincodeForCurrentValue(HFClient client, Channel channel, ChaincodeID chaincodeID) {

        out("Now query chaincode on channel %s for the current value of b", channel.getName());

        QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
        queryByChaincodeRequest.setArgs("b");
        queryByChaincodeRequest.setFcn("query");
        queryByChaincodeRequest.setChaincodeID(chaincodeID);

        Collection<ProposalResponse> queryProposals;

        try {
            queryProposals = channel.queryByChaincode(queryByChaincodeRequest);
        } catch (Exception e) {
            throw new CompletionException(e);
        }

        String expect = null;
        for (ProposalResponse proposalResponse : queryProposals) {
            if (!proposalResponse.isVerified() || proposalResponse.getStatus() != Status.SUCCESS) {
                fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                        ". Messages: " + proposalResponse.getMessage()
                        + ". Was verified : " + proposalResponse.isVerified());
            } else {
                String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                out("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                if (expect != null) {
                    assertEquals(expect, payload);
                } else {
                    expect = payload;
                }
            }
        }
        return expect;
    }

    private static CompletableFuture<BlockEvent.TransactionEvent> moveAmount(HFClient client, Channel channel, ChaincodeID chaincodeID, String from, String to, String moveAmount, User user) throws Exception {

        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();

        ///////////////
        /// Send transaction proposal to all peers
        TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeID(chaincodeID);
        transactionProposalRequest.setFcn("move");
        transactionProposalRequest.setArgs(from, to, moveAmount);
        transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
        if (user != null) { // specific user use that
            transactionProposalRequest.setUserContext(user);
        }
        out("sending transaction proposal to all peers with arguments: move(%s,%s,%s)", from, to, moveAmount);

        Collection<ProposalResponse> invokePropResp = channel.sendTransactionProposal(transactionProposalRequest);
        for (ProposalResponse response : invokePropResp) {
            if (response.getStatus() == Status.SUCCESS) {
                out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successful.add(response);
            } else {
                failed.add(response);
            }
        }

        // Check that all the proposals are consistent with each other. We should have only one set
        // where all the proposals above are consistent.
        Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(invokePropResp);
        if (proposalConsistencySets.size() != 1) {
            fail(format("Expected only one set of consistent move proposal responses but got %d", proposalConsistencySets.size()));
        }

        out("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                invokePropResp.size(), successful.size(), failed.size());
        if (failed.size() > 0) {
            ProposalResponse firstTransactionProposalResponse = failed.iterator().next();

            throw new ProposalException(format("Not enough endorsers for invoke(move %s,%s,%s):%d endorser error:%s. Was verified:%b",
                    from, to, moveAmount, firstTransactionProposalResponse.getStatus().getStatus(), firstTransactionProposalResponse.getMessage(), firstTransactionProposalResponse.isVerified()));
        }
        out("Successfully received transaction proposal responses.");

        ////////////////////////////
        // Send transaction to orderer
        out("Sending chaincode transaction(move %s,%s,%s) to orderer.", from, to, moveAmount);
        if (user != null) {
            return channel.sendTransaction(successful, user);
        }

        return channel.sendTransaction(successful);
    }

    private static ChaincodeID deployChaincode(HFClient client, Channel channel, String ccName, String ccPath, String ccVersion) throws Exception {

        out("deployChaincode - enter");
        ChaincodeID chaincodeID = null;

        try {

            final String channelName = channel.getName();
            out("deployChaincode - channelName = " + channelName);

            Collection<Orderer> orderers = channel.getOrderers();
            Collection<ProposalResponse> responses;
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();

            chaincodeID = ChaincodeID.newBuilder().setName(ccName)
                    .setVersion(ccVersion)
                    .setPath(ccPath).build();

            ////////////////////////////
            // Install Proposal Request
            //
            out("Creating install proposal");

            InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
            installProposalRequest.setChaincodeID(chaincodeID);

            ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
            installProposalRequest.setChaincodeSourceLocation(new File(TEST_FIXTURES_PATH + "/sdkintegration/gocc/sample1"));

            installProposalRequest.setChaincodeVersion(ccVersion);

            out("Sending install proposal");

            ////////////////////////////
            // only a client from the same org as the peer can issue an install request
            int numInstallProposal = 0;

            Collection<Peer> peersFromOrg = channel.getPeers();
            numInstallProposal = numInstallProposal + peersFromOrg.size();
            responses = client.sendInstallProposal(installProposalRequest, peersFromOrg);

            for (ProposalResponse response : responses) {
                if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
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

            ///////////////
            //// Instantiate chaincode.
            //
            // From the docs:
            // The instantiate transaction invokes the lifecycle System Chaincode (LSCC) to create and initialize a chaincode on a channel
            // After being successfully instantiated, the chaincode enters the active state on the channel and is ready to process any transaction proposals of type ENDORSER_TRANSACTION

            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
            instantiateProposalRequest.setChaincodeID(chaincodeID);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs("a", "500", "b", "999");

            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);

            /*
              policy OR(Org1MSP.member, Org2MSP.member) meaning 1 signature from someone in either Org1 or Org2
              See README.md Chaincode endorsement policies section for more details.
            */
            ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
            chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
            instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);

            out("Sending instantiateProposalRequest to all peers...");
            successful.clear();
            failed.clear();

            responses = channel.sendInstantiationProposal(instantiateProposalRequest);

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
            out("Sending instantiateTransaction to orderer...");
            CompletableFuture<TransactionEvent> future = channel.sendTransaction(successful, orderers);

            out("calling get...");
            TransactionEvent event = future.get(30, TimeUnit.SECONDS);
            out("get done...");

            assertTrue(event.isValid()); // must be valid to be here.
            out("Finished instantiate transaction with transaction id %s", event.getTransactionID());

        } catch (Exception e) {
            e.printStackTrace();
            out("Caught an exception running channel %s", channel.getName());
            fail("Test failed with error : " + e.getMessage());
        }

        return chaincodeID;
    }

    private static Channel constructChannel(HFClient client, String channelName) throws Exception {

        //Channel newChannel = client.getChannel(channelName);
        Channel newChannel = client.loadChannelFromConfig(channelName, networkConfig);
        if (newChannel == null) {
            throw new RuntimeException("Channel " + channelName + " is not defined in the config file!");
        }

        return newChannel.initialize();
    }

    // Determines if the specified chaincode has been instantiated on the channel
    private static boolean checkInstantiatedChaincode(Channel channel, Peer peer, String ccName, String ccPath, String ccVersion) throws InvalidArgumentException, ProposalException {
        out("Checking instantiated chaincode: %s, at version: %s, on peer: %s", ccName, ccVersion, peer.getName());
        List<ChaincodeInfo> ccinfoList = channel.queryInstantiatedChaincodes(peer);

        boolean found = false;

        for (ChaincodeInfo ccifo : ccinfoList) {
            found = ccName.equals(ccifo.getName()) && ccPath.equals(ccifo.getPath()) && ccVersion.equals(ccifo.getVersion());
            if (found) {
                break;
            }

        }

        return found;
    }

    private static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

}
