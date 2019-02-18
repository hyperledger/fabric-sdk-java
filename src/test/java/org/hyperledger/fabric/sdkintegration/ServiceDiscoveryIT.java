/*
 *
 *  Copyright 2016,2018 IBM - All Rights Reserved.
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
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.ServiceDiscovery;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.junit.Test;

import static java.lang.String.format;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import static org.hyperledger.fabric.sdk.Channel.DiscoveryOptions.createDiscoveryOptions;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.junit.Assert.assertFalse;

public class ServiceDiscoveryIT {
    private static final TestConfig testConfig = TestConfig.getConfig();

    File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");

    String CHAIN_CODE_NAME = "example_cc_go";
    TransactionRequest.Type CHAIN_CODE_LANG = TransactionRequest.Type.GO_LANG;

    @Test
    public void setup() throws Exception {
        //Persistence is not part of SDK. Sample file store is for demonstration purposes only!
        //   MUST be replaced with more robust application implementation  (Database, LDAP)
        if (!testConfig.runServiceDiscoveryIT()) {
            out("\n\n\nNOT RUNNING: \"ServiceDiscoveryIT\"  runServiceDiscoveryIT=%b.\n", testConfig.runServiceDiscoveryIT());
            return;
        }
        out("\n\n\nRUNNING: %s.\n", "ServiceDiscoveryIT");

        SampleStore sampleStore = new SampleStore(sampleStoreFile);

        //  SampleUser peerAdmin = sampleStore.getMember("admin", "peerOrg1");
        SampleUser user1 = sampleStore.getMember("user1", "peerOrg1");
        final HFClient client = HFClient.createNewInstance();
        testConfig.getIntegrationTestsSampleOrg("peerOrg1");

        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        client.setUserContext(user1);
        Properties properties = testConfig.getPeerProperties("peer0.org1.example.com");

        final String protocol = testConfig.isRunningFabricTLS() ? "grpcs:" : "grpc:";

        Properties sdprops = new Properties();

        //Create initial discovery peer.

        Peer discoveryPeer = client.newPeer("peer0.org1.example.com", protocol + "//localhost:7051", properties);
        Channel foo = client.newChannel("foo"); //create channel that will be discovered.

        foo.addPeer(discoveryPeer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.SERVICE_DISCOVERY, PeerRole.LEDGER_QUERY, PeerRole.EVENT_SOURCE, PeerRole.CHAINCODE_QUERY)));

        // Need to provide client TLS certificate and key files when running mutual tls.
        if (testConfig.isRunningFabricTLS()) {
            sdprops.put("org.hyperledger.fabric.sdk.discovery.default.clientCertFile", "src/test/fixture/sdkintegration/e2e-2Orgs/v1.2/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.crt");
            sdprops.put("org.hyperledger.fabric.sdk.discovery.default.clientKeyFile", "src/test/fixture/sdkintegration/e2e-2Orgs/v1.2/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.key");

            // Need to do host name override for true tls in testing environment
            sdprops.put("org.hyperledger.fabric.sdk.discovery.endpoint.hostnameOverride.localhost:7050", "orderer.example.com");
            sdprops.put("org.hyperledger.fabric.sdk.discovery.endpoint.hostnameOverride.localhost:7051", "peer0.org1.example.com");
            sdprops.put("org.hyperledger.fabric.sdk.discovery.endpoint.hostnameOverride.localhost:7056", "peer1.org1.example.com");
        } else {
            sdprops.put("org.hyperledger.fabric.sdk.discovery.default.protocol", "grpc:");
        }
        foo.setServiceDiscoveryProperties(sdprops);

        final byte[] bytes = foo.serializeChannel(); // Next 3 lines are for testing purposes only!
        foo.shutdown(false);
        foo = client.deSerializeChannel(bytes);

        foo.initialize(); // initialize the channel.

        Set<String> expect = new HashSet<>(Arrays.asList(protocol + "//orderer.example.com:7050")); //discovered orderer
        for (Orderer orderer : foo.getOrderers()) {
            expect.remove(orderer.getUrl());
        }
        assertTrue(expect.isEmpty());

        final Collection<String> discoveredChaincodeNames = foo.getDiscoveredChaincodeNames();

        assertTrue(discoveredChaincodeNames.contains(CHAIN_CODE_NAME));

        ChaincodeID.Builder chaincodeIDBuilder = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME);

        ChaincodeID chaincodeID = chaincodeIDBuilder.build();

        ///////////////
        /// Send transaction proposal to all peers
        TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeID(chaincodeID);
        transactionProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
        transactionProposalRequest.setFcn("move");
        transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
        transactionProposalRequest.setArgs("a", "b", "1");

        //Send proposal request discovering the what endorsers (peers) are needed.
        Collection<ProposalResponse> transactionPropResp =
                foo.sendTransactionProposalToEndorsers(transactionProposalRequest,
                        createDiscoveryOptions().setEndorsementSelector(ServiceDiscovery.EndorsementSelector.ENDORSEMENT_SELECTION_RANDOM)
                                .setForceDiscovery(true));
        assertFalse(transactionPropResp.isEmpty());

        transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeID(chaincodeID);
        transactionProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
        transactionProposalRequest.setFcn("move");
        transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
        transactionProposalRequest.setArgs("a", "b", "1");

        //Send proposal request discovering the what endorsers (peers) are needed.
        transactionPropResp =
                foo.sendTransactionProposalToEndorsers(transactionProposalRequest,
                        createDiscoveryOptions().ignoreEndpoints("blah.blah.blah.com:90", "blah.com:80",
                                // aka peer0.org1.example.com our discovery peer. Lets ignore it in endorsers selection and see if other discovered peer endorses.
                                "peer0.org1.example.com:7051")
                        // if chaincode makes additional chaincode calls or uses collections you should add them with setServiceDiscoveryChaincodeInterests
                        //         .setServiceDiscoveryChaincodeInterests(Channel.ServiceDiscoveryChaincodeCalls.createServiceDiscoveryChaincodeCalls("someOtherChaincodeName").addCollections("collection1", "collection2"))
                );
        assertEquals(transactionPropResp.size(), 1);
        final ProposalResponse proposalResponse = transactionPropResp.iterator().next();
        final Peer peer = proposalResponse.getPeer();
        assertEquals(protocol + "//peer1.org1.example.com:7056", peer.getUrl()); // not our discovery peer but the discovered one.

        String expectedTransactionId = null;

        final StringBuilder evenTransactionId = new StringBuilder();

        for (ProposalResponse response : transactionPropResp) {
            expectedTransactionId = response.getTransactionID();
            if (response.getStatus() != ProposalResponse.Status.SUCCESS || !response.isVerified()) {

                fail("Failed status bad endorsement");
            }
        }
        //Send it to the orderer that was discovered.
        foo.sendTransaction(transactionPropResp).thenApply(transactionEvent -> {

            evenTransactionId.setLength(0);

            evenTransactionId.append(transactionEvent.getTransactionID());

            return null;
        }).exceptionally(e -> {
            if (e instanceof TransactionEventException) {
                BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                if (te != null) {
                    throw new AssertionError(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()), e);
                }
            }

            throw new AssertionError(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()), e);

        }).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

        assertEquals(expectedTransactionId, evenTransactionId.toString());

        out("That's all folks!");
    }

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

}
