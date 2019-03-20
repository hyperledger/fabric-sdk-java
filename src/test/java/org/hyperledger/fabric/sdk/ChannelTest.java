/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

//Allow throwing undeclared checked execeptions in mock code.
//CHECKSTYLE.OFF: IllegalImport

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.Channel.NOfEvents;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.hyperledger.fabric.sdk.transaction.InstallProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import sun.misc.Unsafe;

import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.assertArrayListEquals;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.getMockUser;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.matchesRegex;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.setField;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.tarBytesToEntryArrayList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

//CHECKSTYLE.ON: IllegalImport

public class ChannelTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static HFClient hfclient = null;
    private static Channel shutdownChannel = null;
    private static final String BAD_STUFF = "this is bad!";
    private static Orderer throwOrderer = null;
    private static Channel throwChannel = null;
    private static final String CHANNEL_NAME = "channel3";

    @BeforeClass
    public static void setupClient() {

        try {
            hfclient = TestHFClient.newInstance();

            shutdownChannel = new Channel("shutdown", hfclient);
            shutdownChannel.addOrderer(hfclient.newOrderer("shutdow_orderer", "grpc://localhost:99"));

            setField(shutdownChannel, "shutdown", true);

            throwOrderer = new Orderer("foo", "grpc://localhost:8", null) {

                @Override
                Ab.BroadcastResponse sendTransaction(Common.Envelope transaction) throws Exception {
                    throw new Exception(BAD_STUFF);
                }

                @Override
                Ab.DeliverResponse[] sendDeliver(Common.Envelope transaction) throws TransactionException {
                    throw new TransactionException(BAD_STUFF);
                }

            };

            throwChannel = new Channel("throw", hfclient);

            throwChannel.addOrderer(throwOrderer);

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }
    }

    @Test
    public void testChannelCreation() {

        try {

            final String channelName = "channel3";
            Channel testchannel = new Channel(channelName, hfclient);
            Assert.assertEquals(channelName, testchannel.getName());
            Assert.assertEquals(testchannel.client, hfclient);
            Assert.assertEquals(testchannel.getOrderers().size(), 0);
            Assert.assertEquals(testchannel.getPeers().size(), 0);
            Assert.assertEquals(testchannel.isInitialized(), false);

        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected exception " + e.getMessage());
        }

    }

    @Test
    public void testChannelAddPeer() throws Exception {

        final String channelName = "channel3";
        final Channel testchannel = new Channel(channelName, hfclient);
        final Peer peer = hfclient.newPeer("peer_", "grpc://localhost:7051");

        testchannel.addPeer(peer);

        Assert.assertEquals(testchannel.getPeers().size(), 1);
        Assert.assertEquals(testchannel.getPeers().iterator().next(), peer);

    }

    @Test
    public void testChannelAddOrder() throws Exception {

        final Channel testChannel = new Channel(CHANNEL_NAME, hfclient);
        final Orderer orderer = hfclient.newOrderer("testorder", "grpc://localhost:7051");

        testChannel.addOrderer(orderer);

        Assert.assertEquals(testChannel.getOrderers().size(), 1);
        Assert.assertEquals(testChannel.getOrderers().iterator().next(), orderer);

    }

    @Test
    public void testChannelNullClient() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel client is invalid can not be null.");

        new Channel(CHANNEL_NAME, null);

    }

    @Test
    public void testChannelAddNullPeer() {
        Channel testChannel = null;

        try {

            testChannel = new Channel(CHANNEL_NAME, hfclient);

            testChannel.addPeer(null);

            Assert.fail("Expected set null peer to throw exception.");

        } catch (InvalidArgumentException e) {
            Assert.assertEquals(testChannel.getPeers().size(), 0);
            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
        }

    }

    @Test
    public void testChannelAddNoNamePeer() {
        Channel testChannel = null;

        try {

            testChannel = new Channel(CHANNEL_NAME, hfclient);
            final Peer peer = hfclient.newPeer(null, "grpc://localhost:7051");

            testChannel.addPeer(peer);
            Assert.fail("Expected no named peer to throw exception.");

        } catch (Exception e) {
            Assert.assertEquals(testChannel.getPeers().size(), 0);
            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
        }

    }

    @Test
    public void testChannelAddNullOrder() {
        Channel testChannel = null;

        try {

            testChannel = new Channel(CHANNEL_NAME, hfclient);

            testChannel.addOrderer(null);

            Assert.fail("Expected set null order to throw exception.");

        } catch (InvalidArgumentException e) {
            Assert.assertEquals(testChannel.getOrderers().size(), 0);
            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
        }

    }

    @Test
    public void testChannelInitialize() throws Exception { //test may not be doable once initialize is done

        class MockChannel extends Channel {

            MockChannel(String name, HFClient client) throws InvalidArgumentException {
                super(name, client);
            }

            @Override
            protected Map<String, MSP> parseConfigBlock(boolean force) {

                return null;
            }

            @Override
            protected void loadCACertificates(boolean force) {

            }
        }

        final Channel testChannel = new MockChannel(CHANNEL_NAME, hfclient);
        final Peer peer = hfclient.newPeer("peer_", "grpc://localhost:7051");

        testChannel.addPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.ENDORSING_PEER)));
        assertFalse(testChannel.isInitialized());
        testChannel.initialize();
        Assert.assertTrue(testChannel.isInitialized());

    }
//     Allow no peers
//    @Test
//    public void testChannelInitializeNoPeer() {
//        Channel testChannel = null;
//
//        try {
//
//            testChannel = new Channel(CHANNEL_NAME, hfclient);
//
//            Assert.assertEquals(testChannel.isInitialized(), false);
//            testChannel.initialize();
//            Assert.fail("Expected initialize to throw exception with no peers.");
//
//        } catch (Exception e) {
//
//            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
//            Assert.assertFalse(testChannel.isInitialized());
//        }
//
//    }

    //Shutdown channel tests

    @Test
    public void testChannelShutdown() {

        try {

            Assert.assertTrue(shutdownChannel.isShutdown());

        } catch (Exception e) {

            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
            Assert.assertTrue(shutdownChannel.isInitialized());
        }

    }

    @Test
    public void testChannelShutdownAddPeer() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel shutdown has been shutdown.");

        Assert.assertTrue(shutdownChannel.isShutdown());
        shutdownChannel.addPeer(hfclient.newPeer("name", "grpc://myurl:90"));

    }

    @Test
    public void testChannelShutdownAddOrderer() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel shutdown has been shutdown.");

        Assert.assertTrue(shutdownChannel.isShutdown());
        shutdownChannel.addOrderer(hfclient.newOrderer("name", "grpc://myurl:90"));

    }

    @Test
    public void testChannelShutdownJoinPeer() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("Channel shutdown has been shutdown.");

        Assert.assertTrue(shutdownChannel.isShutdown());
        shutdownChannel.joinPeer(hfclient.newPeer("name", "grpc://myurl:90"));

    }

    @Test
    public void testChannelShutdownInitialize() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel shutdown has been shutdown.");

        shutdownChannel.initialize();

    }

    @Test
    public void testChannelShutdownInstiateProposal() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel shutdown has been shutdown.");

        Assert.assertTrue(shutdownChannel.isShutdown());
        shutdownChannel.sendInstantiationProposal(hfclient.newInstantiationProposalRequest());

    }

    @Test
    public void testChannelShutdownQueryTransactionByIDl() throws Exception {

        thrown.expect(InvalidArgumentException.class);

        thrown.expectMessage("Channel shutdown has been shutdown.");

        Assert.assertTrue(shutdownChannel.isShutdown());
        shutdownChannel.queryBlockByHash(new byte[] {});

    }

    @Test
    public void testChannelBadOrderer() throws Exception {
        thrown.expect(java.util.concurrent.ExecutionException.class);
        thrown.expectMessage("Channel shutdown has been shutdown.");

        CompletableFuture<BlockEvent.TransactionEvent> future = shutdownChannel.sendTransaction(null);
        future.get();

    }

    @Test
    public void testChannelBadPeerNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Peer value is null.");

        final Channel channel = createRunningChannel(null);
        channel.queryBlockByHash((Peer) null, "rick".getBytes());
    }

    @Test
    public void testChannelBadPeerDoesNotBelong() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel channel does not have peer peer2");

        final Channel channel = createRunningChannel(null);

        Collection<Peer> peers = Arrays.asList((Peer[]) new Peer[] {hfclient.newPeer("peer2", "grpc://localhost:22")});

        createRunningChannel("testChannelBadPeerDoesNotBelong", peers);

        channel.sendInstantiationProposal(hfclient.newInstantiationProposalRequest(), peers);

    }

    @Test
    public void testChannelBadPeerDoesNotBelong2() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Peer peer1 not set for channel channel");

        final Channel channel = createRunningChannel(null);

        Peer peer = channel.getPeers().iterator().next();

        final Channel channel2 = createRunningChannel("testChannelBadPeerDoesNotBelong2", null);

        setField(peer, "channel", channel2);

        channel.sendInstantiationProposal(hfclient.newInstantiationProposalRequest());

    }

    @Test
    public void testChannelBadPeerCollection() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Peer value is null.");

        final Channel channel = createRunningChannel(null);

        channel.queryByChaincode(hfclient.newQueryProposalRequest(),
                Arrays.asList((Peer[]) new Peer[] {null}));

    }

    @Test
    public void testChannelBadPeerCollectionEmpty() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Collection of peers is empty.");

        final Channel channel = createRunningChannel(null);

        channel.sendUpgradeProposal(hfclient.newUpgradeProposalRequest(),
                Arrays.asList((Peer[]) new Peer[] {})
        );

    }

    @Test
    public void testChannelBadPeerCollectionNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Collection of peers is null.");

        final Channel channel = createRunningChannel(null);

        channel.sendTransactionProposal(hfclient.newTransactionProposalRequest(), null);

    }

    @Test
    public void testTwoChannelsSameName() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel by the name testTwoChannelsSameName already exists");

        createRunningChannel("testTwoChannelsSameName", null);
        createRunningChannel("testTwoChannelsSameName", null);

    }

    @Test
    public void testSD() throws Exception {

        Channel sd = createRunningChannel("testTwoChannelsSameName", null);

        Class<?>[] declaredClasses = Channel.class.getDeclaredClasses();
        Class n = null;
        for (Class c : declaredClasses) {

            if ("org.hyperledger.fabric.sdk.Channel$SDOPeerDefaultAddition".equals(c.getName())) {
                n = c;
                break;
            }

        }
        Constructor declaredConstructor = n.getDeclaredConstructor(Properties.class);
        Properties properties1 = new Properties();
        properties1.put("org.hyperledger.fabric.sdk.discovery.default.clientKeyBytes", new byte[] {1, 2, 3});
        properties1.put("org.hyperledger.fabric.sdk.discovery.default.clientCertBytes", new byte[] {1, 2, 4});
        properties1.put("org.hyperledger.fabric.sdk.discovery.endpoint.clientKeyBytes.2.1.3.4", new byte[] {9, 2, 4});
        properties1.put("org.hyperledger.fabric.sdk.discovery.endpoint.clientKeyBytes.2.1.3.4:88", new byte[] {88, 2, 4});
        properties1.put("org.hyperledger.fabric.sdk.discovery.mspid.clientCertBytes.SPECIAL", new byte[] {1, 2, 9});
        Object o1 = declaredConstructor.newInstance(properties1);

        setField(sd, "sdPeerAddition", o1);
        setField(sd, "initialized", false);

        //   invokeMethod(Channel.class, "init", null);
        //   new Channel.SDOPeerDefaultAddition(null);
        final String[] discoveredEndpoint = new String[] {"1.1.1.1:10"};
        final String[] discoveredMSPID = new String[] {"MSPID"};

        final Channel.SDPeerAdditionInfo sdPeerAdditionInfo = new Channel.SDPeerAdditionInfo() {
            @Override
            public String getMspId() {
                return discoveredMSPID[0];
            }

            @Override
            public String getEndpoint() {
                return discoveredEndpoint[0];
            }

            @Override
            public Channel getChannel() {
                return sd;
            }

            @Override
            public HFClient getClient() {
                return hfclient;
            }

            @Override
            public byte[][] getTLSCerts() {
                return new byte[0][];
            }

            @Override
            public byte[][] getTLSIntermediateCerts() {
                return new byte[0][];
            }

            @Override
            public Map<String, Peer> getEndpointMap() {
                return new HashMap<>();
            }
        };

        Peer peer = sd.sdPeerAddition.addPeer(sdPeerAdditionInfo);
        Properties properties = peer.getProperties();

        assertArrayEquals(new byte[] {1, 2, 3}, (byte[]) properties.get("clientKeyBytes"));
        assertArrayEquals(new byte[] {1, 2, 4}, (byte[]) properties.get("clientCertBytes"));
        discoveredEndpoint[0] = "1.1.1.3:33";

        discoveredMSPID[0] = "SPECIAL";
        peer = sd.sdPeerAddition.addPeer(sdPeerAdditionInfo);
        properties = peer.getProperties();
        assertArrayEquals(new byte[] {1, 2, 9}, (byte[]) properties.get("clientCertBytes"));

        discoveredEndpoint[0] = "2.1.3.4:99";
        peer = sd.sdPeerAddition.addPeer(sdPeerAdditionInfo);
        properties = peer.getProperties();
        assertArrayEquals(new byte[] {9, 2, 4}, (byte[]) properties.get("clientKeyBytes"));

        discoveredEndpoint[0] = "2.1.3.4:88";
        peer = sd.sdPeerAddition.addPeer(sdPeerAdditionInfo);
        properties = peer.getProperties();
        assertArrayEquals(new byte[] {88, 2, 4}, (byte[]) properties.get("clientKeyBytes"));

    }

    static final String CHANNEL_NAME2 = "channel";

    public static Channel createRunningChannel(Collection<Peer> peers) throws InvalidArgumentException, NoSuchFieldException, IllegalAccessException {
        Channel prevChannel = hfclient.getChannel(CHANNEL_NAME2);
        if (null != prevChannel) { //cleanup remove default channel.
            prevChannel.shutdown(false);
        }
        return createRunningChannel(CHANNEL_NAME2, peers);
    }

    public static Channel createRunningChannel(String channelName, Collection<Peer> peers) throws InvalidArgumentException, NoSuchFieldException, IllegalAccessException {

        Channel channel = hfclient.newChannel(channelName);
        if (peers == null) {
            Peer peer = hfclient.newPeer("peer1", "grpc://localhost:22");
            channel.addPeer(peer);
            channel.addOrderer(hfclient.newOrderer("order1", "grpc://localhost:22"));
        } else {
            for (Peer peer : peers) {
                channel.addPeer(peer);

            }
        }

        setField(channel, "initialized", true);

        return channel;

    }

    @Test
    public void testChannelBadPeerDoesNotBelongJoin() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("Can not add peer peer2 to channel testChannelBadPeerDoesNotBelongJoin because it already belongs to channel testChannelBadPeerDoesNotBelongJoin2");

        final Channel channel = createRunningChannel("testChannelBadPeerDoesNotBelongJoin", null);

        Collection<Peer> peers = Arrays.asList((Peer[]) new Peer[] {hfclient.newPeer("peer2", "grpc://localhost:22")});

        createRunningChannel("testChannelBadPeerDoesNotBelongJoin2", peers);

        //Peer joining channel when it belongs to another channel.

        channel.joinPeer(peers.iterator().next());

    }

    @Test
    public void testChannelPeerJoinNoOrderer() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("Channel channel does not have any orderers associated with it.");

        final Channel channel = createRunningChannel(null);

        setField(channel, "orderers", new LinkedList<>());

        //Peer joining channel were no orderer is there .. not likely.

        channel.joinPeer(hfclient.newPeer("peerJoiningNOT", "grpc://localhost:22"));

    }

    @Test
    public void testChannelInitNoname() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Can not initialize channel without a valid name.");

        final Channel channel = hfclient.newChannel("del");
        setField(channel, "name", null);

        channel.initialize();

    }

    @Test
    public void testChannelInitNullClient() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Can not initialize channel without a client object.");

        final Channel channel = hfclient.newChannel("testChannelInitNullClient");
        setField(channel, "client", null);

        channel.initialize();

    }

    @Test
    public void testChannelsendInstantiationProposalNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("InstantiateProposalRequest is null");

        final Channel channel = createRunningChannel(null);

        channel.sendInstantiationProposal(null);

    }

    @Test
    public void testChannelsendInstallProposalNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("InstallProposalRequest is null");

        final Channel channel = createRunningChannel(null);

        channel.sendInstallProposal(null);

    }

    @Test
    public void testChannelsendUpgradeProposalNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Upgradeproposal is null");

        final Channel channel = createRunningChannel(null);

        channel.sendUpgradeProposal(null);

    }

    //queryBlockByHash

    @Test
    public void testChannelQueryBlockByHashNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("blockHash parameter is null.");

        final Channel channel = createRunningChannel(null);

        channel.queryBlockByHash(null);

    }

    @Test
    public void testChannelQueryBlockByHashNotInitialized() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel channel has not been initialized.");

        final Channel channel = createRunningChannel(null);
        setField(channel, "initialized", false);

        channel.queryBlockByHash("hyper this hyper that".getBytes());

    }

    @Test
    public void testChannelQueryBlockByTransactionIDNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("TxID parameter is null.");

        final Channel channel = createRunningChannel(null);

        channel.queryBlockByTransactionID(null);

    }

    @Test
    public void testChannelQueryTransactionByIDNull() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("TxID parameter is null.");

        final Channel channel = createRunningChannel(null);

        channel.queryTransactionByID(null);

    }

    @Test
    public void testQueryInstalledChaincodesThrowInterrupted() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("You interrupting me?");

        final Channel channel = createRunningChannel(null);
        Peer peer = channel.getPeers().iterator().next();

        setField(peer, "endorserClent", new MockEndorserClient(new InterruptedException("You interrupting me?")));

        hfclient.queryChannels(peer);

    }

    @Test
    public void testQueryInstalledChaincodesThrowPeerException() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("rick did this:)");

        final Channel channel = createRunningChannel(null);
        Peer peer = channel.getPeers().iterator().next();

        setField(peer, "endorserClent", new MockEndorserClient(new PeerException("rick did this:)")));

        hfclient.queryChannels(peer);

    }

    @Test
    public void testQueryInstalledChaincodesThrowTimeoutException() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("What time is it?");

        final Channel channel = createRunningChannel(null);
        Peer peer = channel.getPeers().iterator().next();

        setField(peer, "endorserClent", new MockEndorserClient(new PeerException("What time is it?")));

        hfclient.queryChannels(peer);

    }

    @Test
    public void testQueryInstalledChaincodesERROR() throws Exception {

        thrown.expect(Error.class);
        thrown.expectMessage("Error bad bad bad");

        final Channel channel = createRunningChannel(null);
        Peer peer = channel.getPeers().iterator().next();

        final CompletableFuture<FabricProposalResponse.ProposalResponse> settableFuture = new CompletableFuture<>();
        //  settableFuture.setException(new Error("Error bad bad bad"));
        settableFuture.completeExceptionally(new Error("Error bad bad bad"));
        setField(peer, "endorserClent", new MockEndorserClient(settableFuture));

        hfclient.queryChannels(peer);

    }

    @Test
    public void testQueryInstalledChaincodesStatusRuntimeException() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("ABORTED");

        final Channel channel = createRunningChannel(null);
        Peer peer = channel.getPeers().iterator().next();

        final CompletableFuture<FabricProposalResponse.ProposalResponse> settableFuture = new CompletableFuture<>();
        settableFuture.completeExceptionally(new StatusRuntimeException(Status.ABORTED));

        setField(peer, "endorserClent", new MockEndorserClient(settableFuture));

        hfclient.queryChannels(peer);

    }

    private static final String SAMPLE_GO_CC = "src/test/fixture/sdkintegration/gocc/sample1";

    @Test
    public void testProposalBuilderWithMetaInf() throws Exception {
        InstallProposalBuilder installProposalBuilder = InstallProposalBuilder.newBuilder();

        installProposalBuilder.setChaincodeLanguage(TransactionRequest.Type.GO_LANG);
        installProposalBuilder.chaincodePath("github.com/example_cc");
        installProposalBuilder.setChaincodeSource(new File(SAMPLE_GO_CC));
        installProposalBuilder.chaincodeName("example_cc.go");
        installProposalBuilder.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/test1"));
        installProposalBuilder.chaincodeVersion("1");

        Channel channel = hfclient.newChannel("testProposalBuilderWithMetaInf");

        TestUtils.MockUser mockUser = getMockUser("rick", "rickORG");
        TransactionContext transactionContext = new TransactionContext(channel, mockUser, CryptoSuite.Factory.getCryptoSuite());

        installProposalBuilder.context(transactionContext);

        FabricProposal.Proposal proposal = installProposalBuilder.build(); // Build it get the proposal. Then unpack it to see if it's what we expect.

        FabricProposal.ChaincodeProposalPayload chaincodeProposalPayload = FabricProposal.ChaincodeProposalPayload.parseFrom(proposal.getPayload());
        Chaincode.ChaincodeInvocationSpec chaincodeInvocationSpec = Chaincode.ChaincodeInvocationSpec.parseFrom(chaincodeProposalPayload.getInput());
        Chaincode.ChaincodeSpec chaincodeSpec = chaincodeInvocationSpec.getChaincodeSpec();
        Chaincode.ChaincodeInput input = chaincodeSpec.getInput();

        Chaincode.ChaincodeDeploymentSpec chaincodeDeploymentSpec = Chaincode.ChaincodeDeploymentSpec.parseFrom(input.getArgs(1));
        ByteString codePackage = chaincodeDeploymentSpec.getCodePackage();
        ArrayList tarBytesToEntryArrayList = tarBytesToEntryArrayList(codePackage.toByteArray());

        ArrayList<String> expect = new ArrayList(Arrays.asList(new String[] {
                "META-INF/statedb/couchdb/indexes/MockFakeIndex.json",
                "src/github.com/example_cc/example_cc.go"
        }));

        assertArrayListEquals("Tar in Install Proposal's codePackage does not have expected entries. ", expect, tarBytesToEntryArrayList);
    }

    @Test
    public void testProposalBuilderWithOutMetaInf() throws Exception {
        InstallProposalBuilder installProposalBuilder = InstallProposalBuilder.newBuilder();

        installProposalBuilder.setChaincodeLanguage(TransactionRequest.Type.GO_LANG);
        installProposalBuilder.chaincodePath("github.com/example_cc");
        installProposalBuilder.setChaincodeSource(new File(SAMPLE_GO_CC));
        installProposalBuilder.chaincodeName("example_cc.go");
        installProposalBuilder.chaincodeVersion("1");

        Channel channel = hfclient.newChannel("testProposalBuilderWithOutMetaInf");
        TransactionContext transactionContext = new TransactionContext(channel, getMockUser("rick", "rickORG"), CryptoSuite.Factory.getCryptoSuite());

        installProposalBuilder.context(transactionContext);

        FabricProposal.Proposal proposal = installProposalBuilder.build(); // Build it get the proposal. Then unpack it to see if it's what we expect.
        FabricProposal.ChaincodeProposalPayload chaincodeProposalPayload = FabricProposal.ChaincodeProposalPayload.parseFrom(proposal.getPayload());
        Chaincode.ChaincodeInvocationSpec chaincodeInvocationSpec = Chaincode.ChaincodeInvocationSpec.parseFrom(chaincodeProposalPayload.getInput());
        Chaincode.ChaincodeSpec chaincodeSpec = chaincodeInvocationSpec.getChaincodeSpec();
        Chaincode.ChaincodeInput input = chaincodeSpec.getInput();

        Chaincode.ChaincodeDeploymentSpec chaincodeDeploymentSpec = Chaincode.ChaincodeDeploymentSpec.parseFrom(input.getArgs(1));
        ByteString codePackage = chaincodeDeploymentSpec.getCodePackage();
        ArrayList tarBytesToEntryArrayList = tarBytesToEntryArrayList(codePackage.toByteArray());

        ArrayList<String> expect = new ArrayList(Arrays.asList(new String[] {"src/github.com/example_cc/example_cc.go"
        }));

        assertArrayListEquals("Tar in Install Proposal's codePackage does not have expected entries. ", expect, tarBytesToEntryArrayList);
    }

    @Test
    public void testProposalBuilderWithNoMetaInfDir() throws Exception {

        thrown.expect(java.lang.IllegalArgumentException.class);
        thrown.expectMessage(matchesRegex("The META-INF directory does not exist in.*src.test.fixture.meta-infs.test1.META-INF"));

        InstallProposalBuilder installProposalBuilder = InstallProposalBuilder.newBuilder();

        installProposalBuilder.setChaincodeLanguage(TransactionRequest.Type.GO_LANG);
        installProposalBuilder.chaincodePath("github.com/example_cc");
        installProposalBuilder.setChaincodeSource(new File(SAMPLE_GO_CC));
        installProposalBuilder.chaincodeName("example_cc.go");
        installProposalBuilder.chaincodeVersion("1");
        installProposalBuilder.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/test1/META-INF")); // points into which is not what's expected.

        Channel channel = hfclient.newChannel("testProposalBuilderWithNoMetaInfDir");
        TransactionContext transactionContext = new TransactionContext(channel, getMockUser("rick", "rickORG"), CryptoSuite.Factory.getCryptoSuite());

        installProposalBuilder.context(transactionContext);

        installProposalBuilder.build(); // Build it get the proposal. Then unpack it to see if it's what we epect.
    }

    @Test
    public void testProposalBuilderWithMetaInfExistsNOT() throws Exception {

        thrown.expect(java.lang.IllegalArgumentException.class);
        thrown.expectMessage(matchesRegex("Directory to find chaincode META-INF.*tmp.fdsjfksfj.fjksfjskd.fjskfjdsk.should never exist does not exist"));

        InstallProposalBuilder installProposalBuilder = InstallProposalBuilder.newBuilder();

        installProposalBuilder.setChaincodeLanguage(TransactionRequest.Type.GO_LANG);
        installProposalBuilder.chaincodePath("github.com/example_cc");
        installProposalBuilder.setChaincodeSource(new File(SAMPLE_GO_CC));
        installProposalBuilder.chaincodeName("example_cc.go");
        installProposalBuilder.chaincodeVersion("1");
        installProposalBuilder.setChaincodeMetaInfLocation(new File("/tmp/fdsjfksfj/fjksfjskd/fjskfjdsk/should never exist")); // points into which is not what's expected.

        Channel channel = hfclient.newChannel("testProposalBuilderWithMetaInfExistsNOT");
        TransactionContext transactionContext = new TransactionContext(channel, getMockUser("rick", "rickORG"), CryptoSuite.Factory.getCryptoSuite());

        installProposalBuilder.context(transactionContext);

        installProposalBuilder.build(); // Build it get the proposal. Then unpack it to see if it's what we epect.
    }

    @Test
    public void testNOf() throws Exception {

        Peer peer1Org1 = new Peer("peer1Org1", "grpc://localhost:9", null);
        Peer peer1Org12nd = new Peer("org12nd", "grpc://localhost:9", null);
        Peer peer2Org2 = new Peer("peer2Org2", "grpc://localhost:9", null);
        Peer peer2Org22nd = new Peer("peer2Org22nd", "grpc://localhost:9", null);

        //One from each set.
        NOfEvents nOfEvents = NOfEvents.createNofEvents().addNOfs(NOfEvents.createNofEvents().setN(1).addPeers(peer1Org1, peer1Org12nd),
                NOfEvents.createNofEvents().setN(1).addPeers(peer2Org2, peer2Org22nd)
        );

        NOfEvents nOfEvents1 = new NOfEvents(nOfEvents);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer1Org1);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer1Org12nd);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer2Org22nd);
        assertTrue(nOfEvents1.ready);
        assertFalse(nOfEvents.ready);

        nOfEvents = NOfEvents.createNofEvents().addNOfs(NOfEvents.createNofEvents().addPeers(peer1Org1, peer1Org12nd),
                NOfEvents.createNofEvents().addPeers(peer2Org2, peer2Org22nd)
        );
        nOfEvents1 = new NOfEvents(nOfEvents);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer1Org1);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer2Org2);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer1Org12nd);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer2Org22nd);
        assertTrue(nOfEvents1.ready);
        assertFalse(nOfEvents.ready);

        nOfEvents = NOfEvents.createNofEvents().setN(1).addNOfs(NOfEvents.createNofEvents().addPeers(peer1Org1, peer1Org12nd)
        );

        nOfEvents1 = new NOfEvents(nOfEvents);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer1Org1);
        assertFalse(nOfEvents1.ready);
        nOfEvents1.seen(peer1Org12nd);
        assertTrue(nOfEvents1.ready);

        nOfEvents = NOfEvents.createNoEvents();
        assertTrue(nOfEvents.ready);

    }

    @Test
    public void testProposalBuilderWithMetaInfEmpty() throws Exception {

        thrown.expect(java.lang.IllegalArgumentException.class);
        thrown.expectMessage(matchesRegex("The META-INF directory.*src.test.fixture.meta-infs.emptyMetaInf.META-INF is empty\\."));

        File emptyINF = new File("src/test/fixture/meta-infs/emptyMetaInf/META-INF"); // make it cause git won't check in empty directory
        if (!emptyINF.exists()) {
            emptyINF.mkdirs();
            emptyINF.deleteOnExit();
        }

        InstallProposalBuilder installProposalBuilder = InstallProposalBuilder.newBuilder();

        installProposalBuilder.setChaincodeLanguage(TransactionRequest.Type.GO_LANG);
        installProposalBuilder.chaincodePath("github.com/example_cc");
        installProposalBuilder.setChaincodeSource(new File(SAMPLE_GO_CC));
        installProposalBuilder.chaincodeName("example_cc.go");
        installProposalBuilder.chaincodeVersion("1");
        installProposalBuilder.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/emptyMetaInf")); // points into which is not what's expected.

        Channel channel = hfclient.newChannel("testProposalBuilderWithMetaInfEmpty");
        TransactionContext transactionContext = new TransactionContext(channel, getMockUser("rick", "rickORG"), CryptoSuite.Factory.getCryptoSuite());

        installProposalBuilder.context(transactionContext);

        FabricProposal.Proposal proposal = installProposalBuilder.build(); // Build it get the proposal. Then unpack it to see if it's what we epect.
    }

    //testing of blocklistner

    @Test
    public void testRegisterBlockListenerNULL() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("BlockEventQueue parameter is null.");

        Channel channel = hfclient.newChannel("testRegisterBlockListenerNULL");
        BlockingQueue<QueuedBlockEvent> nblis = null;
        channel.registerBlockListener(nblis);

    }

    @Test
    public void testRegisterBlockListenerNULL2() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("BlockEventQueue parameter is null.");

        Channel channel = hfclient.newChannel("testRegisterBlockListenerNULL2");
        BlockingQueue<QueuedBlockEvent> nblis = null;
        channel.registerBlockListener(nblis, 10, TimeUnit.SECONDS);

    }

    @Test
    public void testRegisterBlockListenerBadArg() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Timeout parameter must be greater than 0 not -1");

        Channel channel = hfclient.newChannel("testRegisterBlockListenerBadArg");
        BlockingQueue<QueuedBlockEvent> nblis = null;
        channel.registerBlockListener(new LinkedBlockingQueue<>(), -1, TimeUnit.SECONDS);

    }

    @Test
    public void testRegisterBlockListenerBadNULLArg() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("TimeUnit parameter must not be null.");

        Channel channel = hfclient.newChannel("testRegisterBlockListenerBadNULLArg");
        channel.registerBlockListener(new LinkedBlockingQueue<>(), 10, null);

    }

    @Test
    public void testRegisterBlockListenerShutdown() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel testRegisterBlockListenerShutdown has been shutdown.");

        Channel channel = hfclient.newChannel("testRegisterBlockListenerShutdown");
        channel.shutdown(false);
        channel.registerBlockListener(new LinkedBlockingQueue<>(), 10, TimeUnit.SECONDS);

    }

    @Test
    public void testRegisterBlockListenerShutdown2() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Channel testRegisterBlockListenerShutdown2 has been shutdown.");

        Channel channel = hfclient.newChannel("testRegisterBlockListenerShutdown2");
        channel.shutdown(false);
        channel.registerBlockListener(new LinkedBlockingQueue<>());

    }

    class MockEndorserClient extends EndorserClient {
        final Throwable throwThis;
        private final CompletableFuture<FabricProposalResponse.ProposalResponse> returnedFuture;

        MockEndorserClient(Throwable throwThis) {
            super("blahchannlname", "blahpeerName", "blahURL", new Endpoint("grpc://loclhost:99", null).getChannelBuilder());
            if (throwThis == null) {
                throw new IllegalArgumentException("Can't throw a null!");
            }
            this.throwThis = throwThis;
            this.returnedFuture = null;
        }

        MockEndorserClient(CompletableFuture<FabricProposalResponse.ProposalResponse> returnedFuture) {
            super("blahchannlname", "blahpeerName", "blahURL", new Endpoint("grpc://loclhost:99", null).getChannelBuilder());
            this.throwThis = null;
            this.returnedFuture = returnedFuture;
        }

        @Override
        public CompletableFuture<FabricProposalResponse.ProposalResponse> sendProposalAsync(FabricProposal.SignedProposal proposal) {
            if (throwThis != null) {
                getUnsafe().throwException(throwThis);
            }
            return returnedFuture;

        }

        @Override
        public boolean isChannelActive() {

            return true;

        }

        private Unsafe getUnsafe() {  //lets us throw undeclared exceptions.
            try {
                Field field = Unsafe.class.getDeclaredField("theUnsafe");
                field.setAccessible(true);
                return (Unsafe) field.get(null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

}
