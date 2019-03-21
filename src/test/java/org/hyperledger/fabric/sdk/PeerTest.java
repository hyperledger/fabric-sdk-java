/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class PeerTest {
    static HFClient hfclient = null;
    static Peer peer = null;

    static final String PEER_NAME = "peertest";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setupClient() {
        try {
            hfclient = TestHFClient.newInstance();
            peer = hfclient.newPeer(PEER_NAME, "grpc://localhost:7051");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testGetName() {
        Assert.assertTrue(peer != null);
        try {
            peer = hfclient.newPeer(PEER_NAME, "grpc://localhost:4");
            Assert.assertEquals(PEER_NAME, peer.getName());
        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test (expected = InvalidArgumentException.class)
    public void testSetNullName() throws InvalidArgumentException {
        peer = hfclient.newPeer(null, "grpc://localhost:4");
        Assert.fail("expected set null name to throw exception.");
    }

    @Test (expected = InvalidArgumentException.class)
    public void testSetEmptyName() throws InvalidArgumentException {
        peer = hfclient.newPeer("", "grpc://localhost:4");
        Assert.fail("expected set empty name to throw exception.");
    }

    @Test (expected = Exception.class)
    public void testSendAsyncNullProposal() throws PeerException, InvalidArgumentException, ExecutionException, InterruptedException {
        Future<FabricProposalResponse.ProposalResponse> future = peer.sendProposalAsync(null);
        future.get();
    }

    @Test (expected = InvalidArgumentException.class)
    public void testBadURL() throws InvalidArgumentException {
        hfclient.newPeer(PEER_NAME, " ");
        Assert.fail("Expected peer with no channel throw exception");
    }

    @Test
    public void testDuplicateChannel() throws InvalidArgumentException {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Can not add peer " + PEER_NAME + " to channel duplicate because it already belongs to channel duplicate.");

        Channel duplicate = hfclient.newChannel("duplicate");
        peer.setChannel(duplicate);
        peer.setChannel(duplicate);
    }

    @Test
    public void getPeerEventingServiceDisconnectedTest() throws InvalidArgumentException {
        Peer somePeer = hfclient.newPeer("somePeer", "grpc://localhost:4");

        final Peer.PeerEventingServiceDisconnected disconnectedHandlerExpect = (Peer.PeerEventingServiceDisconnected) TestUtils.getField(somePeer, "disconnectedHandler");

        Peer.PeerEventingServiceDisconnected disconnectedHandler = somePeer.getPeerEventingServiceDisconnected();

        Assert.assertSame(disconnectedHandlerExpect, disconnectedHandler);

        Peer.PeerEventingServiceDisconnected peerEventingServiceDisconnectedCurrent = somePeer.setPeerEventingServiceDisconnected(null);

        Assert.assertSame(disconnectedHandlerExpect, peerEventingServiceDisconnectedCurrent);

        Assert.assertNull(somePeer.getPeerEventingServiceDisconnected());

        Assert.assertNull(somePeer.setPeerEventingServiceDisconnected(disconnectedHandlerExpect));

        Assert.assertSame(disconnectedHandlerExpect, somePeer.getPeerEventingServiceDisconnected());

    }
}
