/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

//import org.hyperledger.fabric.protos.peer.FabricProposal;

public class PeerTest {
	private static final String CHANNEL_NAME = "channel1";
	static HFClient hfclient = null;
	static Peer peer = null;


	@BeforeClass
	public static void setupClient() {
        try {
			hfclient = TestHFClient.newInstance();

            peer= hfclient.newPeer("peer_" , "grpc://localhost:7051");
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }
    }

	@Test
	public void testgetName() {
		final  String PEER_NAME = "peertest";


		Assert.assertTrue(peer != null);
		try {
			peer =new Peer(PEER_NAME, "grpc://localhost:4", null);

			Assert.assertEquals(PEER_NAME,peer.getName());
		} catch (InvalidArgumentException e) {
			Assert.fail("Unexpected Exeception " + e.getMessage());
		}

	}
	@Test
	public void testSetNullName() {

		try {
			peer =new Peer(null, "grpc://localhost:4", null);
			Assert.fail("expected set null name to throw exception.");
		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
		}
	}
	@Test
	public void testSetEmptyName() {

		try {
			peer =new Peer("", "grpc://localhost:4", null);
			Assert.fail("expected set empty name to throw exception.");
		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
		}
	}



	@Test
	public void testSendNullProposal() {

		try {

			peer.sendProposal(null);
			Assert.fail("Expected null proposal to throw exception.");

		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == PeerException.class);
		}
	}
	@Test
	public void testSendNullChannel() {

		try {

			Peer badpeer = hfclient.newPeer("badpeer", "grpc://localhost:7051");


			badpeer.sendProposal(FabricProposal.SignedProposal.newBuilder().build());
            Assert.fail("Expected peer with no channel throw exception");

		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == PeerException.class);
		}
	}

	@Test(expected = PeerException.class)
	public void testSendAsyncNullProposal() throws Exception {
		peer.sendProposalAsync(null);
	}


	@Test
	public void testBadURL() {

		try {

			hfclient.newPeer("peer_", " ");

            Assert.fail("Expected peer with no channel throw exception");

		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
		}
	}


}
