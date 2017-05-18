/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChannelTest {
    private static final String CHANNEL_NAME = "channel1";
    static HFClient hfclient = null;



    @BeforeClass
    public static void setupClient() {


        try {
            hfclient = TestHFClient.newInstance();

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }
    }

    @Test
    public void testChannelCreation() {

        try {

            final String CHANNEL_NAME = "channel3";
            Channel testchannel = new Channel(CHANNEL_NAME, hfclient);
            Assert.assertEquals(CHANNEL_NAME, testchannel.getName());
            Assert.assertEquals(testchannel.client, hfclient);
            Assert.assertEquals(testchannel.getOrderers().size(), 0);
            Assert.assertEquals(testchannel.getPeers().size(), 0);
            Assert.assertEquals(testchannel.isInitialized(), false);


        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChannelAddPeer() {

        try {

            final String CHANNEL_NAME = "channel3";
            final Channel testchannel = new Channel(CHANNEL_NAME, hfclient);
            final Peer peer = hfclient.newPeer("peer_" , "grpc://localhost:7051");

            testchannel.addPeer(peer);

            Assert.assertEquals(testchannel.getPeers().size(), 1);
            Assert.assertEquals(testchannel.getPeers().iterator().next(), peer);


        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChannelAddOrder() {

        try {

            final String CHANNEL_NAME = "channel3";
            final Channel testChannel = new Channel(CHANNEL_NAME, hfclient);
            final Orderer orderer = hfclient.newOrderer("testorder", "grpc://localhost:7051");

            testChannel.addOrderer(orderer);

            Assert.assertEquals(testChannel.getOrderers().size(), 1);
            Assert.assertEquals(testChannel.getOrderers().iterator().next(), orderer);


        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChannelAddNullPeer() {
        Channel testChannel = null;

        try {

            final String CHANNEL_NAME = "channel3";
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

            final String CHANNEL_NAME = "channel3";
            testChannel = new Channel(CHANNEL_NAME, hfclient);
            final Peer peer = hfclient.newPeer(null , "grpc://localhost:7051");

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

            final String CHANNEL_NAME = "channel3";
            testChannel = new Channel(CHANNEL_NAME, hfclient);

            testChannel.addOrderer(null);

            Assert.fail("Expected set null order to throw exception.");

        } catch (InvalidArgumentException e) {
            Assert.assertEquals(testChannel.getOrderers().size(), 0);
            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
        }

    }

    @Test
    public void testChannelInitialize() { //test may not be doable once initialize is done

        try {

            class MockChannel extends Channel {

                MockChannel(String name, HFClient client) throws InvalidArgumentException {
                    super(name, client);
                }

                @Override
                protected void parseConfigBlock(){

                }
            }

            final String CHANNEL_NAME = "channel3";
            final Channel testChannel = new MockChannel(CHANNEL_NAME, hfclient);
            final Peer peer = hfclient.newPeer("peer_" , "grpc://localhost:7051");

            testChannel.addPeer(peer);
            Assert.assertEquals(testChannel.isInitialized(), false);
            testChannel.initialize();
            Assert.assertEquals(testChannel.isInitialized(), true);


        } catch (Exception e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChannelInitializeNoPeer() {
        Channel testChannel = null;

        try {

            final String CHANNEL_NAME = "channel3";
            testChannel = new Channel(CHANNEL_NAME, hfclient);

            Assert.assertEquals(testChannel.isInitialized(), false);
            testChannel.initialize();
            Assert.fail("Expected initialize to throw exception with no peers.");

        } catch (Exception e) {

            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
            Assert.assertEquals(testChannel.isInitialized(), false);
        }

    }

}
