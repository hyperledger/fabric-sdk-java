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

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChainTest {
    private static final String CHAIN_NAME = "chain1";
    static HFClient hfclient = null;


    @BeforeClass
    public static void setupClient() {
        try {
            hfclient = HFClient.createNewInstance();

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }
    }

    @Test
    public void testChainCreation() {

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            Chain testchain = new Chain(CHAIN_NAME, hfclient);
            Assert.assertEquals(CHAIN_NAME, testchain.getName());
            Assert.assertEquals(testchain.client, hfclient);
            Assert.assertEquals(testchain.getOrderers().size(), 0);
            Assert.assertEquals(testchain.getPeers().size(), 0);
            Assert.assertEquals(testchain.isInitialized(), false);


        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChainAddPeer() {

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            final Chain testchain = new Chain(CHAIN_NAME, hfclient);
            final Peer peer = hfclient.newPeer("grpc://localhost:7051");
            peer.setName("mypeer");

            testchain.addPeer(peer);

            Assert.assertEquals(testchain.getPeers().size(), 1);
            Assert.assertEquals(testchain.getPeers().iterator().next(), peer);


        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChainAddOrder() {

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            final Chain testchain = new Chain(CHAIN_NAME, hfclient);
            final Orderer orderer = hfclient.newOrderer("grpc://localhost:7051");


            testchain.addOrderer(orderer);

            Assert.assertEquals(testchain.getOrderers().size(), 1);
            Assert.assertEquals(testchain.getOrderers().iterator().next(), orderer);


        } catch (InvalidArgumentException e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChainAddNullPeer() {
        Chain testchain = null;

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            testchain = new Chain(CHAIN_NAME, hfclient);


            testchain.addPeer(null);

            Assert.fail("Expected set null peer to throw exception.");


        } catch (InvalidArgumentException e) {
            Assert.assertEquals(testchain.getPeers().size(), 0);
            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
        }

    }

    @Test
    public void testChainAddNoNamePeer() {
        Chain testchain = null;

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            testchain = new Chain(CHAIN_NAME, hfclient);
            final Peer peer = hfclient.newPeer("grpc://localhost:7051");

            testchain.addPeer(peer);
            Assert.fail("Expected no named peer to throw exception.");


        } catch (InvalidArgumentException e) {
            Assert.assertEquals(testchain.getPeers().size(), 0);
            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
        }

    }

    @Test
    public void testChainAddNullOrder() {
        Chain testchain = null;

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            testchain = new Chain(CHAIN_NAME, hfclient);


            testchain.addOrderer(null);

            Assert.fail("Expected set null order to throw exception.");

        } catch (InvalidArgumentException e) {
            Assert.assertEquals(testchain.getOrderers().size(), 0);
            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
        }

    }

    @Test
    public void testChainInitialize() { //test may not be doable once initialize is done

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            final Chain testchain = new Chain(CHAIN_NAME, hfclient);
            final Peer peer = hfclient.newPeer("grpc://localhost:7051");
            hfclient.setUserContext(new User("admin"));
            peer.setName("mypeer");

            testchain.addPeer(peer);
            Assert.assertEquals(testchain.isInitialized(), false);
            testchain.initialize();
            Assert.assertEquals(testchain.isInitialized(), true);


        } catch (Exception e) {
            Assert.fail("Unexpected Exeception " + e.getMessage());
        }

    }

    @Test
    public void testChainInitializeNoPeer() {
        Chain testchain = null;

        try {
            HFClient hfclient = HFClient.createNewInstance();
            final String CHAIN_NAME = "chain3";
            testchain = new Chain(CHAIN_NAME, hfclient);

            Assert.assertEquals(testchain.isInitialized(), false);
            testchain.initialize();
            Assert.fail("Expected initialize to throw exception with no peers.");

        } catch (Exception e) {

            Assert.assertTrue(e.getClass() == InvalidArgumentException.class);
            Assert.assertEquals(testchain.isInitialized(), false);
        }

    }

}
