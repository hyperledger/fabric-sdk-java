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

package org.hyperledger.fabric.sdk;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ClientTest {
    private static final String CHAIN_NAME = "chain1";
    static HFClient hfclient = null;

    @BeforeClass
    public static void setupClient() throws Exception {
        try {
            hfclient = TestHFClient.newInstance();

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());

        }

    }

    @Test
    public void testNewChain() {
        try {
            Chain testChain = hfclient.newChain(CHAIN_NAME);
            Assert.assertTrue(testChain != null && CHAIN_NAME.equalsIgnoreCase(testChain.getName()));
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
    
    @Test
	public void testSetNullChain() {
		try {
			Chain testChain = hfclient.newChain(null);
			Assert.fail("Expected null chain to throw exception.");

		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
		}
	}

    @Test
    public void testNewPeer() {
        try {
            Peer peer = hfclient.newPeer("peer_" , "grpc://localhost:7051");
            Assert.assertTrue(peer != null);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
    
    @Test
	public void testBadURL() {
		try {
			Peer peer = hfclient.newPeer("peer_", " ");
			Assert.fail("Expected peer with no chain throw exception");
		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
		}
	}

    @Test
    public void testNewOrderer() {
    	try {
            Orderer orderer = hfclient.newOrderer("xx", "grpc://localhost:5005");
            Assert.assertTrue(orderer != null);
    	} catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage()); 
    	}    
    }
    
    @Test 
    public void testBadAddress() {
         try {
              Orderer orderer= hfclient.newOrderer("xx","xxxxxx");
              Assert.fail("Orderer did not allow setting bad URL.");
         } catch (Exception e) {
              Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
         }  
    }

}
