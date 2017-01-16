package org.hyperledger.fabric.sdk;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ClientTest {
    private static final String CHAIN_NAME = "chain1";
    static HFClient hfclient = null;

    @BeforeClass
    public static void setupClient() {
        hfclient = HFClient.createNewInstance();
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
            Peer peer = hfclient.newPeer("grpc://localhost:7051");
            Assert.assertTrue(peer != null);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
    
    @Test
	public void testBadURL() {
		try {
			Peer peer = hfclient.newPeer(" ");
			Assert.fail("Expected peer with no chain throw exception");
		} catch (Exception e) {
			Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
		}
	}

    @Test
    public void testNewOrderer() {
    	try {
            Orderer orderer = hfclient.newOrderer("grpc://localhost:5005");
            Assert.assertTrue(orderer != null);
    	} catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage()); 
    	}    
    }
    
    @Test 
    public void testBadAddress() {
         try {
              Orderer orderer= hfclient.newOrderer("xxxxxx");
              Assert.fail("Orderer did not allow setting bad URL.");
         } catch (Exception e) {
              Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
         }  
    }

    @Test
    public void testGetChain() {
        Peer peer = null;
        try {
            Chain chain = hfclient.newChain(CHAIN_NAME);
            peer = hfclient.newPeer("grpc://localhost:7051");
            peer.setName("peer1");
            chain.addPeer(peer);
        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }

        Assert.assertTrue("Test passed - ", peer.getChain().getName().equalsIgnoreCase(CHAIN_NAME));
    }
}
