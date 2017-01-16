package org.hyperledger.fabric.sdk;



import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Ignore;
public class OrdererTest {
        private static final String CHAIN_NAME = "chain1";
        static HFClient hfclient = null;
        static Orderer orderer = null;

        @BeforeClass
        public static void setupClient() {
                hfclient = HFClient.createNewInstance();
                try {
                        //hfclient = HFClient.createNewInstance();
                        orderer= hfclient.newOrderer("grpc://localhost:5151");
                } catch (Exception e) {
                        e.printStackTrace();
                        Assert.fail("Unexpected Exception " + e.getMessage());
                }
        }
        
        @Test
        public void testSetChain() {

                try {
                        Chain chain = hfclient.newChain("chain");
                        orderer.setChain(chain);
                        Assert.assertTrue(chain == orderer.getChain());

                } catch (Exception e) {
                        Assert.fail("Unexpected Exception " + e.getMessage());
                }
        }

        @Test
        public void testSetNullChain() {

                try {

                        orderer.setChain(null);
                        Assert.fail("Expected null chain to throw exception.");

                } catch (Exception e) {
                        Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
                }
        }
        @Test 
        public void testBadAddress() {
                try {
                        orderer= hfclient.newOrderer("xxxxxx");
                        Assert.fail("Orderer did not allow setting bad URL.");
                } catch (Exception e) {
                        Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
                }
        }
        @Test
        public void testMissingAddress() {
                try {
                        orderer= hfclient.newOrderer("");
                        Assert.fail("Orderer did not allow setting a missing address.");
                } catch (Exception e) {
                	    Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
                }
        }
        @Ignore
        public void testGetChain() {
                try {
                        Chain chain = hfclient.newChain("chain");
                        orderer = hfclient.newOrderer("grpc://localhost:5151");
                        chain.addOrderer(orderer);
                 } catch (Exception e) {
                        Assert.fail("Unexpected Exception " + e.getMessage());
                }
                        Assert.assertTrue("Test passed - ", orderer.getChain().getName().equalsIgnoreCase("chain"));
        }
        @Test(expected=AssertionError.class)
        public void testBroadcast() {
                	    try {
							orderer = hfclient.newOrderer("grpc://localhost:5151");
						} catch (Exception e) {
							e.printStackTrace();
						}
                	    Ab.BroadcastResponse resp = orderer.sendTransaction(null);
                	    Assert.fail("Transaction should not be null.");
        }
        
}
