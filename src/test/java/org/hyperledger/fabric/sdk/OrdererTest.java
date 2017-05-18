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

import java.io.File;

import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
public class OrdererTest {
        private static final String CHANNEL_NAME = "channel1";
        static HFClient hfclient = null;
        static Orderer orderer = null;
        static File tempFile;

        @BeforeClass
        public static void setupClient() throws Exception {


                try {
                        //hfclient = HFClient.createNewInstance();
                        hfclient = TestHFClient.newInstance();
                        orderer= hfclient.newOrderer("myorder", "grpc://localhost:5151");
                } catch (Exception e) {
                        e.printStackTrace();
                        Assert.fail("Unexpected Exception " + e.getMessage());
                }
        }

        @Test
        public void testSetChannel() {

                try {
                        Channel channel = hfclient.newChannel("channel");
                        orderer.setChannel(channel);
                        Assert.assertTrue(channel == orderer.getChannel());

                } catch (Exception e) {
                        Assert.fail("Unexpected Exception " + e.getMessage());
                }
        }

        @Test
        public void testSetNullChannel() {

                try {

                        orderer.setChannel(null);
                        Assert.fail("Expected null channel to throw exception.");

                } catch (Exception e) {
                        Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
                }
        }

        @Test
        public void testBadAddress() {
                try {
                        orderer= hfclient.newOrderer("badorderer", "xxxxxx");
                        Assert.fail("Orderer did not allow setting bad URL.");
                } catch (Exception e) {
                        Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
                }
        }
        @Test
        public void testMissingAddress() {
                try {
                        orderer= hfclient.newOrderer("badaddress", "");
                        Assert.fail("Orderer did not allow setting a missing address.");
                } catch (Exception e) {
                	    Assert.assertTrue( e.getClass() == InvalidArgumentException.class);
                }
        }
        @Ignore
        public void testGetChannel() {
                try {
                        Channel channel = hfclient.newChannel("channel");
                        orderer = hfclient.newOrderer("odererName", "grpc://localhost:5151");
                        channel.addOrderer(orderer);
                 } catch (Exception e) {
                        Assert.fail("Unexpected Exception " + e.getMessage());
                }
                Assert.assertTrue("Test passed - ", orderer.getChannel().getName().equalsIgnoreCase("channel"));
        }
        @Test(expected=AssertionError.class)
        public void testBroadcast() {
                	    try {
							orderer = hfclient.newOrderer("orderertest", "grpc://localhost:5151");
						} catch (Exception e) {
							e.printStackTrace();
						}
                try {
                        Ab.BroadcastResponse resp = orderer.sendTransaction(null);
                        Assert.fail("Transaction should not be null.");
                } catch (Exception e) {
                        e.printStackTrace();
                        Assert.fail("Expected null channel to throw exception.");
                }
        }
        @Override
        protected void finalize() throws Throwable {
                super.finalize();
                if( tempFile != null){
                        tempFile.delete();
                        tempFile = null;

                }
        }

}
