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

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;


public class OrdererTest {
    static HFClient hfclient = null;
    static Orderer orderer = null;
    static File tempFile;

    @BeforeClass
    public static void setupClient() throws Exception {
        hfclient = TestHFClient.newInstance();
        orderer = hfclient.newOrderer("myorder", "grpc://localhost:5151");
    }

    @AfterClass
    public static void cleanUp() {
        if (tempFile != null) {
            tempFile.delete();
            tempFile = null;
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

    @Test(expected = InvalidArgumentException.class)
    public void testSetNullChannel() throws InvalidArgumentException {
        orderer.setChannel(null);
        Assert.fail("Expected null channel to throw exception.");
    }

    @Test(expected = InvalidArgumentException.class)
    public void testBadAddress() throws InvalidArgumentException {
        orderer = hfclient.newOrderer("badorderer", "xxxxxx");
        Assert.fail("Orderer did not allow setting bad URL.");
    }

    @Test(expected = InvalidArgumentException.class)
    public void testMissingAddress() throws InvalidArgumentException {
        orderer = hfclient.newOrderer("badaddress", "");
        Assert.fail("Orderer did not allow setting a missing address.");
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

    @Test(expected = Exception.class)
    public void testSendNullTransactionThrowsException() throws Exception {
        try {
            orderer = hfclient.newOrderer("orderertest", "grpc://localhost:5151");
        } catch (InvalidArgumentException e) {
            Assert.fail("Failed to create new orderer: " + e);
        }
        orderer.sendTransaction(null);
        Assert.fail("Transaction should not be null.");
    }

}
