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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


public class OrdererTest {
    static HFClient hfclient = null;
    static Orderer orderer = null;
    static File tempFile;

    static final String DEFAULT_CHANNEL_NAME = "channel";
    static final String ORDERER_NAME = "testorderer";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setupClient() throws Exception {
        hfclient = TestHFClient.newInstance();
        orderer = hfclient.newOrderer(ORDERER_NAME, "grpc://localhost:5151");
    }

    @AfterClass
    public static void cleanUp() {
        if (tempFile != null) {
            tempFile.delete();
            tempFile = null;
        }
    }

    @Test
    public void testSetDuplicateChannnel() throws InvalidArgumentException {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Can not add orderer " + ORDERER_NAME + " to channel channel2 because it already belongs to channel " + DEFAULT_CHANNEL_NAME + ".");

        Channel channel2 = hfclient.newChannel("channel2");
        orderer.setChannel(channel2);
        orderer.setChannel(channel2);
    }

    @Test
    public void testSetNullChannel() throws InvalidArgumentException {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("setChannel Channel can not be null");

        orderer.setChannel(null);
    }

    @Test
    public void testSetChannel() {

        try {
            Channel channel = hfclient.newChannel(DEFAULT_CHANNEL_NAME);
            orderer.setChannel(channel);
            Assert.assertTrue(channel == orderer.getChannel());

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testNullOrdererName() throws InvalidArgumentException {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Invalid name for orderer");

        new Orderer(null, "url", null);
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
            Channel channel = hfclient.newChannel(DEFAULT_CHANNEL_NAME);
            orderer = hfclient.newOrderer("ordererName", "grpc://localhost:5151");
            channel.addOrderer(orderer);
        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
        Assert.assertTrue("Test passed - ", orderer.getChannel().getName().equalsIgnoreCase(DEFAULT_CHANNEL_NAME));
    }

    @Test(expected = Exception.class)
    public void testSendNullTransactionThrowsException() throws Exception {
        try {
            orderer = hfclient.newOrderer(ORDERER_NAME, "grpc://localhost:5151");
        } catch (InvalidArgumentException e) {
            Assert.fail("Failed to create new orderer: " + e);
        }
        orderer.sendTransaction(null);
        Assert.fail("Transaction should not be null.");
    }

}
