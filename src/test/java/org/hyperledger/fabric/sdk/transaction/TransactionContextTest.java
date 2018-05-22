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

package org.hyperledger.fabric.sdk.transaction;

import java.lang.reflect.Constructor;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.TestHFClient;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class TransactionContextTest {

    public final TemporaryFolder tempFolder = new TemporaryFolder();
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
    public void testGetters() throws Exception {

        Channel channel = createTestChannel("channel1");

        User user = hfclient.getUserContext();
        CryptoSuite cryptoSuite = hfclient.getCryptoSuite();

        TransactionContext context = new TransactionContext(channel, user, cryptoSuite);

        // ensure getCryptoPrimitives returns what we passed in to the constructor
        CryptoSuite cryptoPrimitives = context.getCryptoPrimitives();
        Assert.assertEquals(cryptoSuite, cryptoPrimitives);

    }

    @Test
    public void testSignByteStrings() throws Exception {

        TransactionContext context = createTestContext();

        Assert.assertNull(context.signByteStrings((ByteString) null));
        Assert.assertNull(context.signByteStrings((ByteString[]) null));
        Assert.assertNull(context.signByteStrings(new ByteString[0]));

        User[] users = new User[0];
        Assert.assertNull(context.signByteStrings(users, (ByteString) null));
        Assert.assertNull(context.signByteStrings(users, (ByteString[]) null));
        Assert.assertNull(context.signByteStrings(users, new ByteString[0]));

    }

    // ==========================================================================================
    // Helper methods
    // ==========================================================================================

    private TransactionContext createTestContext() throws InvalidArgumentException {
        Channel channel = createTestChannel("channel1");

        User user = hfclient.getUserContext();
        CryptoSuite cryptoSuite = hfclient.getCryptoSuite();

        return new TransactionContext(channel, user, cryptoSuite);
    }

    private Channel createTestChannel(String channelName) {

        Channel channel = null;

        try {
            Constructor<?> constructor = Channel.class.getDeclaredConstructor(String.class, HFClient.class);
            constructor.setAccessible(true);

            channel = (Channel) constructor.newInstance(channelName, hfclient);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail("Unexpected Exception " + e.getMessage());
        }

        return channel;
    }

}
