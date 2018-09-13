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

import org.junit.Assert;
import org.junit.Test;

public class ChannelConfigurationTest {
    private static final String TEST_BYTES_1 = "0A205E87B04D3B137E4F";
    private static final String TEST_BYTES_2 = "00112233445566778899";

    @Test
    public void testChannelConfigurationByeArray() throws Exception {
        // Test empty constructor
        new ChannelConfiguration();

        // Test byte array constructor
        ChannelConfiguration testChannelConfig = new ChannelConfiguration(TEST_BYTES_1.getBytes());
        testChannelConfig.setChannelConfiguration(TEST_BYTES_2.getBytes());
        Assert.assertEquals(TEST_BYTES_2, new String(testChannelConfig.getChannelConfigurationAsBytes()));
    }
}
