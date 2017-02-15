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

package org.hyperledger.fabric.sdk.helper;

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ConfigTest {

    public static Config config;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Properties sys = System.getProperties();
        sys.setProperty("org.hyperledger.fabric.sdk.hash_algorithm", "XXX");
        config = Config.getConfig();
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void testGetConfig() {
        assertEquals(config.getSecurityLevel(), 256);
        assertEquals(config.getHashAlgorithm(), "XXX");
        String[] cacerts = config.getPeerCACerts();
        assertEquals(cacerts[0], "/genesisblock/peercacert.pem");
    }

}
