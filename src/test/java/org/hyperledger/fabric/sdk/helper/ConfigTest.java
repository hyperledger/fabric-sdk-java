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

import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ConfigTest {

        private TestConfigHelper configHelper = new TestConfigHelper() ;
        private String originalValue;

    @Before
    public void setUp() throws Exception {
        originalValue = Config.getConfig().getHashAlgorithm();
        // reset Config before each test
        configHelper.clearConfig();
    }

    @After
    public void tearDown() {
        // reset Config after each test. We do not want to interfere with the next test or the next test suite
        try {configHelper.clearConfig();} catch (Exception e) {} ;
    }

    @Test
    public void testGetConfig() {
        System.setProperty(Config.HASH_ALGORITHM, "XXX");
        Config config = Config.getConfig();
        assertEquals(config.getSecurityLevel(), 256);
        assertEquals(config.getHashAlgorithm(), "XXX");
        String[] cacerts = config.getPeerCACerts();
        assertEquals(cacerts[0], "/genesisblock/peercacert.pem");

        // Clean up so that other tests can get valid values from the Config singleton.
        // configHelper.clearConfig() is not enough. System.clearProperty() is not enough.
        // Have to set the system property back to the original value as well.
        System.setProperty(Config.HASH_ALGORITHM, originalValue);
    }

}
