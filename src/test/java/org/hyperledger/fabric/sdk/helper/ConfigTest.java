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

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ConfigTest {

    public static Config config;

    /**
     * clearConfig "resets" Config so that the Config testcases can run without interference from other test suites.
     * Depending on what order JUnit decides to run the tests, Config could have been instantiated earlier and could
     * contain values that make the tests here fail.
     * @throws SecurityException
     * @throws NoSuchFieldException
     * @throws IllegalAccessException
     * @throws IllegalArgumentException
     *
     */
    private void clearConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        config = Config.getConfig();
        java.lang.reflect.Field configInstance = config.getClass().getDeclaredField("config");
        configInstance.setAccessible(true);
        configInstance.set(null, null);
    }

    @Before
    public void setUp() throws Exception {
        // reset Config before each test
        this.clearConfig();
    }

    @After
    public void tearDown() {
        // reset Config after each test. We do not want to interfere with the next test or the next test suite
        try {this.clearConfig();} catch (Exception e) {} ;
    }

    @Test
    public void testGetConfig() {
        System.setProperty("org.hyperledger.fabric.sdk.hash_algorithm", "XXX");
        config = Config.getConfig();
        assertEquals(config.getSecurityLevel(), 256);
        assertEquals(config.getHashAlgorithm(), "XXX");
        String[] cacerts = config.getPeerCACerts();
        assertEquals(cacerts[0], "/genesisblock/peercacert.pem");
        System.clearProperty("org.hyperledger.fabric.sdk.hash_algorithm");
    }

}
