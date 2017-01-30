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
