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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class EndpointTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testEndpointNonPEM() {
        Endpoint ep = new Endpoint("grpc://localhost:524", null);
        Assert.assertEquals("localhost", ep.getHost());
        Assert.assertEquals(524, ep.getPort());

        ep = new Endpoint("grpcs://localhost:524", null);
        Assert.assertEquals("localhost", ep.getHost());

        try {
            new Endpoint("grpcs2://localhost:524", null);
            Assert.fail("protocol grpcs2 should have been invalid");
        } catch (RuntimeException rex) {
            Assert.assertEquals("Invalid protocol expected grpc or grpcs and found grpcs2.", rex.getMessage());
        }

        try {
            new Endpoint("grpcs://localhost", null);
            Assert.fail("should have thrown error as there is no port in the url");
        } catch (RuntimeException rex) {
            Assert.assertEquals("URL must be of the format protocol://host:port", rex.getMessage());
        }

        try {
            new Endpoint("", null);
            Assert.fail("should have thrown error as url is empty");
        } catch (RuntimeException rex) {
            Assert.assertEquals("URL cannot be null or empty", rex.getMessage());
        }

        try {
            new Endpoint(null, null);
            Assert.fail("should have thrown error as url is empty");
        } catch (RuntimeException rex) {
            Assert.assertEquals("URL cannot be null or empty", rex.getMessage());
        }
    }

    @Test
    public void testNullPropertySslProvider() {

        Properties testprops = new Properties();
        testprops.setProperty("hostnameOverride", "override");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testEmptyPropertySslProvider() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("property of sslProvider has to be either openSSL or JDK");

        Properties testprops = new Properties();
        testprops.setProperty("sslProvider", "closedSSL");
        testprops.setProperty("hostnameOverride", "override");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testNullPropertyNegotiationType() {

        Properties testprops = new Properties();
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testEmptyPropertyNegotiationType() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("property of negotiationType has to be either TLS or plainText");

        Properties testprops = new Properties();
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testExtractCommonName() {

        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");

        Assert.assertSame(new Endpoint("grpcs://localhost:594", testprops).getClass(), Endpoint.class);
    }

    @Test
    public void testNullPropertyClientKeyFile() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Properties \"clientKeyFile\" and \"clientCertFile\" must both be set or both be null");

        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");
        testprops.setProperty("clientCertFile", "clientCertFile");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testNullPropertyClientKeyBytes() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Properties \"clientKeyBytes\" and \"clientCertBytes\" must both be set or both be null");

        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");
        testprops.put("clientCertBytes", new byte[100]);

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testNullPropertyClientCertFile() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Properties \"clientKeyFile\" and \"clientCertFile\" must both be set or both be null");

        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");
        testprops.setProperty("clientKeyFile", "clientKeyFile");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testNullPropertyClientCertBytes() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Properties \"clientKeyBytes\" and \"clientCertBytes\" must both be set or both be null");

        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");
        testprops.put("clientKeyBytes", new byte[100]);

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testBadClientKeyFile() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Failed to parse TLS client private key");

        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");
        testprops.setProperty("clientKeyFile", System.getProperty("user.dir") + "/src/test/resources/bad-ca.crt");
        testprops.setProperty("clientCertFile", System.getProperty("user.dir") + "/src/test/resources/tls-client.crt");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testBadClientCertFile() {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Failed to parse TLS client certificate");

        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");
        testprops.setProperty("clientKeyFile", System.getProperty("user.dir") + "/src/test/resources/tls-client.key");
        testprops.setProperty("clientCertFile", System.getProperty("user.dir") + "/src/test/resources/bad-ca.crt");

        new Endpoint("grpcs://localhost:594", testprops);
    }

    @Test
    public void testClientTLSInvalidProperties() {
        Properties testprops = new Properties();
        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");

        testprops.setProperty("clientKeyFile", System.getProperty("user.dir") + "/src/test/resources/tls-client.key");
        testprops.put("clientKeyBytes", new byte[100]);
        try {
            new Endpoint("grpcs://localhost:594", testprops);
        } catch (RuntimeException e) {
            Assert.assertEquals("Properties \"clientKeyFile\" and \"clientKeyBytes\" must cannot both be set", e.getMessage());
        }

        testprops.remove("clientKeyFile");
        testprops.remove("clientKeyBytes");
        testprops.setProperty("clientCertFile", System.getProperty("user.dir") + "/src/test/resources/tls-client.crt");
        testprops.put("clientCertBytes", new byte[100]);
        try {
            new Endpoint("grpcs://localhost:594", testprops);
        } catch (RuntimeException e) {
            Assert.assertEquals("Properties \"clientCertFile\" and \"clientCertBytes\" must cannot both be set", e.getMessage());
        }

        testprops.remove("clientCertFile");
        testprops.put("clientKeyBytes", new byte[100]);
        testprops.put("clientCertBytes", new byte[100]);
        try {
            new Endpoint("grpcs://localhost:594", testprops);
        } catch (RuntimeException e) {
            Assert.assertEquals("Failed to parse TLS client private key", e.getMessage());
        }
    }

    @Test
    public void testClientTLSProperties() {

        Properties testprops = new Properties();

        testprops.setProperty("trustServerCertificate", "true");
        testprops.setProperty("pemFile", System.getProperty("user.dir") + "/src/test/resources/keypair-signed.crt");
        testprops.setProperty("sslProvider", "openSSL");
        testprops.setProperty("hostnameOverride", "override");
        testprops.setProperty("negotiationType", "TLS");
        testprops.setProperty("clientKeyFile", System.getProperty("user.dir") + "/src/test/resources/tls-client.key");
        testprops.setProperty("clientCertFile", System.getProperty("user.dir") + "/src/test/resources/tls-client.crt");
        new Endpoint("grpcs://localhost:594", testprops);

        byte[] ckb = null, ccb = null;
        try {
            ckb = Files.readAllBytes(Paths.get(System.getProperty("user.dir") + "/src/test/resources/tls-client.key"));
            ccb = Files.readAllBytes(Paths.get(System.getProperty("user.dir") + "/src/test/resources/tls-client.crt"));
        } catch (Exception e) {
            Assert.fail("failed to read tls client key or cert: " + e.toString());
        }
        testprops.remove("clientKeyFile");
        testprops.remove("clientCertFile");
        testprops.put("clientKeyBytes", ckb);
        testprops.put("clientCertBytes", ccb);
        new Endpoint("grpcs://localhost:594", testprops);
    }
}
