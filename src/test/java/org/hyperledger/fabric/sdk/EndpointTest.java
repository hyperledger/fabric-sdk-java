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

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.getField;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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
            Assert.assertEquals("URL must be of the format protocol://host:port. Found: 'grpcs://localhost'", rex.getMessage());
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
        thrown.expectMessage("Failed endpoint grpcs://localhost:594 to parse TLS client private key");

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
        thrown.expectMessage("Failed endpoint grpcs://localhost:594 to parse TLS client certificate");

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
            Assert.assertTrue(e.getMessage().contains("Failed endpoint grpcs://localhost:594 to parse TLS client private key"));
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
        Endpoint endpoint = new Endpoint("grpcs://localhost:594", testprops);

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

    @Test
    public void testClientTLSCACertProperties() throws Exception {

        Properties testprops = new Properties();

        testprops.setProperty("pemFile", "src/test/fixture/testPems/caBundled.pems," + // has 4 certs
                "src/test/fixture/testPems/AnotherUniqCA.pem"); // has 1

        testprops.put("pemBytes", Files.readAllBytes(Paths.get("src/test/fixture/testPems/Org2MSP_CA.pem"))); //Can have pem bytes too. 1 cert

        class TEndpoint extends Endpoint {

            private SslContextBuilder sslContextBuilder;

            TEndpoint(String url, Properties properties) {
                super(url, properties);
            }

            @Override
            protected SslContextBuilder getSslContextBuilder(X509Certificate[] clientCert, PrivateKey clientKey, SslProvider sslprovider) {
                sslContextBuilder = super.getSslContextBuilder(clientCert, clientKey, sslprovider);
                return sslContextBuilder;
            }

        }
        TEndpoint endpoint = new TEndpoint("grpcs://localhost:594", testprops);
        X509Certificate[] certs = (X509Certificate[]) getField(endpoint.sslContextBuilder, "trustCertCollection");

        Set<BigInteger> expected = new HashSet<>(Arrays.asList(
                new BigInteger("4804555946196630157804911090140692961"),
                new BigInteger("127556113420528788056877188419421545986539833585"),
                new BigInteger("704500179517916368023344392810322275871763581896"),
                new BigInteger("70307443136265237483967001545015671922421894552"),
                new BigInteger("276393268186007733552859577416965113792"),
                new BigInteger("217904166635533061823782766071154643254")));

        for (X509Certificate cert : certs) {
            final BigInteger serialNumber = cert.getSerialNumber();
            assertTrue(format("Missing certificate %s", serialNumber + ""), expected.contains(serialNumber));
        }
        assertEquals("Didn't find the expected number of certs", expected.size(), certs.length); // should have same number.
    }

    @Test
    public void testClientTLSCACertPropertiesBadFile() throws Exception {
        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Failed to read certificate file");

        Properties testprops = new Properties();

        testprops.setProperty("pemFile", "src/test/fixture/testPems/caBundled.pems," + // has 3 certs
                "src/test/fixture/testPems/IMBAD" +
                ",src/test/fixture/testPems/Org1MSP_CA.pem"); // has 1

        Endpoint endpoint = new Endpoint("grpcs://localhost:594", testprops);

    }
}
