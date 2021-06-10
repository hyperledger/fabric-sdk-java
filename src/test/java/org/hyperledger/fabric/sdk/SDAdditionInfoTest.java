/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.sdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;

import org.hyperledger.fabric.sdk.exception.ServiceDiscoveryException;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class SDAdditionInfoTest {
    private static byte[][] asByteArrays(String... strings) {
        return Arrays.stream(strings)
                .map(cert -> cert.getBytes(StandardCharsets.UTF_8))
                .toArray(byte[][]::new);
    }

    private static Channel.SDOrdererAdditionInfo newOrdererAdditionInfo(byte[][] tlsCerts, byte[][] tlsIntermediateCerts) {
        return new Channel.SDOrdererAdditionInfo() {
            @Override
            public String getEndpoint() {
                return null;
            }

            @Override
            public Properties getProperties() {
                return null;
            }

            @Override
            public String getMspId() {
                return null;
            }

            @Override
            public Channel getChannel() {
                return null;
            }

            @Override
            public HFClient getClient() {
                return null;
            }

            @Override
            public byte[][] getTLSCerts() {
                return tlsCerts;
            }

            @Override
            public byte[][] getTLSIntermediateCerts() {
                return tlsIntermediateCerts;
            }

            @Override
            public Map<String, Orderer> getEndpointMap() {
                return null;
            }

            @Override
            public boolean isTLS() {
                return false;
            }
        };
    }

    private static Channel.SDPeerAdditionInfo newPeerAdditionInfo(byte[][] tlsCerts, byte[][] tlsIntermediateCerts) {
        return new Channel.SDPeerAdditionInfo() {
            @Override
            public String getName() {
                return null;
            }

            @Override
            public String getMspId() {
                return null;
            }

            @Override
            public String getEndpoint() {
                return null;
            }

            @Override
            public Channel getChannel() {
                return null;
            }

            @Override
            public HFClient getClient() {
                return null;
            }

            @Override
            public byte[][] getTLSCerts() {
                return tlsCerts;
            }

            @Override
            public byte[][] getTLSIntermediateCerts() {
                return tlsIntermediateCerts;
            }

            @Override
            public Map<String, Peer> getEndpointMap() {
                return null;
            }

            @Override
            public Properties getProperties() {
                return null;
            }

            @Override
            public boolean isTLS() {
                return false;
            }
        };
    }

    @Test
    public void testOrdererSeparatesCertificatesWithNewlines() throws ServiceDiscoveryException {
        byte[][] tlsCerts = asByteArrays("a", "b");
        byte[][] intermediateCerts = asByteArrays("c", "d");
        Channel.SDOrdererAdditionInfo additionInfo = newOrdererAdditionInfo(tlsCerts, intermediateCerts);

        byte[] allCerts = additionInfo.getAllTLSCerts();

        String[] allCertLines = new String(allCerts, StandardCharsets.UTF_8).split("\n");
        assertTrue("Expected at least 4 lines, got:\n" + Arrays.toString(allCertLines), allCertLines.length >= 4);
    }

    @Test
    public void testPeerSeparatesCertificatesWithNewlines() throws ServiceDiscoveryException {
        byte[][] tlsCerts = asByteArrays("a", "b");
        byte[][] intermediateCerts = asByteArrays("c", "d");
        Channel.SDPeerAdditionInfo additionInfo = newPeerAdditionInfo(tlsCerts, intermediateCerts);

        byte[] allCerts = additionInfo.getAllTLSCerts();

        String[] allCertLines = new String(allCerts, StandardCharsets.UTF_8).split("\n");
        assertTrue("Expected at least 4 lines, got:\n" + Arrays.toString(allCertLines), allCertLines.length >= 4);
    }
}
