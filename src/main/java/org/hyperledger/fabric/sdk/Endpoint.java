/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLException;

import com.google.common.collect.ImmutableMap;
import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.helper.Utils.parseGrpcUrl;

class Endpoint {
    private static final Log logger = LogFactory.getLog(Endpoint.class);

    private final String addr;
    private final int port;
    private final String url;
    private byte[] clientTLSCertificateDigest;
    private byte[] tlsClientCertificatePEMBytes;
    private NettyChannelBuilder channelBuilder = null;

    private static final Map<String, String> CN_CACHE = Collections.synchronizedMap(new HashMap<>());

    Endpoint(String url, Properties properties) {
        logger.trace(String.format("Creating endpoint for url %s", url));
        this.url = url;
        String cn = null;
        String sslp = null;
        String nt = null;
        byte[] pemBytes = null;
        X509Certificate[] clientCert = null;
        PrivateKey clientKey = null;
        Properties purl = parseGrpcUrl(url);
        String protocol = purl.getProperty("protocol");
        this.addr = purl.getProperty("host");
        this.port = Integer.parseInt(purl.getProperty("port"));

        if (properties != null) {
            if ("grpcs".equals(protocol)) {
                CryptoPrimitives cp;
                try {
                    cp = new CryptoPrimitives();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                if (properties.containsKey("pemFile") && properties.containsKey("pemBytes")) {
                    throw new RuntimeException("Properties \"pemBytes\" and \"pemFile\" can not be both set.");
                }
                if (properties.containsKey("pemFile")) {
                    Path path = Paths.get(properties.getProperty("pemFile"));
                    try {
                        pemBytes = Files.readAllBytes(path);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else if (properties.containsKey("pemBytes")) {
                    pemBytes = (byte[]) properties.get("pemBytes");
                }
                if (null != pemBytes) {
                    try {
                        cn = properties.getProperty("hostnameOverride");
                        if (cn == null && "true".equals(properties.getProperty("trustServerCertificate"))) {
                            final String cnKey = new String(pemBytes, UTF_8);
                            cn = CN_CACHE.get(cnKey);
                            if (cn == null) {
                                X500Name x500name = new JcaX509CertificateHolder(
                                        (X509Certificate) cp.bytesToCertificate(pemBytes)).getSubject();
                                RDN rdn = x500name.getRDNs(BCStyle.CN)[0];
                                cn = IETFUtils.valueToString(rdn.getFirst().getValue());
                                CN_CACHE.put(cnKey, cn);
                            }
                        }
                    } catch (Exception e) {
                        /// Mostly a development env. just log it.
                        logger.error(
                                "Error getting Subject CN from certificate. Try setting it specifically with hostnameOverride property. "
                                        + e.getMessage());
                    }
                }
                // check for mutual TLS - both clientKey and clientCert must be present
                byte[] ckb = null, ccb = null;
                if (properties.containsKey("clientKeyFile") && properties.containsKey("clientKeyBytes")) {
                    throw new RuntimeException("Properties \"clientKeyFile\" and \"clientKeyBytes\" must cannot both be set");
                } else if (properties.containsKey("clientCertFile") && properties.containsKey("clientCertBytes")) {
                    throw new RuntimeException("Properties \"clientCertFile\" and \"clientCertBytes\" must cannot both be set");
                } else if (properties.containsKey("clientKeyFile") || properties.containsKey("clientCertFile")) {
                    if ((properties.getProperty("clientKeyFile") != null) && (properties.getProperty("clientCertFile") != null)) {
                        try {
                            ckb = Files.readAllBytes(Paths.get(properties.getProperty("clientKeyFile")));
                            ccb = Files.readAllBytes(Paths.get(properties.getProperty("clientCertFile")));
                        } catch (IOException e) {
                            throw new RuntimeException("Failed to parse TLS client key and/or cert", e);
                        }
                    } else {
                        throw new RuntimeException("Properties \"clientKeyFile\" and \"clientCertFile\" must both be set or both be null");
                    }
                } else if (properties.containsKey("clientKeyBytes") || properties.containsKey("clientCertBytes")) {
                    ckb = (byte[]) properties.get("clientKeyBytes");
                    ccb = (byte[]) properties.get("clientCertBytes");
                    if ((ckb == null) || (ccb == null)) {
                        throw new RuntimeException("Properties \"clientKeyBytes\" and \"clientCertBytes\" must both be set or both be null");
                    }
                }

                if ((ckb != null) && (ccb != null)) {
                    String what = "private key";
                    try {
                        logger.trace("client TLS private key bytes size:" + ckb.length);
                        clientKey = cp.bytesToPrivateKey(ckb);
                        logger.trace("converted TLS key.");
                        what = "certificate";
                        logger.trace("client TLS certificate bytes:" + Hex.encodeHexString(ccb));
                        clientCert = new X509Certificate[] {(X509Certificate) cp.bytesToCertificate(ccb)};
                        logger.trace("converted client TLS certificate.");
                        tlsClientCertificatePEMBytes = ccb; // Save this away it's the exact pem we used.
                    } catch (CryptoException e) {
                        throw new RuntimeException("Failed to parse TLS client " + what, e);
                    }
                }

                sslp = properties.getProperty("sslProvider");
                if (sslp == null) {
                    throw new RuntimeException("Property of sslProvider expected");
                }
                if (!sslp.equals("openSSL") && !sslp.equals("JDK")) {
                    throw new RuntimeException("Property of sslProvider has to be either openSSL or JDK");
                }

                nt = properties.getProperty("negotiationType");
                if (nt == null) {
                    throw new RuntimeException("Property of negotiationType expected");
                }
                if (!nt.equals("TLS") && !nt.equals("plainText")) {
                    throw new RuntimeException("Property of negotiationType has to be either TLS or plainText");
                }
            }
        }

        try {
            if (protocol.equalsIgnoreCase("grpc")) {
                this.channelBuilder = NettyChannelBuilder.forAddress(addr, port).usePlaintext(true);
                addNettyBuilderProps(channelBuilder, properties);
            } else if (protocol.equalsIgnoreCase("grpcs")) {
                if (pemBytes == null) {
                    // use root certificate
                    this.channelBuilder = NettyChannelBuilder.forAddress(addr, port);
                    addNettyBuilderProps(channelBuilder, properties);
                } else {
                    try {

                        SslProvider sslprovider = sslp.equals("openSSL") ? SslProvider.OPENSSL : SslProvider.JDK;
                        NegotiationType ntype = nt.equals("TLS") ? NegotiationType.TLS : NegotiationType.PLAINTEXT;

                        InputStream myInputStream = new ByteArrayInputStream(pemBytes);
                        SslContextBuilder clientContextBuilder = GrpcSslContexts.configure(SslContextBuilder.forClient(), sslprovider);
                        if (clientKey != null && clientCert != null) {
                            clientContextBuilder = clientContextBuilder.keyManager(clientKey, clientCert);
                        }
                        SslContext sslContext = clientContextBuilder
                            .trustManager(myInputStream)
                            .build();
                        this.channelBuilder = NettyChannelBuilder
                            .forAddress(addr, port)
                            .sslContext(sslContext)
                            .negotiationType(ntype);
                        if (cn != null) {
                            channelBuilder.overrideAuthority(cn);
                        }
                        addNettyBuilderProps(channelBuilder, properties);
                    } catch (SSLException sslex) {
                        throw new RuntimeException(sslex);
                    }
                }
            } else {
                throw new RuntimeException("invalid protocol: " + protocol);
            }
        } catch (RuntimeException e) {
            logger.error(e);
            throw e;
        } catch (Exception e) {
            logger.error(e);
            throw new RuntimeException(e);
        }
    }

    byte[] getClientTLSCertificateDigest() {
        //The digest must be SHA256 over the DER encoded certificate. The PEM has the exact DER sequence in hex encoding around the begin and end markers

        if (tlsClientCertificatePEMBytes != null && clientTLSCertificateDigest == null) {

            String pemCert = new String(tlsClientCertificatePEMBytes, UTF_8);
            byte[] derBytes = Base64.getDecoder().decode(
                    pemCert.replaceAll("-+[ \t]*(BEGIN|END)[ \t]+CERTIFICATE[ \t]*-+", "").replaceAll("\\s", "").trim()
            );

            Digest digest = new SHA256Digest();
            clientTLSCertificateDigest = new byte[digest.getDigestSize()];
            digest.update(derBytes, 0, derBytes.length);
            digest.doFinal(clientTLSCertificateDigest, 0);
        }

        return clientTLSCertificateDigest;
    }

    private static final Pattern METHOD_PATTERN = Pattern.compile("grpc\\.NettyChannelBuilderOption\\.([^.]*)$");
    private static final Map<Class<?>, Class<?>> WRAPPERS_TO_PRIM = new ImmutableMap.Builder<Class<?>, Class<?>>()
            .put(Boolean.class, boolean.class).put(Byte.class, byte.class).put(Character.class, char.class)
            .put(Double.class, double.class).put(Float.class, float.class).put(Integer.class, int.class)
            .put(Long.class, long.class).put(Short.class, short.class).put(Void.class, void.class).build();

    private void addNettyBuilderProps(NettyChannelBuilder channelBuilder, Properties props)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        if (props == null) {
            return;
        }

        for (Map.Entry<?, ?> es : props.entrySet()) {
            Object methodprop = es.getKey();
            if (methodprop == null) {
                continue;
            }
            String methodprops = String.valueOf(methodprop);

            Matcher match = METHOD_PATTERN.matcher(methodprops);

            String methodName = null;

            if (match.matches() && match.groupCount() == 1) {
                methodName = match.group(1).trim();

            }
            if (null == methodName || "forAddress".equals(methodName) || "build".equals(methodName)) {

                continue;
            }

            Object parmsArrayO = es.getValue();
            Object[] parmsArray;
            if (!(parmsArrayO instanceof Object[])) {
                parmsArray = new Object[] {parmsArrayO};

            } else {
                parmsArray = (Object[]) parmsArrayO;
            }

            Class<?>[] classParms = new Class[parmsArray.length];
            int i = -1;
            for (Object oparm : parmsArray) {
                ++i;

                if (null == oparm) {
                    classParms[i] = Object.class;
                    continue;
                }

                Class<?> unwrapped = WRAPPERS_TO_PRIM.get(oparm.getClass());
                if (null != unwrapped) {
                    classParms[i] = unwrapped;
                } else {

                    Class<?> clz = oparm.getClass();

                    Class<?> ecz = clz.getEnclosingClass();
                    if (null != ecz && ecz.isEnum()) {
                        clz = ecz;
                    }

                    classParms[i] = clz;
                }
            }

            final Method method = channelBuilder.getClass().getMethod(methodName, classParms);

            method.invoke(channelBuilder, parmsArray);

            if (logger.isTraceEnabled()) {
                StringBuilder sb = new StringBuilder(200);
                String sep = "";
                for (Object p : parmsArray) {
                    sb.append(sep).append(p + "");
                    sep = ", ";

                }
                logger.trace(String.format("Endpoint with url: %s set managed channel builder method %s (%s) ", url,
                        method, sb.toString()));

            }

        }

    }

    ManagedChannelBuilder<?> getChannelBuilder() {
        return this.channelBuilder;
    }

    String getHost() {
        return this.addr;
    }

    int getPort() {
        return this.port;
    }

}
