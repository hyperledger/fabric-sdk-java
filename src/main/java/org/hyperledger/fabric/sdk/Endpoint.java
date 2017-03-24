/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.SSLException;

import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import static org.hyperledger.fabric.sdk.helper.SDKUtil.parseGrpcUrl;

class Endpoint {
    private static final Log logger = LogFactory.getLog(Endpoint.class);

    private final String addr;
    private final int port;
    private final Properties properties;
    private ManagedChannelBuilder<?> channelBuilder = null;


    private final static Map<String, String> cnCache = Collections.synchronizedMap(new HashMap<>());

    Endpoint(String url, Properties properties) {

        this.properties = properties;

        String pem = null;
        String cn = null;

        Properties purl = parseGrpcUrl(url);
        String protocol = purl.getProperty("protocol");
        this.addr = purl.getProperty("host");
        this.port = Integer.parseInt(purl.getProperty("port"));

        if (properties != null) {
            if ("grpcs".equals(protocol)) {
                try {
                    pem = properties.getProperty("pemFile");
                    cn = properties.getProperty("hostnameOverride");

                    if (cn == null && "true".equals(properties.getProperty("trustServerCertificate"))) {

                        File pemF = new File(pem);
                        final String cnKey = pemF.getAbsolutePath() + pemF.length() + pemF.lastModified();

                        cn = cnCache.get(cnKey);
                        if (cn == null) {
                            Path path = Paths.get(pem);
                            byte[] data = Files.readAllBytes(path);

                            CryptoPrimitives cp = new CryptoPrimitives();


                            X500Name x500name = new JcaX509CertificateHolder((X509Certificate) cp.bytesToCertificate(data)).getSubject();
                            RDN rdn = x500name.getRDNs(BCStyle.CN)[0];
                            //   cnn =  cn +"";
                            AttributeTypeAndValue f = rdn.getFirst();
                            cn = IETFUtils.valueToString(rdn.getFirst().getValue());
                            cnCache.put(cnKey, cn);
                        }


                    }
                } catch (Exception e) {
                    /// Mostly a development env. just log it.
                    logger.error("Error getting Subject CN from certificate. Try setting it specifically with hostnameOverride property. " + e.getMessage());

                }
            }

        }


        if (protocol.equalsIgnoreCase("grpc")) {
            this.channelBuilder = ManagedChannelBuilder.forAddress(addr, port)
                    .usePlaintext(true);
        } else if (protocol.equalsIgnoreCase("grpcs")) {
            if (StringUtil.isNullOrEmpty(pem)) {
                // use root certificate
                this.channelBuilder = ManagedChannelBuilder.forAddress(addr, port);
            } else {
                try {


                    SslContext sslContext = GrpcSslContexts.forClient().trustManager(new java.io.File(pem)).build();
                    this.channelBuilder = NettyChannelBuilder.forAddress(addr, port)
                            .sslContext(sslContext);
                    if (cn != null) {
                        channelBuilder.overrideAuthority(cn);
                    }
                } catch (SSLException sslex) {
                    throw new RuntimeException(sslex);
                }
            }
        } else {
            throw new RuntimeException("invalid protocol: " + protocol);
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
