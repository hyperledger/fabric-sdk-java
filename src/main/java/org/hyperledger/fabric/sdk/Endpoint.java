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

import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.util.internal.StringUtil;

import javax.net.ssl.SSLException;
import java.util.Properties;

import static org.hyperledger.fabric.sdk.helper.SDKUtil.parseGrpcUrl;

public class Endpoint {

    private final String addr;
    private final int port;
    private ManagedChannelBuilder<?> channelBuilder = null;

    public Endpoint(String url, String pem) {

        Properties purl = parseGrpcUrl(url);
        String protocol = purl.getProperty("protocol");
        this.addr = purl.getProperty("host");
        this.port = Integer.parseInt(purl.getProperty("port"));

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
                } catch (SSLException sslex) {
                    throw new RuntimeException(sslex);
                }
            }
        } else {
            throw new RuntimeException("invalid protocol: " + protocol);
        }
    }

    public ManagedChannelBuilder<?> getChannelBuilder() {
        return this.channelBuilder;
    }

    String getHost() {
        return this.addr;
    }


    int getPort() {
        return this.port;
    }
}
