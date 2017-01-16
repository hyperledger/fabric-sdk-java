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

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.util.internal.StringUtil;

import javax.net.ssl.SSLException;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

abstract  class  Remote {

    private String addr;
    private int port;
    String url;

    protected ManagedChannel getChannel() {
        return channelBuilder.build();
    }

    private ManagedChannelBuilder<?> channelBuilder = null;

    Remote( String url, String pem) {
        

        Properties purl = parseUrl(url);
        String protocol = purl.getProperty("protocol");
        this.addr = purl.getProperty("host");
        this.port = Integer.parseInt(purl.getProperty("port"));



        if (protocol.equalsIgnoreCase("grpc")) {//
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


    ManagedChannelBuilder<?> getChannelBuilder() {
        return this.channelBuilder;
    }

    String getHost() {
        return this.addr;
    }


    int getPort() {
        return this.port;
    }

    private Properties parseUrl(String url) {
        if (StringUtil.isNullOrEmpty(url)) {
            throw new RuntimeException("URL cannot be null or empty");
        }

        Properties props = new Properties();
        Pattern p = Pattern.compile("([^:]+)[:]//([^:]+)[:]([0-9]+)", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(url);
        if (m.matches()) {
            props.setProperty("protocol", m.group(1));
            props.setProperty("host", m.group(2));
            props.setProperty("port", m.group(3));
        } else {
            throw new RuntimeException("URL must be of the format protocol://host:port");
        }

        // TODO: allow all possible formats of the URL
        return props;
    }


    //  private static final Log logger = LogFactory.getLog(EndorserClient.class);

   // private final ManagedChannel channel;
   // abstract EndorserGrpc.EndorserBlockingStub blockingStub;

    /**
     * Construct client for accessing Peer server using the existing channel.
     */
    //       private static final Log logger = LogFactory.getLog(EndorserClient.class);



    public void shutdown() throws InterruptedException {
  //      channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }


    @Override
    public void finalize() {
        try {
            shutdown();
        } catch (InterruptedException e) {
//            logger.debug("Failed to shutdown the PeerClient");
        }
    }




}
