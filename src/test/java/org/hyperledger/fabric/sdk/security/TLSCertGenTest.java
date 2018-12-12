/*
 *
 *  Copyright 2018 IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdk.security;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLSession;

import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.NettyServerBuilder;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import org.hyperledger.fabric.protos.peer.EndorserGrpc;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.security.certgen.TLSCertificateBuilder;
import org.hyperledger.fabric.sdk.security.certgen.TLSCertificateKeyPair;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class TLSCertGenTest {

    private static List<File> files2Cleanup = new LinkedList<>();
    private static String vendor = System.getProperty("java.vendor");
    private static final String TLS_PROTOCOL = "TLSv1.2";

    @AfterClass
    public static void cleanup() {
        files2Cleanup.forEach(File::delete);
    }

    @Ignore
    // issue when moved up to latest netty http://openjdk.5641.n7.nabble.com/sun-security-ssl-ProtocolVersion-valueOf-in-Java8-and-TLSv1-3-td350186.html
    @Test
    public void selfSignedTLSCertTest() throws Exception {
        AtomicBoolean handshakeOccured = new AtomicBoolean(false);
        TLSCertificateBuilder certBuilder = new TLSCertificateBuilder();

        TLSCertificateKeyPair serverCert = certBuilder.serverCert("localhost");
        File serverCertFile = createFile("server-cert.pem", serverCert.getCertPEMBytes());
        File serverKeyFile = createFile("server-key.pem", serverCert.getKeyPemBytes());

        TLSCertificateKeyPair clientCert = certBuilder.clientCert();
        File clientCertFile = createFile("client-cert.pem", clientCert.getCertPEMBytes());
        File clientKeyFile = createFile("client-key.pem", clientCert.getKeyPemBytes());
        Server server = NettyServerBuilder.forPort(0).addService(new MockEndorser()).
                intercept(mutualTLSInterceptor(clientCert.getCertDERBytes(), handshakeOccured))
                .sslContext(GrpcSslContexts.forServer(serverCertFile, serverKeyFile).protocols(TLS_PROTOCOL)
                        .trustManager(clientCertFile)
                        .clientAuth(ClientAuth.REQUIRE)
                        .build()).build();

        server.start();

        if (vendor.contains("IBM")) {
            // The TLS handshake doesn't work with IBM JRE, skipping
            server.shutdown();
            return;
        }

        NettyChannelBuilder channelBuilder = NettyChannelBuilder
                .forAddress("localhost", server.getPort())
                .sslContext(getSslContextBuilder(clientCertFile, clientKeyFile, serverCertFile).protocols(TLS_PROTOCOL).build())
                .negotiationType(NegotiationType.TLS);
        ManagedChannel chan = channelBuilder.build();
        FabricProposal.SignedProposal prop = FabricProposal.SignedProposal.getDefaultInstance();
        EndorserGrpc.newBlockingStub(chan).processProposal(prop);
        // Ensure that TLS handshake occurred
        Assert.assertTrue("Handshake didn't occur", handshakeOccured.get());
        chan.shutdown();
        server.shutdown();
    }

    private SslContextBuilder getSslContextBuilder(File clientCertFile, File clientKeyFile, File serverCertFile) {
        SslProvider sslprovider = SslProvider.OPENSSL;
        SslContextBuilder ctxBuilder = SslContextBuilder.forClient().protocols(TLS_PROTOCOL).trustManager(serverCertFile);
        SslContextBuilder clientContextBuilder = GrpcSslContexts.configure(ctxBuilder, sslprovider);
        clientContextBuilder = clientContextBuilder.keyManager(clientCertFile, clientKeyFile);
        return clientContextBuilder;
    }

    private ServerInterceptor mutualTLSInterceptor(byte[] expectedClientCert, AtomicBoolean toggleHandshakeOccured) {
        return new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> serverCall, Metadata metadata, ServerCallHandler<ReqT, RespT> serverCallHandler) {
                SSLSession sslSession = serverCall.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
                try {
                    javax.security.cert.X509Certificate[] certChain = sslSession.getPeerCertificateChain();
                    Assert.assertFalse("Client didn't send TLS certificate", certChain == null || certChain.length == 0);
                    byte[] clientRawCert = certChain[0].getEncoded();
                    // Ensure the client TLS cert matches the expected one - the one it was created with
                    boolean equalCerts = Arrays.equals(clientRawCert, expectedClientCert);
                    Assert.assertTrue("Expected certificate doesn't match actual", equalCerts);
                    toggleHandshakeOccured.set(true);
                } catch (Exception e) {
                    Assert.fail(String.format("Uncaught exception: %s", e.toString()));
                    e.printStackTrace();
                }
                return serverCallHandler.startCall(serverCall, metadata);
            }
        };
    }

    private static File createFile(String path, byte[] data) throws IOException {
        FileOutputStream key = new FileOutputStream(path);
        key.write(data);
        key.flush();
        key.close();
        File f = new File(path);
        files2Cleanup.add(f);
        return f;
    }

    private static class MockEndorser extends EndorserGrpc.EndorserImplBase {
        public void processProposal(org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request,
                                    io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse> responseObserver) {
            responseObserver.onNext(FabricProposalResponse.ProposalResponse.newBuilder().getDefaultInstanceForType());
            responseObserver.onCompleted();
        }
    }
}
