/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric.sdk;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.discovery.Protocol;
import org.hyperledger.fabric.protos.gossip.Message;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.msp.MspConfigPackage;
import org.hyperledger.fabric.sdk.Channel.ServiceDiscoveryChaincodeCalls;
import org.hyperledger.fabric.sdk.ServiceDiscovery.SDLayout.SDGroup;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.hyperledger.fabric.sdk.exception.ServiceDiscoveryException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.toHexString;

public class ServiceDiscovery {
    private static final Log logger = LogFactory.getLog(ServiceDiscovery.class);
    private static final boolean DEBUG = logger.isDebugEnabled();
    private static final Config config = Config.getConfig();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;
    private static final int SERVICE_DISCOVERY_WAITTIME = config.getServiceDiscoveryWaitTime();
    private static final Random random = new Random();
    private final Collection<Peer> serviceDiscoveryPeers;
    private final Channel channel;
    private final TransactionContext transactionContext;
    private final String channelName;
    private volatile Map<String, SDChaindcode> chaindcodeMap = new HashMap<>();
    private static final boolean asLocalhost = config.discoverAsLocalhost();

    ServiceDiscovery(Channel channel, Collection<Peer> serviceDiscoveryPeers, TransactionContext transactionContext) {
        this.serviceDiscoveryPeers = serviceDiscoveryPeers;
        this.channel = channel;
        this.channelName = channel.getName();
        this.transactionContext = transactionContext.retryTransactionSameContext();
    }

    SDChaindcode discoverEndorserEndpoint(TransactionContext transactionContext, final String name) throws ServiceDiscoveryException {
        Map<String, SDChaindcode> lchaindcodeMap = chaindcodeMap;
        if (lchaindcodeMap != null) { // check if we have it already.
            SDChaindcode sdChaindcode = lchaindcodeMap.get(name);
            if (null != sdChaindcode) {
                return sdChaindcode;
            }
        }

        final ServiceDiscoveryChaincodeCalls serviceDiscoveryChaincodeCalls = new ServiceDiscoveryChaincodeCalls(name);
        LinkedList<ServiceDiscoveryChaincodeCalls> cc = new LinkedList<>();
        cc.add(serviceDiscoveryChaincodeCalls);
        List<List<ServiceDiscoveryChaincodeCalls>> ccl = new LinkedList<>();
        ccl.add(cc);

        Map<String, SDChaindcode> dchaindcodeMap = discoverEndorserEndpoints(transactionContext, ccl);
        final SDChaindcode sdChaindcode = dchaindcodeMap.get(name);
        if (null == sdChaindcode) {
            throw new ServiceDiscoveryException(format("Failed to find any endorsers for chaincode %s. See logs for details", name));
        }
        return sdChaindcode;
    }

    Collection<String> getDiscoveredChaincodeNames() {
        final SDNetwork lsdNetwork = fullNetworkDiscovery(false);
        if (null == lsdNetwork) {
            return Collections.emptyList();
        }

        return new ArrayList<>(lsdNetwork.getChaincodesNames());
    }

    class SDNetwork {
        final Map<String, List<byte[]>> tlsCerts = new HashMap<>();
        final Map<String, List<byte[]>> tlsIntermCerts = new HashMap<>();
        long discoveryTime;

        void addTlsCert(String mspid, byte[] cert) {
            if (IS_TRACE_LEVEL) {
                logger.trace(format("Channel %s service discovery MSPID %s adding TLSCert %s", channelName, mspid, toHexString(cert)));
            }
            tlsCerts.computeIfAbsent(mspid, k -> new LinkedList<>()).add(cert);
        }

        void addTlsIntermCert(String mspid, byte[] cert) {
            if (IS_TRACE_LEVEL) {
                logger.trace(format("Channel %s service discovery MSPID %s adding intermediate TLSCert %s", channelName, mspid, toHexString(cert)));
            }
            tlsIntermCerts.computeIfAbsent(mspid, k -> new LinkedList<>()).add(cert);
        }

        SDEndorser getEndorserByEndpoint(String endpoint) {
            return endorsers.get(endpoint);
        }

        public Collection<SDEndorser> getEndorsers() {
            return Collections.unmodifiableCollection(endorsers.values());
        }

        Map<String, SDEndorser> endorsers = Collections.emptyMap();

        Map<String, SDOrderer> ordererEndpoints = Collections.emptyMap();

        Set<String> getOrdererEndpoints() {
            return Collections.unmodifiableSet(ordererEndpoints.keySet());
        }

        Collection<SDOrderer> getSDOrderers() {
            return ordererEndpoints.values();
        }

        Set<String> getPeerEndpoints() {
            return Collections.unmodifiableSet(endorsers.keySet());
        }

        Set<String> chaincodeNames = null;

        Set<String> getChaincodesNames() {
            if (null == chaincodeNames) {
                if (null == endorsers) {
                    chaincodeNames = Collections.emptySet();
                    return chaincodeNames;
                }

                Set<String> ret = new HashSet<>();
                endorsers.values().forEach(sdEndorser -> {
                    if (null != sdEndorser.chaincodesList) {
                        sdEndorser.chaincodesList.forEach(chaincode -> ret.add(chaincode.getName()));
                    }
                });
                chaincodeNames = ret;
            }

            return chaincodeNames;
        }

        Collection<byte[]> getTlsCerts(final String mspid) {

            final Collection<byte[]> bytes = tlsCerts.get(mspid);
            if (null == bytes) {
                logger.debug(format("Channel %s no tls ca certs for mspid: %s", channelName, mspid));
                return Collections.emptyList();

            }
            if (bytes.isEmpty()) {
                logger.debug(format("Channel %s no tls ca certs for mspid: %s", channelName, mspid));
            }
            return Collections.unmodifiableCollection(bytes);
        }

        Collection<byte[]> getTlsIntermediateCerts(String mspid) {
            final Collection<byte[]> bytes = tlsIntermCerts.get(mspid);

            if (null == bytes) {
                logger.debug(format("Channel %s no tls intermediary ca certs for mspid: %s", channelName, mspid));
                return Collections.emptyList();

            }
            if (bytes.isEmpty()) {
                logger.debug(format("Channel %s no tls intermediary ca certs for mspid: %s", channelName, mspid));
            }
            return Collections.unmodifiableCollection(bytes);

        }
    }

    private volatile SDNetwork sdNetwork = null;

    private final Set<ByteString> certs = ConcurrentHashMap.newKeySet();

    SDNetwork networkDiscovery(TransactionContext ltransactionContext, boolean force) {
        logger.trace(format("Network discovery force: %b", force));

        ArrayList<Peer> speers = new ArrayList<>(serviceDiscoveryPeers);
        Collections.shuffle(speers);
        SDNetwork ret = sdNetwork;

        if (!force && null != ret && ret.discoveryTime + SERVICE_DISCOVER_FREQ_SECONDS * 1000 > System.currentTimeMillis()) {
            return ret;
        }
        ret = null;

        for (final Peer serviceDiscoveryPeer : speers) {
            try {
                URI serviceDiscoveryPeerURI = URI.create(serviceDiscoveryPeer.getUrl());
                boolean isTLS = serviceDiscoveryPeerURI.getScheme().equals("grpcs");
                logger.trace(format("Service discovery peer %s using TLS: %b", serviceDiscoveryPeerURI.toString(), isTLS));

                SDNetwork lsdNetwork = new SDNetwork();
                final byte[] clientTLSCertificateDigest = serviceDiscoveryPeer.getClientTLSCertificateDigest();

                logger.info(format("Channel %s doing discovery with peer: %s", channelName, serviceDiscoveryPeer.toString()));

                if (null == clientTLSCertificateDigest) {
                    throw new RuntimeException(format("Channel %s, peer %s requires mutual tls for service discovery.", channelName, serviceDiscoveryPeer));
                }

                ByteString clientIdent = ltransactionContext.getIdentity().toByteString();
                ByteString tlshash = ByteString.copyFrom(clientTLSCertificateDigest);
                Protocol.AuthInfo authentication = Protocol.AuthInfo.newBuilder().setClientIdentity(clientIdent).setClientTlsCertHash(tlshash).build();

                List<Protocol.Query> fq = new ArrayList<>(2);
                fq.add(Protocol.Query.newBuilder().setChannel(channelName).setConfigQuery(Protocol.ConfigQuery.newBuilder().build()).build());
                fq.add(Protocol.Query.newBuilder().setChannel(channelName).setPeerQuery(Protocol.PeerMembershipQuery.newBuilder().build()).build());

                Protocol.Request request = Protocol.Request.newBuilder().addAllQueries(fq).setAuthentication(authentication).build();
                ByteString payloadBytes = request.toByteString();
                ByteString signatureBytes = ltransactionContext.signByteStrings(payloadBytes);
                Protocol.SignedRequest sr = Protocol.SignedRequest.newBuilder()
                        .setPayload(payloadBytes).setSignature(signatureBytes).build();

                if (IS_TRACE_LEVEL && null != diagnosticFileDumper) { // dump protobuf we sent
                    logger.trace(format("Service discovery channel %s %s service chaincode query sent %s", channelName, serviceDiscoveryPeer,
                            diagnosticFileDumper.createDiagnosticProtobufFile(sr.toByteArray())));
                }

                final Protocol.Response response = serviceDiscoveryPeer.sendDiscoveryRequestAsync(sr).get(SERVICE_DISCOVERY_WAITTIME, TimeUnit.MILLISECONDS);

                if (IS_TRACE_LEVEL && null != diagnosticFileDumper) { // dump protobuf we get
                    logger.trace(format("Service discovery channel %s %s service discovery returned %s", channelName, serviceDiscoveryPeer,
                            diagnosticFileDumper.createDiagnosticProtobufFile(response.toByteArray())));
                }

                serviceDiscoveryPeer.hasConnected();
                final List<Protocol.QueryResult> resultsList = response.getResultsList();
                Protocol.QueryResult queryResult;
                Protocol.QueryResult queryResult2;

                queryResult = resultsList.get(0); //configquery
                if (queryResult.getResultCase().getNumber() == Protocol.QueryResult.ERROR_FIELD_NUMBER) {
                    logger.warn(format("Channel %s peer: %s error during service discovery %s", channelName, serviceDiscoveryPeer.toString(), queryResult.getError().getContent()));
                    continue;
                }
                queryResult2 = resultsList.get(1);
                if (queryResult2.getResultCase().getNumber() == Protocol.QueryResult.ERROR_FIELD_NUMBER) {
                    logger.warn(format("Channel %s peer %s service discovery error %s", channelName, serviceDiscoveryPeer.toString(), queryResult2.getError().getContent()));
                    continue;
                }
                Protocol.ConfigResult configResult = queryResult.getConfigResult();

                Map<String, MspConfigPackage.FabricMSPConfig> msps = configResult.getMspsMap();
                Set<ByteString> cbbs = new HashSet<>(msps.size() * 4);

                for (Map.Entry<String, MspConfigPackage.FabricMSPConfig> i : msps.entrySet()) {
                    final MspConfigPackage.FabricMSPConfig value = i.getValue();
                    final String mspid = value.getName();
                    cbbs.addAll(value.getRootCertsList());
                    cbbs.addAll(value.getIntermediateCertsList());

                    value.getTlsRootCertsList().forEach(bytes -> lsdNetwork.addTlsCert(mspid, bytes.toByteArray()));

                    value.getTlsIntermediateCertsList().forEach(bytes -> lsdNetwork.addTlsIntermCert(mspid, bytes.toByteArray()));
                }

                List<byte[]> toaddCerts = new LinkedList<>();

                synchronized (certs) {
                    cbbs.forEach(bytes -> {
                        if (certs.add(bytes)) {
                            toaddCerts.add(bytes.toByteArray());
                        }
                    });
                }
                if (!toaddCerts.isEmpty()) { // add them to crypto store.
                    channel.client.getCryptoSuite().loadCACertificatesAsBytes(toaddCerts);
                }

                Map<String, SDOrderer> ordererEndpoints = new HashMap<>();
                Map<String, Protocol.Endpoints> orderersMap = configResult.getOrderersMap();
                for (Map.Entry<String, Protocol.Endpoints> i : orderersMap.entrySet()) {
                    final String mspid = i.getKey();

                    Protocol.Endpoints value = i.getValue();
                    for (Protocol.Endpoint l : value.getEndpointList()) {
                        logger.trace(format("Channel: %s peer: %s discovered orderer MSPID: %s, endpoint: %s:%s", channelName, serviceDiscoveryPeer, mspid, l.getHost(), l.getPort()));
                        String host = asLocalhost ? "localhost" : l.getHost();
                        String endpoint = (host + ":" + l.getPort()).trim().toLowerCase();

                        SDOrderer discoveredAlready = ordererEndpoints.get(endpoint);
                        if (discoveredAlready != null) {
                            if (!mspid.equals(discoveredAlready.getMspid())) {
                                logger.error(format("Service discovery in channel: %s, peer: %s found Orderer endpoint: %s with two mspids: '%s', '%s'", channelName, serviceDiscoveryPeer, endpoint, mspid, discoveredAlready.getMspid()));
                                continue; // report it and ignore.
                            }
                            logger.debug(format("Service discovery in channel: %s, peer: %s found Orderer endpoint: %s mspid: %s discovered twice", channelName, serviceDiscoveryPeer, endpoint, mspid));
                            continue;
                        }

                        Properties properties = new Properties();
                        if (asLocalhost) {
                            properties.put("hostnameOverride", l.getHost());
                        }

                        final SDOrderer sdOrderer = new SDOrderer(mspid, endpoint, lsdNetwork.getTlsCerts(mspid), lsdNetwork.getTlsIntermediateCerts(mspid), properties, isTLS);

                        ordererEndpoints.put(sdOrderer.getEndPoint(), sdOrderer);
                    }
                }
                lsdNetwork.ordererEndpoints = ordererEndpoints;

                Protocol.PeerMembershipResult membership = queryResult2.getMembers();

                lsdNetwork.endorsers = new HashMap<>();

                for (Map.Entry<String, Protocol.Peers> peers : membership.getPeersByOrgMap().entrySet()) {
                    final String mspId = peers.getKey();
                    final Protocol.Peers peer = peers.getValue();

                    for (Protocol.Peer pp : peer.getPeersList()) {
                        SDEndorser ppp = new SDEndorser(pp, lsdNetwork.getTlsCerts(mspId), lsdNetwork.getTlsIntermediateCerts(mspId), asLocalhost, isTLS);

                        SDEndorser discoveredAlready = lsdNetwork.endorsers.get(ppp.getEndpoint());
                        if (null != discoveredAlready) {
                            if (!mspId.equals(discoveredAlready.getMspid())) {
                                logger.error(format("Service discovery in channel: %s, peer: %s,  found endorser endpoint: %s with two mspids: '%s', '%s'", channelName, serviceDiscoveryPeer, ppp.getEndpoint(), mspId, discoveredAlready.getMspid()));
                                continue; // report it and ignore.
                            }
                            logger.debug(format("Service discovery in channel %s peer: %s found Endorser endpoint: %s mspid: %s discovered twice", channelName, serviceDiscoveryPeer, ppp.getEndpoint(), mspId));
                            continue;
                        }

                        logger.trace(format("Channel %s peer: %s discovered peer mspid group: %s, endpoint: %s, mspid: %s", channelName, serviceDiscoveryPeer, mspId, ppp.getEndpoint(), ppp.getMspid()));

                        lsdNetwork.endorsers.put(ppp.getEndpoint(), ppp);
                    }
                }
                lsdNetwork.discoveryTime = System.currentTimeMillis();

                sdNetwork = lsdNetwork;
                ret = lsdNetwork;
                break;
            } catch (Exception e) {
                logger.warn(format("Channel %s peer %s service discovery error %s", channelName, serviceDiscoveryPeer, e.getMessage()));
            }
        }

        logger.debug(format("Channel %s service discovery completed: %b", channelName, ret != null));

        return ret;
    }

    public static class SDOrderer {
        private final String mspid;
        private final Collection<byte[]> tlsCerts;
        private final Collection<byte[]> tlsIntermediateCerts;
        private final String endPoint;
        private final Properties properties;
        private final boolean tls;

        SDOrderer(String mspid, String endPoint, Collection<byte[]> tlsCerts, Collection<byte[]> tlsIntermediateCerts, Properties properties, boolean tls) {
            this.mspid = mspid;
            this.endPoint = endPoint;
            this.tlsCerts = tlsCerts;
            this.tlsIntermediateCerts = tlsIntermediateCerts;
            this.properties = properties;
            this.tls = tls;
        }

        public Collection<byte[]> getTlsIntermediateCerts() {
            return tlsIntermediateCerts;
        }

        public String getEndPoint() {
            return endPoint;
        }

        public String getMspid() {
            return mspid;
        }

        public Collection<byte[]> getTlsCerts() {
            return tlsCerts;
        }

        public Properties getProperties() {
            return properties;
        }

        public boolean isTLS() {
            return tls;
        }
    }

    Map<String, SDChaindcode> discoverEndorserEndpoints(TransactionContext transactionContext, List<List<ServiceDiscoveryChaincodeCalls>> chaincodeNames) throws ServiceDiscoveryException {
        if (null == chaincodeNames) {
            logger.warn("Discover of chaincode names was null.");
            return Collections.emptyMap();
        }
        if (chaincodeNames.isEmpty()) {
            logger.warn("Discover of chaincode names was empty.");
            return Collections.emptyMap();
        }
        if (DEBUG) {
            StringBuilder cns = new StringBuilder(1000);
            String sep = "";
            cns.append("[");
            for (List<ServiceDiscoveryChaincodeCalls> s : chaincodeNames) {

                ServiceDiscoveryChaincodeCalls n = s.get(0);
                cns.append(sep).append(n.write(s.subList(1, s.size())));
                sep = ", ";
            }
            cns.append("]");
            logger.debug(format("Channel %s doing discovery for chaincodes: %s", channelName, cns.toString()));
        }

        ArrayList<Peer> speers = new ArrayList<>(serviceDiscoveryPeers);
        Collections.shuffle(speers);
        final Map<String, SDChaindcode> ret = new HashMap<>();
        SDNetwork sdNetwork = networkDiscovery(transactionContext, false);
        ServiceDiscoveryException serviceDiscoveryException = null;

        for (Peer serviceDiscoveryPeer : speers) {
            serviceDiscoveryException = null;
            try {
                URI serviceDiscoveryPeerURI = URI.create(serviceDiscoveryPeer.getUrl());
                boolean isTLS = serviceDiscoveryPeerURI.getScheme().equals("grpcs");
                logger.trace(format("Service discovery peer %s using TLS: %b", serviceDiscoveryPeerURI.toString(), isTLS));

                logger.debug(format("Channel %s doing discovery for chaincodes on peer: %s", channelName, serviceDiscoveryPeer.toString()));

                TransactionContext ltransactionContext = transactionContext.retryTransactionSameContext();
                final byte[] clientTLSCertificateDigest = serviceDiscoveryPeer.getClientTLSCertificateDigest();

                if (null == clientTLSCertificateDigest) {
                    logger.warn(format("Channel %s peer %s requires mutual tls for service discovery.", channelName, serviceDiscoveryPeer.toString()));
                    continue;
                }

                ByteString clientIdent = ltransactionContext.getIdentity().toByteString();
                ByteString tlshash = ByteString.copyFrom(clientTLSCertificateDigest);
                Protocol.AuthInfo authentication = Protocol.AuthInfo.newBuilder().setClientIdentity(clientIdent).setClientTlsCertHash(tlshash).build();

                List<Protocol.Query> fq = new ArrayList<>(chaincodeNames.size());

                for (List<ServiceDiscoveryChaincodeCalls> chaincodeName : chaincodeNames) {
                    if (ret.containsKey(chaincodeName.get(0).getName())) {
                        continue;
                    }
                    LinkedList<Protocol.ChaincodeCall> chaincodeCalls = new LinkedList<>();
                    chaincodeName.forEach(serviceDiscoveryChaincodeCalls -> chaincodeCalls.add(serviceDiscoveryChaincodeCalls.build()));
                    List<Protocol.ChaincodeInterest> cinn = new ArrayList<>(1);
                    chaincodeName.forEach(ServiceDiscoveryChaincodeCalls::build);
                    Protocol.ChaincodeInterest cci = Protocol.ChaincodeInterest.newBuilder().addAllChaincodes(chaincodeCalls).build();
                    cinn.add(cci);
                    Protocol.ChaincodeQuery chaincodeQuery = Protocol.ChaincodeQuery.newBuilder().addAllInterests(cinn).build();

                    fq.add(Protocol.Query.newBuilder().setChannel(channelName).setCcQuery(chaincodeQuery).build());
                }

                if (fq.size() == 0) {
                    //this would be odd but lets take care of it.
                    break;
                }

                Protocol.Request request = Protocol.Request.newBuilder().addAllQueries(fq).setAuthentication(authentication).build();
                ByteString payloadBytes = request.toByteString();
                ByteString signatureBytes = ltransactionContext.signByteStrings(payloadBytes);
                Protocol.SignedRequest sr = Protocol.SignedRequest.newBuilder()
                        .setPayload(payloadBytes).setSignature(signatureBytes).build();
                if (IS_TRACE_LEVEL && null != diagnosticFileDumper) { // dump protobuf we sent
                    logger.trace(format("Service discovery channel %s %s service chaincode query sent %s", channelName, serviceDiscoveryPeer,
                            diagnosticFileDumper.createDiagnosticProtobufFile(sr.toByteArray())));
                }

                logger.debug(format("Channel %s peer %s sending chaincode query request", channelName, serviceDiscoveryPeer.toString()));
                final Protocol.Response response = serviceDiscoveryPeer.sendDiscoveryRequestAsync(sr).get(SERVICE_DISCOVERY_WAITTIME, TimeUnit.MILLISECONDS);
                if (IS_TRACE_LEVEL && null != diagnosticFileDumper) { // dump protobuf we get
                    logger.trace(format("Service discovery channel %s %s service chaincode query returned %s", channelName, serviceDiscoveryPeer,
                            diagnosticFileDumper.createDiagnosticProtobufFile(response.toByteArray())));
                }
                logger.debug(format("Channel %s peer %s completed chaincode query request", channelName, serviceDiscoveryPeer.toString()));
                serviceDiscoveryPeer.hasConnected();

                for (Protocol.QueryResult queryResult : response.getResultsList()) {
                    if (queryResult.getResultCase().getNumber() == Protocol.QueryResult.ERROR_FIELD_NUMBER) {
                        ServiceDiscoveryException discoveryException = new ServiceDiscoveryException(format("Error %s", queryResult.getError().getContent()));
                        logger.error(discoveryException.getMessage());
                        continue;
                    }

                    if (queryResult.getResultCase().getNumber() != Protocol.QueryResult.CC_QUERY_RES_FIELD_NUMBER) {
                        ServiceDiscoveryException discoveryException = new ServiceDiscoveryException(format("Error expected chaincode endorsement query but got %s : ", queryResult.getResultCase().toString()));
                        logger.error(discoveryException.getMessage());
                        continue;
                    }

                    Protocol.ChaincodeQueryResult ccQueryRes = queryResult.getCcQueryRes();
                    if (ccQueryRes.getContentList().isEmpty()) {
                        throw new ServiceDiscoveryException(format("Error %s", queryResult.getError().getContent()));
                    }

                    for (Protocol.EndorsementDescriptor es : ccQueryRes.getContentList()) {
                        final String chaincode = es.getChaincode();
                        List<SDLayout> layouts = new LinkedList<>();
                        for (Protocol.Layout layout : es.getLayoutsList()) {
                            SDLayout sdLayout = null;
                            Map<String, Integer> quantitiesByGroupMap = layout.getQuantitiesByGroupMap();
                            for (Map.Entry<String, Integer> qmap : quantitiesByGroupMap.entrySet()) {
                                final String key = qmap.getKey();
                                final int quantity = qmap.getValue();
                                if (quantity < 1) {
                                    continue;
                                }
                                Protocol.Peers peers = es.getEndorsersByGroupsMap().get(key);
                                if (peers == null || peers.getPeersCount() == 0) {
                                    continue;
                                }

                                List<SDEndorser> sdEndorsers = new LinkedList<>();

                                for (Protocol.Peer pp : peers.getPeersList()) {
                                    SDEndorser ppp = new SDEndorser(pp, null, null, asLocalhost, isTLS);
                                    final String endPoint = ppp.getEndpoint();
                                    SDEndorser nppp = sdNetwork.getEndorserByEndpoint(endPoint);
                                    if (null == nppp) {
                                        sdNetwork = networkDiscovery(transactionContext, true);
                                        if (null == sdNetwork) {
                                            throw new ServiceDiscoveryException("Failed to discover network resources.");
                                        }
                                        nppp = sdNetwork.getEndorserByEndpoint(ppp.getEndpoint());
                                        if (null == nppp) {
                                            throw new ServiceDiscoveryException(format("Failed to discover peer endpoint information %s for chaincode %s ", endPoint, chaincode));
                                        }
                                    }
                                    sdEndorsers.add(nppp);
                                }
                                if (sdLayout == null) {
                                    sdLayout = new SDLayout();
                                    layouts.add(sdLayout);
                                }
                                sdLayout.addGroup(key, quantity, sdEndorsers);
                            }
                        }
                        if (layouts.isEmpty()) {
                            logger.warn(format("Channel %s chaincode %s discovered no layouts!", channelName, chaincode));
                        } else {
                            if (DEBUG) {
                                StringBuilder sb = new StringBuilder(1000);
                                sb.append("Channel ").append(channelName)
                                        .append(" found ").append(layouts.size()).append(" layouts for chaincode: ").append(es.getChaincode());
                                sb.append(", layouts: [");

                                String sep = "";
                                for (SDLayout layout : layouts) {
                                    sb.append(sep).append(layout);
                                    sep = ", ";
                                }
                                sb.append("]");

                                logger.debug(sb.toString());
                            }
                            ret.put(es.getChaincode(), new SDChaindcode(es.getChaincode(), layouts));
                        }
                    }
                }

                if (ret.size() == chaincodeNames.size()) {
                    break; // found them all.
                }
            } catch (ServiceDiscoveryException e) {
                logger.warn(format("Service discovery error on peer %s. Error: %s", serviceDiscoveryPeer.toString(), e.getMessage()));
                serviceDiscoveryException = e;
            } catch (Exception e) {
                logger.warn(format("Service discovery error on peer %s. Error: %s", serviceDiscoveryPeer.toString(), e.getMessage()));
                serviceDiscoveryException = new ServiceDiscoveryException(e);
            }
        }

        if (null != serviceDiscoveryException) {
            throw serviceDiscoveryException;
        }
        if (ret.size() != chaincodeNames.size()) {
            logger.warn((format("Channel %s failed to find all layouts for chaincodes. Expected: %d and found: %d", channelName, chaincodeNames.size(), ret.size())));
        }

        return ret;
    }

    /**
     * Endorsement selection by layout group that has least required and block height is the highest (most up to date).
     */
    static final EndorsementSelector ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT = sdChaindcode -> {
        List<SDLayout> layouts = sdChaindcode.getLayouts();

        class LGroup { // local book keeping.
            int stillRequred;
            final Set<SDEndorser> endorsers = new HashSet<>();

            LGroup(SDGroup group) {
                endorsers.addAll(group.getEndorsers());
                this.stillRequred = group.getStillRequired();
            }

            // return true if still required
            boolean endorsed(Set<SDEndorser> endorsed) {
                for (SDEndorser sdEndorser : endorsed) {
                    if (endorsers.contains(sdEndorser)) {
                        endorsers.remove(sdEndorser);
                        stillRequred = Math.max(0, stillRequred - 1);
                    }
                }
                return stillRequred > 0;
            }
        }

        SDLayout pickedLayout = null;

        Map<SDLayout, Set<SDEndorser>> layoutEndorsers = new HashMap<>();

        // if (layouts.size() > 1) { // pick layout by least number of endorsers ..  least number of peers hit and smaller block!

        for (SDLayout sdLayout : layouts) {
            Set<LGroup> remainingGroups = new HashSet<>();
            for (SDGroup sdGroup : sdLayout.getSDLGroups()) {
                remainingGroups.add(new LGroup(sdGroup));
            }
            // These are required as there is no choice.
            Set<SDEndorser> required = new HashSet<>();
            for (LGroup lgroup : remainingGroups) {
                if (lgroup.stillRequred == lgroup.endorsers.size()) {
                    required.addAll(lgroup.endorsers);
                }
            }
            //add those that there are no choice.

            if (required.size() > 0) {
                Set<LGroup> remove = new HashSet<>(remainingGroups.size());
                for (LGroup lGroup : remainingGroups) {
                    if (!lGroup.endorsed(required)) {
                        remove.add(lGroup);
                    }
                }
                remainingGroups.removeAll(remove);
                Set<SDEndorser> sdEndorsers = layoutEndorsers.computeIfAbsent(sdLayout, k -> new HashSet<>());
                sdEndorsers.addAll(required);
            }

            if (remainingGroups.isEmpty()) { // no more groups here done for this layout.
                continue; // done with this layout there really were no choices.
            }

            //Now go through groups finding which endorsers can satisfy the most groups.

            do {
                Map<SDEndorser, Integer> matchCount = new HashMap<>();

                for (LGroup group : remainingGroups) {
                    for (SDEndorser sdEndorser : group.endorsers) {
                        Integer count = matchCount.get(sdEndorser);
                        if (count == null) {
                            matchCount.put(sdEndorser, 1);
                        } else {
                            matchCount.put(sdEndorser, ++count);
                        }
                    }
                }

                Set<SDEndorser> theMost = new HashSet<>();
                int maxMatch = 0;
                for (Map.Entry<SDEndorser, Integer> m : matchCount.entrySet()) {
                    int count = m.getValue();
                    SDEndorser sdEndorser = m.getKey();
                    if (count > maxMatch) {
                        theMost.clear();
                        theMost.add(sdEndorser);
                        maxMatch = count;
                    } else if (count == maxMatch) {
                        theMost.add(sdEndorser);
                    }
                }

                Set<SDEndorser> theVeryMost = new HashSet<>(1);
                long max = 0L;
                // Tie breaker: Pick one with greatest ledger height.
                for (SDEndorser sd : theMost) {
                    if (sd.getLedgerHeight() > max) {
                        max = sd.getLedgerHeight();
                        theVeryMost.clear();
                        theVeryMost.add(sd);
                    }

                }

                Set<LGroup> remove2 = new HashSet<>(remainingGroups.size());
                for (LGroup lGroup : remainingGroups) {
                    if (!lGroup.endorsed(theVeryMost)) {
                        remove2.add(lGroup);
                    }
                }
                Set<SDEndorser> sdEndorsers = layoutEndorsers.computeIfAbsent(sdLayout, k -> new HashSet<>());
                sdEndorsers.addAll(theVeryMost);
                remainingGroups.removeAll(remove2);
            } while (!remainingGroups.isEmpty());

            // Now pick the layout with least endorsers
        }
        //Pick layout which needs least endorsements.
        int min = Integer.MAX_VALUE;
        Set<SDLayout> theLeast = new HashSet<>();

        for (Map.Entry<SDLayout, Set<SDEndorser>> l : layoutEndorsers.entrySet()) {
            SDLayout sdLayoutK = l.getKey();
            Integer count = l.getValue().size();
            if (count < min) {
                theLeast.clear();
                theLeast.add(sdLayoutK);
                min = count;
            } else if (count == min) {
                theLeast.add(sdLayoutK);
            }
        }

        if (theLeast.size() == 1) {
            pickedLayout = theLeast.iterator().next();
        } else {
            long max = 0L;
            // Tie breaker: Pick one with greatest ledger height.
            for (SDLayout sdLayout : theLeast) {
                int height = 0;
                for (SDEndorser sdEndorser : layoutEndorsers.get(sdLayout)) {
                    height += sdEndorser.getLedgerHeight();
                }
                if (height > max) {
                    max = height;
                    pickedLayout = sdLayout;
                }
            }
        }

        final SDEndorserState sdEndorserState = new SDEndorserState();
        sdEndorserState.setPickedEndorsers(layoutEndorsers.get(pickedLayout));
        sdEndorserState.setPickedLayout(pickedLayout);

        return sdEndorserState;
    };

    public static final EndorsementSelector DEFAULT_ENDORSEMENT_SELECTION = ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;

    /**
     * Endorsement selection by random layout group and random endorsers there in.
     */
    public static final EndorsementSelector ENDORSEMENT_SELECTION_RANDOM = sdChaindcode -> {
        List<SDLayout> layouts = sdChaindcode.getLayouts();

        SDLayout pickedLayout = layouts.get(0);

        if (layouts.size() > 1) { // more than one pick a random one.
            pickedLayout = layouts.get(random.nextInt(layouts.size()));
        }

        Map<String, SDEndorser> retMap = new HashMap<>(); //hold results.

        for (SDGroup group : pickedLayout.getSDLGroups()) { // go through groups getting random required endorsers
            List<SDEndorser> endorsers = new ArrayList<>(group.getEndorsers());
            int required = group.getStillRequired(); // what's needed in that group.
            Collections.shuffle(endorsers); // randomize.
            List<SDEndorser> sdEndorsers = endorsers.subList(0, required); // pick top endorsers.
            sdEndorsers.forEach(sdEndorser -> {
                retMap.putIfAbsent(sdEndorser.getEndpoint(), sdEndorser); // put if endpoint is not in there already.
            });
        }

        final SDEndorserState sdEndorserState = new SDEndorserState(); //returned result.
        sdEndorserState.setPickedEndorsers(retMap.values());
        sdEndorserState.setPickedLayout(pickedLayout);

        return sdEndorserState;
    };

    public static class SDChaindcode {
        final String name;
        final List<SDLayout> layouts;

        SDChaindcode(SDChaindcode sdChaindcode) {
            name = sdChaindcode.name;
            layouts = new LinkedList<>();
            sdChaindcode.layouts.forEach(sdLayout -> layouts.add(new SDLayout(sdLayout)));
        }

        SDChaindcode(String name, List<SDLayout> layouts) {
            this.name = name;
            this.layouts = layouts;
        }

        public List<SDLayout> getLayouts() {
            return Collections.unmodifiableList(layouts);
        }

        // returns number of layouts left.
        int ignoreList(Collection<String> names) {
            if (names != null && !names.isEmpty()) {
                layouts.removeIf(sdLayout -> !sdLayout.ignoreList(names));
            }
            return layouts.size();
        }

        int ignoreListSDEndorser(Collection<SDEndorser> sdEndorsers) {
            if (sdEndorsers != null && !sdEndorsers.isEmpty()) {
                layouts.removeIf(sdLayout -> !sdLayout.ignoreListSDEndorser(sdEndorsers));
            }
            return layouts.size();
        }

        boolean endorsedList(Collection<SDEndorser> sdEndorsers) {
            boolean ret = false;

            for (SDLayout sdLayout : layouts) {
                if (sdLayout.endorsedList(sdEndorsers)) {
                    ret = true;
                }
            }
            return ret;
        }

        // return the set needed or null if the policy was not meet.
        Collection<SDEndorser> meetsEndorsmentPolicy(Set<SDEndorser> endpoints) {
            Collection<SDEndorser> ret = null; // not meet.

            for (SDLayout sdLayout : layouts) {
                final Collection<SDEndorser> needed = sdLayout.meetsEndorsmentPolicy(endpoints);

                if (needed != null && (ret == null || ret.size() > needed.size())) {
                    ret = needed;  // needed is less so lets go with that.
                }
            }
            return ret;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(1000);
            sb.append("SDChaindcode(name: ").append(name);
            if (null != layouts && !layouts.isEmpty()) {
                sb.append(", layouts: [");
                String sep = "";
                for (SDLayout sdLayout : layouts) {
                    sb.append(sep).append(sdLayout + "");
                    sep = " ,";
                }
                sb.append("]");
            }
            sb.append(")");
            return sb.toString();
        }
    }

    public static class SDLayout {
        final List<SDGroup> groups = new LinkedList<>();

        SDLayout() { }

        //Copy constructor
        SDLayout(SDLayout sdLayout) {
            for (SDGroup group : sdLayout.groups) {
                new SDGroup(group);
            }
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(1000);

            sb.append("SDLayout: {");

            if (!groups.isEmpty()) {
                sb.append("groups: [");
                String sep2 = "";
                for (SDGroup group : groups) {
                    sb.append(sep2).append(group.toString());
                    sep2 = ", ";
                }
                sb.append("]");
            } else {
                sb.append(", groups: []");
            }
            sb.append("}");

            return sb.toString();
        }

        //return true if the groups still exist to get endorsement.
        boolean ignoreList(Collection<String> names) {
            boolean ret = true;
            HashSet<String> bnames = new HashSet<>(names);

            for (SDGroup group : groups) {
                if (!group.ignoreList(bnames)) {
                    ret = false; // group can no longer be satisfied.
                }
            }
            return ret;
        }

        boolean ignoreListSDEndorser(Collection<SDEndorser> names) {
            boolean ret = true;
            HashSet<SDEndorser> bnames = new HashSet<>(names);

            for (SDGroup group : groups) {
                if (!group.ignoreListSDEndorser(bnames)) {
                    ret = false; // group can no longer be satisfied.
                }
            }
            return ret;
        }

        // endorsement has been meet.
        boolean endorsedList(Collection<SDEndorser> sdEndorsers) {
            int endorsementMeet = 0;
            for (SDGroup group : groups) {
                if (group.endorsedList(sdEndorsers)) {
                    ++endorsementMeet;
                }
            }
            return endorsementMeet >= groups.size();
        }

        //       Returns null when not meet and endorsers needed if it is.
        Collection<SDEndorser> meetsEndorsmentPolicy(Set<SDEndorser> endpoints) {
            Set<SDEndorser> ret = new HashSet<>();

            for (SDGroup group : groups) {
                Collection<SDEndorser> sdEndorsers = group.meetsEndorsmentPolicy(endpoints, null);
                if (null == sdEndorsers) {
                    return null; // group was not satisfied
                }
                ret.addAll(sdEndorsers); // add all these endorsers.
            }

            return ret;
        }

        public Collection<SDGroup> getSDLGroups() {
            return new ArrayList<>(groups);
        }

        public class SDGroup {
            final int required; // the number that's needed for the group to be endorsed.
            final List<SDEndorser> endorsers = new LinkedList<>();
            private final String name; // name of the groups - just for debug sake.
            private int endorsed = 0; // number that have been now endorsed.

            {
                SDLayout.this.groups.add(this);
            }

            SDGroup(String name, int required, List<SDEndorser> endorsers) {
                this.name = name;
                this.required = required;
                this.endorsers.addAll(endorsers);
            }

            SDGroup(SDGroup group) { //copy constructor
                name = group.name;
                required = group.required;
                endorsers.addAll(group.endorsers);
                endorsed = 0; // on copy reset to no endorsements
            }

            public int getStillRequired() {
                return required - endorsed;
            }

            public String getName() {
                return name;
            }

            public int getRequired() {
                return required;
            }

            public Collection<SDEndorser> getEndorsers() {
                return new ArrayList<>(endorsers);
            }

            //returns true if there are still sufficent endorsers for this group.
            boolean ignoreList(Collection<String> names) {
                HashSet<String> bnames = new HashSet<>(names);
                endorsers.removeIf(endorser -> bnames.contains(endorser.getEndpoint()));
                return endorsers.size() >= getStillRequired();
            }

            //returns true if there are still sufficent endorsers for this group.
            boolean ignoreListSDEndorser(Collection<SDEndorser> sdEndorsers) {
                HashSet<SDEndorser> bnames = new HashSet<>(sdEndorsers);
                endorsers.removeIf(bnames::contains);
                return endorsers.size() >= getStillRequired();
            }

            // retrun true if th endorsements have been meet.
            boolean endorsedList(Collection<SDEndorser> sdEndorsers) {
                //This is going to look odd so here goes: Service discovery can't guarantee the endpoint certs are valid
                // and so there may be multiple endpoints with different MSP ids. However if we have gotten an
                // endorsement from an endpoint that means it's been satisfied and can be removed.

                if (endorsed >= required) {
                    return true;
                }
                if (!sdEndorsers.isEmpty()) {
                    final Set<String> enames = new HashSet<>(sdEndorsers.size());
                    sdEndorsers.forEach(sdEndorser -> enames.add(sdEndorser.getEndpoint()));

                    endorsers.removeIf(endorser -> {
                        if (enames.contains(endorser.getEndpoint())) {
                            endorsed = Math.min(required, endorsed + 1);
                            return true; // remove it.
                        }
                        return false; // needs to stay in the list.
                    });
                }

                return endorsed >= required;
            }

            @Override
            public String toString() {
                StringBuilder sb = new StringBuilder(512);
                sb.append("SDGroup: { name: ").append(name).append(", required: ").append(required);

                if (!endorsers.isEmpty()) {
                    sb.append(", endorsers: [");
                    String sep2 = "";
                    for (SDEndorser sdEndorser : endorsers) {
                        sb.append(sep2).append(sdEndorser.toString());
                        sep2 = ", ";
                    }
                    sb.append("]");
                } else {
                    sb.append(", endorsers: []");
                }
                sb.append("}");
                return sb.toString();
            }

            // Returns
            Collection<SDEndorser> meetsEndorsmentPolicy(Set<SDEndorser> allEndorsed, Collection<SDEndorser> requiredYet) {
                Set<SDEndorser> ret = new HashSet<>(this.endorsers.size());
                for (SDEndorser hasBeenEndorsed : allEndorsed) {
                    for (SDEndorser sdEndorser : endorsers) {
                        if (hasBeenEndorsed.equals(sdEndorser)) {
                            ret.add(sdEndorser);
                            if (ret.size() >= required) {
                                return ret; // got what we needed.
                            }
                        }
                    }
                }
                if (null != requiredYet) {
                    for (SDEndorser sdEndorser : endorsers) {
                        if (!allEndorsed.contains(sdEndorser)) {
                            requiredYet.add(sdEndorser);
                        }
                    }
                }
                return null; // group has not meet endorsement.
            }
        }

        void addGroup(String key, int required, List<SDEndorser> endorsers) {
            new SDGroup(key, required, endorsers);
        }
    }

    public static class SDEndorserState {
        private Collection<SDEndorser> sdEndorsers = new ArrayList<>();
        private SDLayout pickedLayout;

        public void setPickedEndorsers(Collection<SDEndorser> sdEndorsers) {
            this.sdEndorsers = sdEndorsers;
        }

        Collection<SDEndorser> getSdEndorsers() {
            return sdEndorsers;
        }

        public void setPickedLayout(SDLayout pickedLayout) {
            this.pickedLayout = pickedLayout;
        }

        public SDLayout getPickedLayout() {
            return pickedLayout;
        }
    }

    public static class SDEndorser {
        private List<Message.Chaincode> chaincodesList;
        // private final Protocol.Peer proto;
        private String endPoint = null;
        private String name = null;
        private String mspid;
        private long ledgerHeight = -1L;
        private final Collection<byte[]> tlsCerts;
        private final Collection<byte[]> tlsIntermediateCerts;
        private final boolean asLocalhost;
        private final boolean tls;

        SDEndorser() { // for testing only
            tlsCerts = null;
            tlsIntermediateCerts = null;
            asLocalhost = false;
            tls = false;
        }

        SDEndorser(Protocol.Peer peerRet, Collection<byte[]> tlsCerts, Collection<byte[]> tlsIntermediateCerts, boolean asLocalhost, boolean tls) {
            this.tlsCerts = tlsCerts;
            this.tlsIntermediateCerts = tlsIntermediateCerts;
            this.asLocalhost = asLocalhost;
            this.tls = tls;

            parseEndpoint(peerRet);
            parseLedgerHeight(peerRet);
            parseIdentity(peerRet);
        }

        Collection<byte[]> getTLSCerts() {
            return tlsCerts;
        }

        Collection<byte[]> getTLSIntermediateCerts() {
            return tlsIntermediateCerts;
        }

        public String getName() {
            return name;
        }

        public String getEndpoint() {
            return endPoint;
        }

        public long getLedgerHeight() {
            return ledgerHeight;
        }

        private void parseIdentity(Protocol.Peer peerRet) {
            try {
                Identities.SerializedIdentity serializedIdentity = Identities.SerializedIdentity.parseFrom(peerRet.getIdentity());
                mspid = serializedIdentity.getMspid();
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
        }

        private String parseEndpoint(Protocol.Peer peerRet) throws InvalidProtocolBufferRuntimeException {
            if (null == endPoint) {
                try {
                    Message.Envelope membershipInfo = peerRet.getMembershipInfo();
                    final ByteString membershipInfoPayloadBytes = membershipInfo.getPayload();
                    final Message.GossipMessage gossipMessageMemberInfo = Message.GossipMessage.parseFrom(membershipInfoPayloadBytes);

                    if (Message.GossipMessage.ContentCase.ALIVE_MSG.getNumber() != gossipMessageMemberInfo.getContentCase().getNumber()) {
                        throw new RuntimeException(format("Error %s", "bad"));
                    }
                    Message.AliveMessage aliveMsg = gossipMessageMemberInfo.getAliveMsg();
                    name = aliveMsg.getMembership().getEndpoint();
                    if (name != null) {
                        if (asLocalhost) {
                            endPoint = "localhost" + name.substring(name.lastIndexOf(':'));
                        } else {
                            endPoint = name.toLowerCase().trim(); //makes easier on comparing.
                        }
                    }
                } catch (InvalidProtocolBufferException e) {
                    throw new InvalidProtocolBufferRuntimeException(e);
                }
            }
            return endPoint;
        }

        private long parseLedgerHeight(Protocol.Peer peerRet) throws InvalidProtocolBufferRuntimeException {
            if (-1L == ledgerHeight) {
                try {
                    Message.Envelope stateInfo = peerRet.getStateInfo();
                    final Message.GossipMessage stateInfoGossipMessage = Message.GossipMessage.parseFrom(stateInfo.getPayload());
                    Message.GossipMessage.ContentCase contentCase = stateInfoGossipMessage.getContentCase();
                    if (contentCase.getNumber() != Message.GossipMessage.ContentCase.STATE_INFO.getNumber()) {
                        throw new RuntimeException("" + contentCase.getNumber());
                    }
                    Message.StateInfo stateInfo1 = stateInfoGossipMessage.getStateInfo();
                    ledgerHeight = stateInfo1.getProperties().getLedgerHeight();

                    this.chaincodesList = stateInfo1.getProperties().getChaincodesList();
                } catch (InvalidProtocolBufferException e) {
                    throw new InvalidProtocolBufferRuntimeException(e);
                }
            }

            return ledgerHeight;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }

            if (!(obj instanceof SDEndorser)) {
                return false;
            }
            SDEndorser other = (SDEndorser) obj;
            return Objects.equals(mspid, other.getMspid()) && Objects.equals(endPoint, other.getEndpoint());
        }

        @Override
        public int hashCode() {
            return Objects.hash(mspid, endPoint);
        }

        Set<String> getChaincodeNames() {
            if (chaincodesList == null) {
                return Collections.emptySet();
            }

            HashSet<String> ret = new HashSet<>(chaincodesList.size());

            chaincodesList.forEach(chaincode -> ret.add(chaincode.getName()));
            return ret;
        }

        public String getMspid() {
            return mspid;
        }

        public boolean isTLS() {
            return this.tls;
        }

        @Override
        public String toString() {
            return "SDEndorser-" + mspid + "-" + endPoint;
        }
    }

    private static List<SDEndorser> topNbyHeight(int required, List<SDEndorser> endorsers) {
        ArrayList<SDEndorser> ret = new ArrayList<>(endorsers);
        ret.sort(Comparator.comparingLong(SDEndorser::getLedgerHeight));
        return ret.subList(Math.max(ret.size() - required, 0), ret.size());
    }

    private ScheduledFuture<?> seviceDiscovery = null;

    private static final int SERVICE_DISCOVER_FREQ_SECONDS = config.getServiceDiscoveryFreqSeconds();

    void run() {
        if (channel.isShutdown() || SERVICE_DISCOVER_FREQ_SECONDS < 1) {
            return;
        }

        if (seviceDiscovery == null) {
            seviceDiscovery = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = Executors.defaultThreadFactory().newThread(r);
                t.setDaemon(true);
                return t;
            }).scheduleAtFixedRate(() -> {
                logger.debug(format("Channel %s starting service rediscovery after %d seconds.", channelName, SERVICE_DISCOVER_FREQ_SECONDS));
                fullNetworkDiscovery(true);

            }, SERVICE_DISCOVER_FREQ_SECONDS, SERVICE_DISCOVER_FREQ_SECONDS, TimeUnit.SECONDS);
        }
    }

    SDNetwork fullNetworkDiscovery(boolean force) {
        if (channel.isShutdown()) {
            return null;
        }
        logger.trace(format("Full network discovery force: %b", force));
        try {
            SDNetwork osdNetwork = sdNetwork;
            SDNetwork lsdNetwork = networkDiscovery(transactionContext.retryTransactionSameContext(), force);
            if (channel.isShutdown() || null == lsdNetwork) {
                return null;
            }

            if (osdNetwork != lsdNetwork) { // means it changed.
                final Set<String> chaincodesNames = lsdNetwork.getChaincodesNames();
                List<List<ServiceDiscoveryChaincodeCalls>> lcc = new LinkedList<>();
                chaincodesNames.forEach(s -> {
                    List<ServiceDiscoveryChaincodeCalls> lc = new LinkedList<>();
                    lc.add(new ServiceDiscoveryChaincodeCalls(s));
                    lcc.add(lc);
                });
                chaindcodeMap = discoverEndorserEndpoints(transactionContext.retryTransactionSameContext(), lcc);
                if (channel.isShutdown()) {
                    return null;
                }

                channel.sdUpdate(lsdNetwork);
            }

            return lsdNetwork;
        } catch (Exception e) {
            logger.warn("Service discovery got error:" + e.getMessage(), e);
        } finally {
            logger.trace("Full network rediscovery completed.");
        }
        return null;
    }

    void shutdown() {
        logger.trace("Service discovery shutdown.");
        try {
            final ScheduledFuture<?> lseviceDiscovery = seviceDiscovery;
            seviceDiscovery = null;
            if (null != lseviceDiscovery) {
                lseviceDiscovery.cancel(true);
            }
        } catch (Exception e) {
            logger.error(e);
            //best effort.
        }
    }

    @Override
    protected void finalize() throws Throwable {
        shutdown();
        super.finalize();
    }

    public interface EndorsementSelector {
        SDEndorserState endorserSelector(SDChaindcode sdChaindcode);

        EndorsementSelector ENDORSEMENT_SELECTION_RANDOM = ServiceDiscovery.ENDORSEMENT_SELECTION_RANDOM;
        EndorsementSelector ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT = ServiceDiscovery.ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;
    }
}
