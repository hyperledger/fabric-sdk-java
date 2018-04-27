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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.netty.util.internal.ConcurrentSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.discovery.Protocol;
import org.hyperledger.fabric.protos.gossip.Message;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.msp.MspConfig;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.hyperledger.fabric.sdk.exception.ServiceDiscoveryException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;

import static java.lang.String.format;

class ServiceDiscovery {
    private static final Log logger = LogFactory.getLog(ServiceDiscovery.class);
    private static final Config config = Config.getConfig();
    private static final int SERVICE_DISCOVERY_WAITTIME = config.getServiceDiscoveryWaitTime();
    private static final Random random = new Random();
    private final Collection<Peer> serviceDiscoveryPeers;
    private final Channel channel;
    private final TransactionContext transactionContext;
    private final String channelName;
    private volatile Map<String, SDChaindcode> chaindcodeMap = new HashMap<>();

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
        Map<String, SDChaindcode> dchaindcodeMap = discoverEndorserEndpoints(transactionContext, Collections.singleton(name));
        final SDChaindcode sdChaindcode = dchaindcodeMap.get(name);
        if (null == sdChaindcode) {
            throw new ServiceDiscoveryException(format("Failed to find and endorsers for chaincode %s. See logs for details", name));
        }
        return sdChaindcode;
    }

    Collection<String> getDiscoveredChaincodeNames() {

        final SDNetwork lsdNetwork = fullNetworkDiscovery(false);
        if (null == lsdNetwork) {
            return Collections.EMPTY_LIST;

        }

        return new ArrayList<>(lsdNetwork.getChaincodesNames());

    }

    class SDNetwork {
        final Map<String, List<byte[]>> tlsCerts = new HashMap<>();
        final Map<String, List<byte[]>> tlsIntermCerts = new HashMap<>();
        long discoveryTime;

        void addTlsCert(String mspid, byte[] cert) {
            tlsCerts.computeIfAbsent(mspid, k -> new LinkedList<>()).add(cert);

        }

        void addTlsIntermCert(String mspid, byte[] cert) {
            tlsIntermCerts.computeIfAbsent(mspid, k -> new LinkedList<>()).add(cert);

        }

        SDEndorser getEndorserByEndpoint(String endpoint) {
            return endorsers.get(endpoint);
        }

        public Collection<SDEndorser> getEndorsers() {
            return Collections.unmodifiableCollection(endorsers.values());
        }

        Map<String, SDEndorser> endorsers = Collections.EMPTY_MAP;

        Map<String, SDOrderer> ordererEndpoints = Collections.EMPTY_MAP;

        Collection<SDOrderer> getOrdererEndpoints() {
            return ordererEndpoints.values();
        }

        Set<String> getPeerEndpoints() {

            return Collections.unmodifiableSet(endorsers.keySet());
        }

        Set<String> chaincodeNames = null;

        Set<String> getChaincodesNames() {
            if (null == chaincodeNames) {

                if (null == endorsers) {
                    chaincodeNames = Collections.EMPTY_SET;
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

        Collection<byte[]> getTlsCerts(String mspid) {
            final Collection<byte[]> bytes = tlsCerts.get(mspid);
            if (null == bytes) {
                return Collections.EMPTY_LIST;

            }
            return Collections.unmodifiableCollection(bytes);
        }

        Collection<byte[]> getTlsIntermediateCerts(String mspid) {
            final Collection<byte[]> bytes = tlsIntermCerts.get(mspid);
            if (null == bytes) {
                return Collections.EMPTY_LIST;

            }
            return Collections.unmodifiableCollection(bytes);

        }
    }

    private volatile SDNetwork sdNetwork = null;

    private final ConcurrentSet<ByteString> certs = new ConcurrentSet<>();

    SDNetwork networkDiscovery(TransactionContext ltransactionContext, boolean force) {

        ArrayList<Peer> speers = new ArrayList<>(serviceDiscoveryPeers);
        Collections.shuffle(speers);
        SDNetwork ret = sdNetwork;

        if (!force && null != ret && ret.discoveryTime + SERVICE_DISCOVER_FREQ_SECONDS * 1000 > System.currentTimeMillis()) {

            return ret;
        }
        ret = null;

        for (Peer serviceDiscoveryPeer : speers) {

            try {

                SDNetwork lsdNetwork = new SDNetwork();

                final byte[] clientTLSCertificateDigest = serviceDiscoveryPeer.getClientTLSCertificateDigest();

                logger.info(format("Doing discovery on peer: %s", serviceDiscoveryPeer));

                if (null == clientTLSCertificateDigest) {
                    throw new RuntimeException(format("Peer %s requires mutual tls for service discovery.", channelName));
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

                final Protocol.Response response = serviceDiscoveryPeer.sendDiscoveryRequestAsync(sr).get(SERVICE_DISCOVERY_WAITTIME, TimeUnit.MILLISECONDS);
                serviceDiscoveryPeer.hasConnected();
                final List<Protocol.QueryResult> resultsList = response.getResultsList();
                Protocol.QueryResult queryResult;

                queryResult = resultsList.get(0); //configquery
                if (queryResult.getResultCase().getNumber() == Protocol.QueryResult.ERROR_FIELD_NUMBER) {
                    throw new RuntimeException(format("Error %s", queryResult.getError().getContent()));
                }
                Protocol.ConfigResult configResult = queryResult.getConfigResult();

                Map<String, MspConfig.FabricMSPConfig> msps = configResult.getMspsMap();
                Set<ByteString> cbbs = new HashSet<>(msps.size() * 4);

                for (Map.Entry<String, MspConfig.FabricMSPConfig> i : msps.entrySet()) {
                    final MspConfig.FabricMSPConfig value = i.getValue();
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
                    String mspid = i.getKey();

                    Protocol.Endpoints value = i.getValue();
                    for (Protocol.Endpoint l : value.getEndpointList()) {
                        String endpoint = remapEndpoint((l.getHost() + ":" + l.getPort()).trim().toLowerCase());

                        final SDOrderer sdOrderer = new SDOrderer(mspid, endpoint, lsdNetwork.getTlsCerts(mspid), lsdNetwork.getTlsIntermediateCerts(mspid));

                        ordererEndpoints.put(sdOrderer.getEndPoint(), sdOrderer);
                    }
                }
                lsdNetwork.ordererEndpoints = ordererEndpoints;

                queryResult = resultsList.get(1);
                if (queryResult.getResultCase().getNumber() == Protocol.QueryResult.ERROR_FIELD_NUMBER) {
                    throw new RuntimeException(format("Error %s", queryResult.getError().getContent()));

                }

                Protocol.PeerMembershipResult membership = queryResult.getMembers();

                lsdNetwork.endorsers = new HashMap<>();

                for (Map.Entry<String, Protocol.Peers> peerses : membership.getPeersByOrgMap().entrySet()) {
                    String mspId = peerses.getKey();
                    Protocol.Peers peers = peerses.getValue();

                    for (Protocol.Peer pp : peers.getPeersList()) {
                        SDEndorser ppp = new SDEndorser(pp, lsdNetwork.getTlsCerts(mspId), lsdNetwork.getTlsIntermediateCerts(mspId));
                        lsdNetwork.endorsers.put(ppp.getEndpoint(), ppp);

                    }
                }
                lsdNetwork.discoveryTime = System.currentTimeMillis();

                sdNetwork = lsdNetwork;
                ret = lsdNetwork;
                break;

            } catch (Exception e) {
                logger.error(e);

            }
        }

        return ret;

    }

    public static class SDOrderer {

        private final String mspid;
        private final Collection<byte[]> tlsCerts;
        private final Collection<byte[]> tlsIntermediateCerts;
        private final String endPoint;

        SDOrderer(String mspid, String endPoint, Collection<byte[]> tlsCerts, Collection<byte[]> tlsIntermediateCerts) {
            this.mspid = mspid;
            this.endPoint = endPoint;
            this.tlsCerts = tlsCerts;
            this.tlsIntermediateCerts = tlsIntermediateCerts;
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
    }

    Map<String, SDChaindcode> discoverEndorserEndpoints(TransactionContext transactionContext, Set<String> chaincodeNames) throws ServiceDiscoveryException {

        ArrayList<Peer> speers = new ArrayList<>(serviceDiscoveryPeers);
        Collections.shuffle(speers);
        final Map<String, SDChaindcode> ret = new HashMap<>();
        SDNetwork sdNetwork = networkDiscovery(transactionContext, false);
        ServiceDiscoveryException serviceDiscoveryException = null;

        for (Peer serviceDiscoveryPeer : speers) {
            serviceDiscoveryException = null;
            try {

                TransactionContext ltransactionContext = transactionContext.retryTransactionSameContext();

                final byte[] clientTLSCertificateDigest = serviceDiscoveryPeer.getClientTLSCertificateDigest();

                if (null == clientTLSCertificateDigest) {
                    throw new RuntimeException(format("Peer %s requires mutual tls for service discovery.", serviceDiscoveryPeer));
                }

                ByteString clientIdent = ltransactionContext.getIdentity().toByteString();
                ByteString tlshash = ByteString.copyFrom(clientTLSCertificateDigest);
                Protocol.AuthInfo authentication = Protocol.AuthInfo.newBuilder().setClientIdentity(clientIdent).setClientTlsCertHash(tlshash).build();

                List<Protocol.Query> fq = new ArrayList<>(chaincodeNames.size());

                for (String chaincodeName : chaincodeNames) {
                    if (ret.containsKey(chaincodeName)) {
                        continue;
                    }
                    List<Protocol.ChaincodeInterest> cinn = new ArrayList<>(1);
                    Protocol.ChaincodeCall.newBuilder().setName(chaincodeName).build();
                    Protocol.ChaincodeInterest cci = Protocol.ChaincodeInterest.newBuilder().addChaincodes(Protocol.ChaincodeCall.newBuilder().setName(chaincodeName).build()).build();
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

                final Protocol.Response response = serviceDiscoveryPeer.sendDiscoveryRequestAsync(sr).get(SERVICE_DISCOVERY_WAITTIME, TimeUnit.MILLISECONDS);
                serviceDiscoveryPeer.hasConnected();
                final List<Protocol.QueryResult> resultsList = response.getResultsList();

                for (Protocol.QueryResult queryResult : response.getResultsList()) {

                    if (queryResult.getResultCase().getNumber() == Protocol.QueryResult.ERROR_FIELD_NUMBER) {
                        throw new ServiceDiscoveryException(format("Error %s", queryResult.getError().getContent()));
                    }

                    if (queryResult.getResultCase().getNumber() != Protocol.QueryResult.CC_QUERY_RES_FIELD_NUMBER) {
                        throw new ServiceDiscoveryException(format("Error expected chaincode endorsement query but go:t %s : ", queryResult.getResultCase().toString()));
                    }

                    Protocol.ChaincodeQueryResult ccQueryRes = queryResult.getCcQueryRes();
                    if (ccQueryRes.getContentList().isEmpty()) {
                        throw new ServiceDiscoveryException(format("Error %s", queryResult.getError().getContent()));
                    }

                    for (Protocol.EndorsementDescriptor es : ccQueryRes.getContentList()) {
                        final String chaincode = es.getChaincode();
                        List<SDLayout> layouts = new LinkedList<>();
                        for (Protocol.Layout layout : es.getLayoutsList()) {
                            Map<String, Integer> quantitiesByGroupMap = layout.getQuantitiesByGroupMap();
                            for (Map.Entry<String, Integer> qmap : quantitiesByGroupMap.entrySet()) {
                                final String key = qmap.getKey();
                                final int quantity = qmap.getValue();
                                Protocol.Peers peers = es.getEndorsersByGroupsMap().get(key);

                                List<SDEndorser> sdEndorsers = new LinkedList<>();

                                for (Protocol.Peer pp : peers.getPeersList()) {

                                    SDEndorser ppp = new SDEndorser(pp, null, null);
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
                                layouts.add(new SDLayout(quantity, sdEndorsers));
                            }
                        }
                        ret.put(es.getChaincode(), new SDChaindcode(es.getChaincode(), layouts));
                    }

                }

                if (ret.size() == chaincodeNames.size()) {
                    break; // found them all.
                }

            } catch (ServiceDiscoveryException e) {
                logger.warn(format("Service discovery error on peer %s. Error: %s", serviceDiscoveryPeer, e.getMessage()));
                serviceDiscoveryException = e;
            } catch (Exception e) {
                logger.warn(format("Service discovery error on peer %s. Error: %s", serviceDiscoveryPeer, e.getMessage()));
                serviceDiscoveryException = new ServiceDiscoveryException(e);
            }
        }

        if (null != serviceDiscoveryException) {
            throw serviceDiscoveryException;
        }

        return ret;

    }

    /**
     * Endorsement selection by layout group that has least required and block height is the highest (most up to date).
     */

    static final EndorsementSelector ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT = sdChaindcode -> {
        List<SDLayout> layouts = sdChaindcode.getLayouts();

        SDLayout pickedLayout = layouts.get(0);

        if (layouts.size() > 1) { // pick layout by least number of endorsers ..  least number of peers hit and smaller block!

            ArrayList<SDLayout> leastEndorsers = new ArrayList<>();
            for (SDLayout sdLayout : layouts) {

                if (leastEndorsers.size() == 0 || leastEndorsers.get(0).getStillRequired() > sdLayout.getStillRequired()) {
                    leastEndorsers = new ArrayList<>();
                    leastEndorsers.add(sdLayout);
                } else if (leastEndorsers.get(0).getStillRequired() == sdLayout.getStillRequired()) {
                    leastEndorsers.add(sdLayout);

                }
            }
            if (leastEndorsers.size() == 1) {
                pickedLayout = leastEndorsers.get(0);
            } else {
                long maxHeight = -1L; // go with the highest total block height of the required.

                for (SDLayout layout : leastEndorsers) { // means required was the same.
                    List<SDEndorser> sdEndorsers = topNbyHeight(layout.getStillRequired(), layout.getSDEndorsers());
                    long score = 0;
                    for (SDEndorser sdEndorser : sdEndorsers) {
                        score += sdEndorser.getLedgerHeight();
                    }
                    if (score > maxHeight) {
                        maxHeight = score;
                        pickedLayout = layout;
                    }
                }
            }
        }

        List<SDEndorser> top = topNbyHeight(pickedLayout.getStillRequired(), pickedLayout.getSDEndorsers());
        ArrayList<SDEndorser> retlist = new ArrayList<>(pickedLayout.getStillRequired());
        retlist.addAll(top);
        final SDEndorserState sdEndorserState = new SDEndorserState();
        sdEndorserState.setPickedEndorsers(retlist);
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

        if (layouts.size() > 1) {
            pickedLayout = layouts.get(random.nextInt(layouts.size()));
        }

        List<SDEndorser> pickedEndorsers = pickedLayout.getSDEndorsers();
        final int required = pickedLayout.getStillRequired();

        if (required != pickedEndorsers.size()) {
            List<SDEndorser> shuffle = new ArrayList<>(pickedEndorsers);
            Collections.shuffle(shuffle);
            pickedEndorsers = shuffle.subList(0, required);
        }
        List<SDEndorser> retlist = new ArrayList<>(required);
        retlist.addAll(pickedEndorsers);

        final SDEndorserState sdEndorserState = new SDEndorserState();
        sdEndorserState.setPickedEndorsers(retlist);
        sdEndorserState.setPickedLayout(pickedLayout);

        return sdEndorserState;
    };

    static class SDChaindcode {
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

        List<SDLayout> getLayouts() {
            return layouts;
        }

        int ignoreList(Collection<String> names) {
            layouts.removeIf(sdLayout -> !sdLayout.ignoreList(names));
            return layouts.size();
        }

        void endorsedList(Collection<String> names) {
            for (SDLayout sdLayout : layouts) {
                sdLayout.endorsedList(names);
            }
        }

        // return the set
        Set<String> meetsEndorsmentPolicy(Set<String> endpoints) {

            Set<String> ret = null;

            for (SDLayout sdLayout : layouts) {
                final Set<String> needed = sdLayout.meetsEndorsmentPolicy(endpoints);
                if (needed != null && (ret == null || ret.size() > needed.size())) {
                    ret = needed;
                }
            }
            return ret;
        }
    }

    public static class SDLayout {

        final List<SDEndorser> sdEndorsers;
        final int required;
        int endorsed = 0;

        SDLayout(int quantity, List<SDEndorser> protocolPeers) {
            required = quantity;
            this.sdEndorsers = protocolPeers;
        }

        SDLayout(SDLayout sdLayout) {
            required = sdLayout.required;
            this.sdEndorsers = new LinkedList<>(sdLayout.sdEndorsers);
            endorsed = 0;
        }

        public int getRequired() {
            return required;
        }

        List<SDEndorser> getSDEndorsers() {
            return sdEndorsers;
        }

        int getStillRequired() {
            return required - endorsed;
        }

        boolean ignoreList(Collection<String> names) {
            HashSet<String> bnames = new HashSet<>(names);
            for (Iterator<SDEndorser> i = sdEndorsers.iterator(); i.hasNext();
                    ) { //checkstyle oddity.
                final SDEndorser endorser = i.next();
                if (bnames.contains(endorser.getEndpoint())) {
                    i.remove();
                    if (sdEndorsers.size() < getStillRequired()) {
                        return false; // not enough endorsers
                    }
                }
            }
            return true;
        }

        boolean endorsedList(Collection<String> names) {
            HashSet<String> bnames = new HashSet<>(names);
            for (Iterator<SDEndorser> i = sdEndorsers.iterator(); i.hasNext();
                    ) { //checkstyle oddity.
                final SDEndorser endorser = i.next();
                if (bnames.contains(endorser.getEndpoint())) {
                    i.remove();
                    ++endorsed;
                }
            }

            return true;
        }

        Set<String> meetsEndorsmentPolicy(Set<String> endpoints) {
            Set<String> needed = new HashSet<>();
            for (SDEndorser sdEndorser : sdEndorsers) {
                if (endpoints.contains(sdEndorser.getEndpoint())) {
                    needed.add(sdEndorser.getEndpoint());
                    if (needed.size() >= required) {
                        return needed;
                    }
                }

            }

            return null;
        }
    }

    public static class SDEndorserState {

        Collection<SDEndorser> sdEndorsers = new ArrayList<>();
        private SDLayout pickedLayout;

        void setPickedEndorsers(Collection<SDEndorser> sdEndorsers) {
            this.sdEndorsers = sdEndorsers;

        }

        Collection<SDEndorser> getSdEndorsers() {
            return sdEndorsers;
        }

        void setPickedLayout(SDLayout pickedLayout) {
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
        private String mspid;
        private long ledgerHeight = -1L;
        private final Collection<byte[]> tlsCerts;
        private final Collection<byte[]> tlsIntermediateCerts;

        SDEndorser(Protocol.Peer peerRet, Collection<byte[]> tlsCerts, Collection<byte[]> tlsIntermediateCerts) {
            this.tlsCerts = tlsCerts;
            this.tlsIntermediateCerts = tlsIntermediateCerts;

            parseEndpoint(peerRet);
            parseLedgerHeight(peerRet);
            parseIdentity(peerRet);
        }

        public Collection<byte[]> getTLSCerts() {
            return tlsCerts;
        }

        public Collection<byte[]> getTLSIntermediateCerts() {
            return tlsIntermediateCerts;
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

        String parseEndpoint(Protocol.Peer peerRet) throws InvalidProtocolBufferRuntimeException {

            if (null == endPoint) {
                try {
                    Message.Envelope membershipInfo = peerRet.getMembershipInfo();
                    final ByteString membershipInfoPayloadBytes = membershipInfo.getPayload();
                    final Message.GossipMessage gossipMessageMemberInfo = Message.GossipMessage.parseFrom(membershipInfoPayloadBytes);

                    if (Message.GossipMessage.ContentCase.ALIVE_MSG.getNumber() != gossipMessageMemberInfo.getContentCase().getNumber()) {
                        throw new RuntimeException(format("Error %s", "bad"));
                    }
                    Message.AliveMessage aliveMsg = gossipMessageMemberInfo.getAliveMsg();
                    endPoint = aliveMsg.getMembership().getEndpoint();
                    if (endPoint != null) {
                        endPoint = remapEndpoint(endPoint.toLowerCase().trim()); //makes easier on comparing.
                    }
                } catch (InvalidProtocolBufferException e) {
                    throw new InvalidProtocolBufferRuntimeException(e);
                }

            }
            return endPoint;

        }

        long parseLedgerHeight(Protocol.Peer peerRet) throws InvalidProtocolBufferRuntimeException {

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

        Set<String> getChaincodeNames() {
            if (chaincodesList == null) {
                return Collections.EMPTY_SET;
            }

            HashSet<String> ret = new HashSet<>(chaincodesList.size());

            chaincodesList.forEach(chaincode -> ret.add(chaincode.getName()));
            return ret;
        }

        public String getMspid() {
            return mspid;
        }

    }

    static List<SDEndorser> topNbyHeight(int required, List<SDEndorser> endorsers) {
        ArrayList<SDEndorser> ret = new ArrayList<>(endorsers);
        Collections.sort(ret, Comparator.comparingLong(SDEndorser::getLedgerHeight));
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

                fullNetworkDiscovery(true);

            }, SERVICE_DISCOVER_FREQ_SECONDS, SERVICE_DISCOVER_FREQ_SECONDS, TimeUnit.SECONDS);
        }

    }

    SDNetwork fullNetworkDiscovery(boolean force) {
        if (channel.isShutdown()) {
            return null;
        }
        try {
            SDNetwork osdNetwork = sdNetwork;
            SDNetwork lsdNetwork = networkDiscovery(transactionContext.retryTransactionSameContext(), force);
            if (channel.isShutdown() || null == lsdNetwork) {
                return null;
            }

            if (osdNetwork != lsdNetwork) { // means it changed.
                chaindcodeMap = discoverEndorserEndpoints(transactionContext.retryTransactionSameContext(), lsdNetwork.getChaincodesNames());
                if (channel.isShutdown()) {
                    return null;
                }

                channel.sdUpdate(lsdNetwork);
            }

            return lsdNetwork;

        } catch (Exception e) {
            logger.warn("Service discovery got error:" + e.getMessage(), e);
        }
        return null;
    }

    void shutdown() {
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

    static final String REMAP2HOST = System.getProperty("org.hyperledger.fabric.sdk.test.endpoint_remap_discovery_host_name");

    private static String remapEndpoint(String endpoint) {
        String ret = endpoint;

        if (REMAP2HOST != null && !REMAP2HOST.isEmpty()) {

            final String[] split = endpoint.split(":");
            final String port = split[1];

            ret = REMAP2HOST + ":" + port;

        }

        return ret;

    }
}
