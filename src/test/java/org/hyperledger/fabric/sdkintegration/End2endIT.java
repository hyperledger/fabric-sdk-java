/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric.sdkintegration;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.openssl.PEMWriter;
import org.hyperledger.fabric.protos.ledger.rwset.kvrwset.KvRwset;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.BlockchainInfo;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.ChaincodeEvent;
import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.ChannelConfiguration;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.InstallProposalRequest;
import org.hyperledger.fabric.sdk.InstantiateProposalRequest;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.SDKUtils;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionInfo;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.TxReadWriteSetInfo;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.HFCAInfo;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.Before;
import org.junit.Test;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;
import static org.hyperledger.fabric.sdk.Channel.NOfEvents.createNofEvents;
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.Channel.TransactionOptions.createTransactionOptions;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.testRemovingAddingPeersOrderers;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test end to end scenario
 */
public class End2endIT {

    private static final TestConfig testConfig = TestConfig.getConfig();
    static final String TEST_ADMIN_NAME = "admin";
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";

    private static Random random = new Random();

    private static final String FOO_CHANNEL_NAME = "foo";
    private static final String BAR_CHANNEL_NAME = "bar";

    private static final int DEPLOYWAITTIME = testConfig.getDeployWaitTime();

    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;

    String testName = "End2endIT";

    String CHAIN_CODE_FILEPATH = "sdkintegration/gocc/sample1";
    String CHAIN_CODE_NAME = "example_cc_go";
    String CHAIN_CODE_PATH = "github.com/example_cc";
    String CHAIN_CODE_VERSION = "1";
    Type CHAIN_CODE_LANG = Type.GO_LANG;

    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

    private final TestConfigHelper configHelper = new TestConfigHelper();
    String testTxID = null;  // save the CC invoke TxID and use in queries
    SampleStore sampleStore = null;
    private Collection<SampleOrg> testSampleOrgs;
    static String testUser1 = "user1";

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }
    //CHECKSTYLE.ON: Method length is 320 lines (max allowed is 150).

    static String printableString(final String string) {
        int maxLogStringLength = 64;
        if (string == null || string.length() == 0) {
            return string;
        }

        String ret = string.replaceAll("[^\\p{Print}]", "?");

        ret = ret.substring(0, Math.min(ret.length(), maxLogStringLength)) + (ret.length() > maxLogStringLength ? "..." : "");

        return ret;

    }

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, MalformedURLException, org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException {
        out("\n\n\nRUNNING: %s.\n", testName);
        //   configHelper.clearConfig();
        //   assertEquals(256, Config.getConfig().getSecurityLevel());
        resetConfig();
        configHelper.customizeConfig();

        testSampleOrgs = testConfig.getIntegrationTestsSampleOrgs();
        //Set up hfca for each sample org

        for (SampleOrg sampleOrg : testSampleOrgs) {
            String caName = sampleOrg.getCAName(); //Try one of each name and no name.
            if (caName != null && !caName.isEmpty()) {
                sampleOrg.setCAClient(HFCAClient.createNewInstance(caName, sampleOrg.getCALocation(), sampleOrg.getCAProperties()));
            } else {
                sampleOrg.setCAClient(HFCAClient.createNewInstance(sampleOrg.getCALocation(), sampleOrg.getCAProperties()));
            }
        }
    }

    Map<String, Properties> clientTLSProperties = new HashMap<>();

    File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");

    @Test
    public void setup() throws Exception {
        //Persistence is not part of SDK. Sample file store is for demonstration purposes only!
        //   MUST be replaced with more robust application implementation  (Database, LDAP)

        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        sampleStore = new SampleStore(sampleStoreFile);
        enrollUsersSetup(sampleStore); //This enrolls users with fabric ca and setups sample store to get users later.
        runFabricTest(sampleStore); //Runs Fabric tests with constructing channels, joining peers, exercising chaincode

    }

    public void runFabricTest(final SampleStore sampleStore) throws Exception {

        ////////////////////////////
        // Setup client

        //Create instance of client.
        HFClient client = HFClient.createNewInstance();

        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        ////////////////////////////
        //Construct and run the channels
        SampleOrg sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
        Channel fooChannel = constructChannel(FOO_CHANNEL_NAME, client, sampleOrg);
        sampleStore.saveChannel(fooChannel);
        runChannel(client, fooChannel, true, sampleOrg, 0);

        assertFalse(fooChannel.isShutdown());
        fooChannel.shutdown(true); // Force foo channel to shutdown clean up resources.
        assertTrue(fooChannel.isShutdown());

        assertNull(client.getChannel(FOO_CHANNEL_NAME));
        out("\n");

        sampleOrg = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
        Channel barChannel = constructChannel(BAR_CHANNEL_NAME, client, sampleOrg);
        assertTrue(barChannel.isInitialized());
        /**
         * sampleStore.saveChannel uses {@link Channel#serializeChannel()}
         */
        sampleStore.saveChannel(barChannel);
        assertFalse(barChannel.isShutdown());
        runChannel(client, barChannel, true, sampleOrg, 100); //run a newly constructed bar channel with different b value!
        //let bar channel just shutdown so we have both scenarios.

        out("\nTraverse the blocks for chain %s ", barChannel.getName());

        blockWalker(client, barChannel);

        assertFalse(barChannel.isShutdown());
        assertTrue(barChannel.isInitialized());
        out("That's all folks!");
    }

    /**
     * Will register and enroll users persisting them to samplestore.
     *
     * @param sampleStore
     * @throws Exception
     */
    public void enrollUsersSetup(SampleStore sampleStore) throws Exception {
        ////////////////////////////
        //Set up USERS

        //SampleUser can be any implementation that implements org.hyperledger.fabric.sdk.User Interface

        ////////////////////////////
        // get users for all orgs

        out("***** Enrolling Users *****");
        for (SampleOrg sampleOrg : testSampleOrgs) {

            HFCAClient ca = sampleOrg.getCAClient();

            final String orgName = sampleOrg.getName();
            final String mspid = sampleOrg.getMSPID();
            ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            if (testConfig.isRunningFabricTLS()) {
                //This shows how to get a client TLS certificate from Fabric CA
                // we will use one client TLS certificate for orderer peers etc.
                final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
                enrollmentRequestTLS.addHost("localhost");
                enrollmentRequestTLS.setProfile("tls");
                final Enrollment enroll = ca.enroll("admin", "adminpw", enrollmentRequestTLS);
                final String tlsCertPEM = enroll.getCert();
                final String tlsKeyPEM = getPEMStringFromPrivateKey(enroll.getKey());

                final Properties tlsProperties = new Properties();

                tlsProperties.put("clientKeyBytes", tlsKeyPEM.getBytes(UTF_8));
                tlsProperties.put("clientCertBytes", tlsCertPEM.getBytes(UTF_8));
                clientTLSProperties.put(sampleOrg.getName(), tlsProperties);
                //Save in samplestore for follow on tests.
                sampleStore.storeClientPEMTLCertificate(sampleOrg, tlsCertPEM);
                sampleStore.storeClientPEMTLSKey(sampleOrg, tlsKeyPEM);
            }

            HFCAInfo info = ca.info(); //just check if we connect at all.
            assertNotNull(info);
            String infoName = info.getCAName();
            if (infoName != null && !infoName.isEmpty()) {
                assertEquals(ca.getCAName(), infoName);
            }

            SampleUser admin = sampleStore.getMember(TEST_ADMIN_NAME, orgName);
            if (!admin.isEnrolled()) {  //Preregistered admin only needs to be enrolled with Fabric caClient.
                admin.setEnrollment(ca.enroll(admin.getName(), "adminpw"));
                admin.setMspId(mspid);
            }

            SampleUser user = sampleStore.getMember(testUser1, sampleOrg.getName());
            if (!user.isRegistered()) {  // users need to be registered AND enrolled
                RegistrationRequest rr = new RegistrationRequest(user.getName(), "org1.department1");
                user.setEnrollmentSecret(ca.register(rr, admin));
            }
            if (!user.isEnrolled()) {
                user.setEnrollment(ca.enroll(user.getName(), user.getEnrollmentSecret()));
                user.setMspId(mspid);
            }

            final String sampleOrgName = sampleOrg.getName();
            final String sampleOrgDomainName = sampleOrg.getDomainName();

            SampleUser peerOrgAdmin = sampleStore.getMember(sampleOrgName + "Admin", sampleOrgName, sampleOrg.getMSPID(),
                    Util.findFileSk(Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/",
                            sampleOrgDomainName, format("/users/Admin@%s/msp/keystore", sampleOrgDomainName)).toFile()),
                    Paths.get(testConfig.getTestChannelPath(), "crypto-config/peerOrganizations/", sampleOrgDomainName,
                            format("/users/Admin@%s/msp/signcerts/Admin@%s-cert.pem", sampleOrgDomainName, sampleOrgDomainName)).toFile());
            sampleOrg.setPeerAdmin(peerOrgAdmin); //A special user that can create channels, join peers and install chaincode

            sampleOrg.addUser(user);
            sampleOrg.setAdmin(admin); // The admin of this org --
        }
    }

    static String getPEMStringFromPrivateKey(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(pemStrWriter);

        pemWriter.writeObject(privateKey);

        pemWriter.close();

        return pemStrWriter.toString();
    }

    Map<String, Long> expectedMoveRCMap = new HashMap<>(); // map from channel name to move chaincode's return code.

    //CHECKSTYLE.OFF: Method length is 320 lines (max allowed is 150).
    void runChannel(HFClient client, Channel channel, boolean installChaincode, SampleOrg sampleOrg, int delta) {

        class ChaincodeEventCapture { //A test class to capture chaincode events
            final String handle;
            final BlockEvent blockEvent;
            final ChaincodeEvent chaincodeEvent;

            ChaincodeEventCapture(String handle, BlockEvent blockEvent, ChaincodeEvent chaincodeEvent) {
                this.handle = handle;
                this.blockEvent = blockEvent;
                this.chaincodeEvent = chaincodeEvent;
            }
        }

        // The following is just a test to see if peers and orderers can be added and removed.
        // not pertinent to the code flow.
        testRemovingAddingPeersOrderers(client, channel);

        Vector<ChaincodeEventCapture> chaincodeEvents = new Vector<>(); // Test list to capture chaincode events.

        try {

            final String channelName = channel.getName();
            boolean isFooChain = FOO_CHANNEL_NAME.equals(channelName);
            out("Running channel %s", channelName);

            Collection<Orderer> orderers = channel.getOrderers();
            final ChaincodeID chaincodeID;
            Collection<ProposalResponse> responses;
            Collection<ProposalResponse> successful = new LinkedList<>();
            Collection<ProposalResponse> failed = new LinkedList<>();

            // Register a chaincode event listener that will trigger for any chaincode id and only for EXPECTED_EVENT_NAME event.

            String chaincodeEventListenerHandle = channel.registerChaincodeEventListener(Pattern.compile(".*"),
                    Pattern.compile(Pattern.quote(EXPECTED_EVENT_NAME)),
                    (handle, blockEvent, chaincodeEvent) -> {

                        chaincodeEvents.add(new ChaincodeEventCapture(handle, blockEvent, chaincodeEvent));

                        String es = blockEvent.getPeer() != null ? blockEvent.getPeer().getName() : "peer was null!!!";
                        out("RECEIVED Chaincode event with handle: %s, chaincode Id: %s, chaincode event name: %s, "
                                        + "transaction id: %s, event payload: \"%s\", from event source: %s",
                                handle, chaincodeEvent.getChaincodeId(),
                                chaincodeEvent.getEventName(),
                                chaincodeEvent.getTxId(),
                                new String(chaincodeEvent.getPayload()), es);

                    });

            //For non foo channel unregister event listener to test events are not called.
            if (!isFooChain) {
                channel.unregisterChaincodeEventListener(chaincodeEventListenerHandle);
                chaincodeEventListenerHandle = null;

            }

            ChaincodeID.Builder chaincodeIDBuilder = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
                    .setVersion(CHAIN_CODE_VERSION);
            if (null != CHAIN_CODE_PATH) {
                chaincodeIDBuilder.setPath(CHAIN_CODE_PATH);

            }
            chaincodeID = chaincodeIDBuilder.build();

            if (installChaincode) {
                ////////////////////////////
                // Install Proposal Request
                //

                client.setUserContext(sampleOrg.getPeerAdmin());

                out("Creating install proposal");

                InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
                installProposalRequest.setChaincodeID(chaincodeID);

                if (isFooChain) {
                    // on foo chain install from directory.

                    ////For GO language and serving just a single user, chaincodeSource is mostly likely the users GOPATH
                    installProposalRequest.setChaincodeSourceLocation(Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile());

                    if (testConfig.isFabricVersionAtOrAfter("1.1")) { // Fabric 1.1 added support for  META-INF in the chaincode image.

                        //This sets an index on the variable a in the chaincode // see http://hyperledger-fabric.readthedocs.io/en/master/couchdb_as_state_database.html#using-couchdb-from-chaincode
                        // The file IndexA.json as part of the META-INF will be packaged with the source to create the index.
                        installProposalRequest.setChaincodeMetaInfLocation(new File("src/test/fixture/meta-infs/end2endit"));
                    }
                } else {
                    // On bar chain install from an input stream.

                    // For inputstream if indicies are desired the application needs to make sure the META-INF is provided in the stream.
                    // The SDK does not change anything in the stream.

                    if (CHAIN_CODE_LANG.equals(Type.GO_LANG)) {

                        installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                                (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH, "src", CHAIN_CODE_PATH).toFile()),
                                Paths.get("src", CHAIN_CODE_PATH).toString()));
                    } else {
                        installProposalRequest.setChaincodeInputStream(Util.generateTarGzInputStream(
                                (Paths.get(TEST_FIXTURES_PATH, CHAIN_CODE_FILEPATH).toFile()),
                                "src"));
                    }
                }

                installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);
                installProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);

                out("Sending install proposal");

                ////////////////////////////
                // only a client from the same org as the peer can issue an install request
                int numInstallProposal = 0;
                //    Set<String> orgs = orgPeers.keySet();
                //   for (SampleOrg org : testSampleOrgs) {

                Collection<Peer> peers = channel.getPeers();
                numInstallProposal = numInstallProposal + peers.size();
                responses = client.sendInstallProposal(installProposalRequest, peers);

                for (ProposalResponse response : responses) {
                    if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                        out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                        successful.add(response);
                    } else {
                        failed.add(response);
                    }
                }

                //   }
                out("Received %d install proposal responses. Successful+verified: %d . Failed: %d", numInstallProposal, successful.size(), failed.size());

                if (failed.size() > 0) {
                    ProposalResponse first = failed.iterator().next();
                    fail("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
                }
            }

            //   client.setUserContext(sampleOrg.getUser(TEST_ADMIN_NAME));
            //  final ChaincodeID chaincodeID = firstInstallProposalResponse.getChaincodeID();
            // Note installing chaincode does not require transaction no need to
            // send to Orderers

            ///////////////
            //// Instantiate chaincode.
            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setProposalWaitTime(DEPLOYWAITTIME);
            instantiateProposalRequest.setChaincodeID(chaincodeID);
            instantiateProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
            instantiateProposalRequest.setFcn("init");
            instantiateProposalRequest.setArgs(new String[] {"a", "500", "b", "" + (200 + delta)});
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);

            /*
              policy OR(Org1MSP.member, Org2MSP.member) meaning 1 signature from someone in either Org1 or Org2
              See README.md Chaincode endorsement policies section for more details.
            */
            ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
            chaincodeEndorsementPolicy.fromYamlFile(new File(TEST_FIXTURES_PATH + "/sdkintegration/chaincodeendorsementpolicy.yaml"));
            instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);

            out("Sending instantiateProposalRequest to all peers with arguments: a and b set to 100 and %s respectively", "" + (200 + delta));
            successful.clear();
            failed.clear();

            if (isFooChain) {  //Send responses both ways with specifying peers and by using those on the channel.
                responses = channel.sendInstantiationProposal(instantiateProposalRequest, channel.getPeers());
            } else {
                responses = channel.sendInstantiationProposal(instantiateProposalRequest);
            }
            for (ProposalResponse response : responses) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);
                    out("Succesful instantiate proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                } else {
                    failed.add(response);
                }
            }
            out("Received %d instantiate proposal responses. Successful+verified: %d . Failed: %d", responses.size(), successful.size(), failed.size());
            if (failed.size() > 0) {
                for (ProposalResponse fail : failed) {

                    out("Not enough endorsers for instantiate :" + successful.size() + "endorser failed with " + fail.getMessage() + ", on peer" + fail.getPeer());

                }
                ProposalResponse first = failed.iterator().next();
                fail("Not enough endorsers for instantiate :" + successful.size() + "endorser failed with " + first.getMessage() + ". Was verified:" + first.isVerified());
            }
            ///////////////
            /// Send instantiate transaction to orderer
            out("Sending instantiateTransaction to orderer with a and b set to 100 and %s respectively", "" + (200 + delta));

            //Specify what events should complete the interest in this transaction. This is the default
            // for all to complete. It's possible to specify many different combinations like
            //any from a group, all from one group and just one from another or even None(NOfEvents.createNoEvents).
            // See. Channel.NOfEvents
            Channel.NOfEvents nOfEvents = createNofEvents();
            if (!channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty()) {
                nOfEvents.addPeers(channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)));
            }

            channel.sendTransaction(successful, createTransactionOptions() //Basically the default options but shows it's usage.
                    .userContext(client.getUserContext()) //could be a different user context. this is the default.
                    .shuffleOrders(false) // don't shuffle any orderers the default is true.
                    .orderers(channel.getOrderers()) // specify the orderers we want to try this transaction. Fails once all Orderers are tried.
                    .nOfEvents(nOfEvents) // The events to signal the completion of the interest in the transaction
            ).thenApply(transactionEvent -> {

                waitOnFabric(0);

                assertTrue(transactionEvent.isValid()); // must be valid to be here.

                assertNotNull(transactionEvent.getSignature()); //musth have a signature.
                BlockEvent blockEvent = transactionEvent.getBlockEvent(); // This is the blockevent that has this transaction.
                assertNotNull(blockEvent.getBlock()); // Make sure the RAW Fabric block is returned.

                out("Finished instantiate transaction with transaction id %s", transactionEvent.getTransactionID());

                try {
                    assertEquals(blockEvent.getChannelId(), channel.getName());
                    successful.clear();
                    failed.clear();

                    client.setUserContext(sampleOrg.getUser(testUser1));

                    ///////////////
                    /// Send transaction proposal to all peers
                    TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
                    transactionProposalRequest.setChaincodeID(chaincodeID);
                    transactionProposalRequest.setChaincodeLanguage(CHAIN_CODE_LANG);
                    //transactionProposalRequest.setFcn("invoke");
                    transactionProposalRequest.setFcn("move");
                    transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
                    transactionProposalRequest.setArgs("a", "b", "100");

                    Map<String, byte[]> tm2 = new HashMap<>();
                    tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8)); //Just some extra junk in transient map
                    tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8)); // ditto
                    tm2.put("result", ":)".getBytes(UTF_8));  // This should be returned in the payload see chaincode why.
                    if (Type.GO_LANG.equals(CHAIN_CODE_LANG) && testConfig.isFabricVersionAtOrAfter("1.2")) {

                        expectedMoveRCMap.put(channelName, random.nextInt(300) + 100L); // the chaincode will return this as status see chaincode why.
                        tm2.put("rc", (expectedMoveRCMap.get(channelName) + "").getBytes(UTF_8));  // This should be returned see chaincode why.
                        // 400 and above results in the peer not endorsing!
                    } else {
                        expectedMoveRCMap.put(channelName, 200L); // not really supported for Java or Node.
                    }

                    tm2.put(EXPECTED_EVENT_NAME, EXPECTED_EVENT_DATA);  //This should trigger an event see chaincode why.

                    transactionProposalRequest.setTransientMap(tm2);

                    out("sending transactionProposal to all peers with arguments: move(a,b,100)");

                    //  Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposalToEndorsers(transactionProposalRequest);
                    Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposal(transactionProposalRequest, channel.getPeers());
                    for (ProposalResponse response : transactionPropResp) {
                        if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                            out("Successful transaction proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                            successful.add(response);
                        } else {
                            failed.add(response);
                        }
                    }

                    out("Received %d transaction proposal responses. Successful+verified: %d . Failed: %d",
                            transactionPropResp.size(), successful.size(), failed.size());
                    if (failed.size() > 0) {
                        ProposalResponse firstTransactionProposalResponse = failed.iterator().next();
                        fail("Not enough endorsers for invoke(move a,b,100):" + failed.size() + " endorser error: " +
                                firstTransactionProposalResponse.getMessage() +
                                ". Was verified: " + firstTransactionProposalResponse.isVerified());
                    }

                    // Check that all the proposals are consistent with each other. We should have only one set
                    // where all the proposals above are consistent. Note the when sending to Orderer this is done automatically.
                    //  Shown here as an example that applications can invoke and select.
                    // See org.hyperledger.fabric.sdk.proposal.consistency_validation config property.
                    Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionPropResp);
                    if (proposalConsistencySets.size() != 1) {
                        fail(format("Expected only one set of consistent proposal responses but got %d", proposalConsistencySets.size()));
                    }
                    out("Successfully received transaction proposal responses.");

                    //  System.exit(10);

                    ProposalResponse resp = successful.iterator().next();
                    byte[] x = resp.getChaincodeActionResponsePayload(); // This is the data returned by the chaincode.
                    String resultAsString = null;
                    if (x != null) {
                        resultAsString = new String(x, UTF_8);
                    }
                    assertEquals(":)", resultAsString);

                    assertEquals(expectedMoveRCMap.get(channelName).longValue(), resp.getChaincodeActionResponseStatus()); //Chaincode's status.

                    TxReadWriteSetInfo readWriteSetInfo = resp.getChaincodeActionResponseReadWriteSetInfo();
                    //See blockwalker below how to transverse this
                    assertNotNull(readWriteSetInfo);
                    assertTrue(readWriteSetInfo.getNsRwsetCount() > 0);

                    ChaincodeID cid = resp.getChaincodeID();
                    assertNotNull(cid);
                    final String path = cid.getPath();
                    if (null == CHAIN_CODE_PATH) {
                        assertTrue(path == null || "".equals(path));

                    } else {

                        assertEquals(CHAIN_CODE_PATH, path);

                    }

                    assertEquals(CHAIN_CODE_NAME, cid.getName());
                    assertEquals(CHAIN_CODE_VERSION, cid.getVersion());

                    ////////////////////////////
                    // Send Transaction Transaction to orderer
                    out("Sending chaincode transaction(move a,b,100) to orderer.");
                    return channel.sendTransaction(successful).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

                } catch (Exception e) {
                    out("Caught an exception while invoking chaincode");
                    e.printStackTrace();
                    fail("Failed invoking chaincode with error : " + e.getMessage());
                }

                return null;

            }).thenApply(transactionEvent -> {
                try {

                    waitOnFabric(0);

                    assertTrue(transactionEvent.isValid()); // must be valid to be here.
                    out("Finished transaction with transaction id %s", transactionEvent.getTransactionID());
                    testTxID = transactionEvent.getTransactionID(); // used in the channel queries later

                    ////////////////////////////
                    // Send Query Proposal to all peers
                    //
                    String expect = "" + (300 + delta);
                    out("Now query chaincode for the value of b.");
                    QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
                    queryByChaincodeRequest.setArgs(new String[] {"b"});
                    queryByChaincodeRequest.setFcn("query");
                    queryByChaincodeRequest.setChaincodeID(chaincodeID);

                    Map<String, byte[]> tm2 = new HashMap<>();
                    tm2.put("HyperLedgerFabric", "QueryByChaincodeRequest:JavaSDK".getBytes(UTF_8));
                    tm2.put("method", "QueryByChaincodeRequest".getBytes(UTF_8));
                    queryByChaincodeRequest.setTransientMap(tm2);

                    Collection<ProposalResponse> queryProposals = channel.queryByChaincode(queryByChaincodeRequest, channel.getPeers());
                    for (ProposalResponse proposalResponse : queryProposals) {
                        if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                            fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                                    ". Messages: " + proposalResponse.getMessage()
                                    + ". Was verified : " + proposalResponse.isVerified());
                        } else {
                            String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                            out("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                            assertEquals(payload, expect);
                        }
                    }

                    return null;
                } catch (Exception e) {
                    out("Caught exception while running query");
                    e.printStackTrace();
                    fail("Failed during chaincode query with error : " + e.getMessage());
                }

                return null;
            }).exceptionally(e -> {
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {
                        throw new AssertionError(format("Transaction with txid %s failed. %s", te.getTransactionID(), e.getMessage()), e);
                    }
                }

                throw new AssertionError(format("Test failed with %s exception %s", e.getClass().getName(), e.getMessage()), e);

            }).get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);

            // Channel queries

            // We can only send channel queries to peers that are in the same org as the SDK user context
            // Get the peers from the current org being used and pick one randomly to send the queries to.
            //  Set<Peer> peerSet = sampleOrg.getPeers();
            //  Peer queryPeer = peerSet.iterator().next();
            //   out("Using peer %s for channel queries", queryPeer.getName());

            BlockchainInfo channelInfo = channel.queryBlockchainInfo();
            out("Channel info for : " + channelName);
            out("Channel height: " + channelInfo.getHeight());
            String chainCurrentHash = Hex.encodeHexString(channelInfo.getCurrentBlockHash());
            String chainPreviousHash = Hex.encodeHexString(channelInfo.getPreviousBlockHash());
            out("Chain current block hash: " + chainCurrentHash);
            out("Chainl previous block hash: " + chainPreviousHash);

            // Query by block number. Should return latest block, i.e. block number 2
            BlockInfo returnedBlock = channel.queryBlockByNumber(channelInfo.getHeight() - 1);
            String previousHash = Hex.encodeHexString(returnedBlock.getPreviousHash());
            out("queryBlockByNumber returned correct block with blockNumber " + returnedBlock.getBlockNumber()
                    + " \n previous_hash " + previousHash);
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());
            assertEquals(chainPreviousHash, previousHash);

            // Query by block hash. Using latest block's previous hash so should return block number 1
            byte[] hashQuery = returnedBlock.getPreviousHash();
            returnedBlock = channel.queryBlockByHash(hashQuery);
            out("queryBlockByHash returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 2, returnedBlock.getBlockNumber());

            // Query block by TxID. Since it's the last TxID, should be block 2
            returnedBlock = channel.queryBlockByTransactionID(testTxID);
            out("queryBlockByTxID returned block with blockNumber " + returnedBlock.getBlockNumber());
            assertEquals(channelInfo.getHeight() - 1, returnedBlock.getBlockNumber());

            // query transaction by ID
            TransactionInfo txInfo = channel.queryTransactionByID(testTxID);
            out("QueryTransactionByID returned TransactionInfo: txID " + txInfo.getTransactionID()
                    + "\n     validation code " + txInfo.getValidationCode().getNumber());

            if (chaincodeEventListenerHandle != null) {

                channel.unregisterChaincodeEventListener(chaincodeEventListenerHandle);

                final int numberEventsExpected =
                        channel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).size();
                //just make sure we get the notifications.
                for (int i = 15; i > 0; --i) {
                    if (chaincodeEvents.size() == numberEventsExpected) {
                        break;
                    } else {
                        Thread.sleep(90); // wait for the events.
                    }

                }
                assertEquals(numberEventsExpected, chaincodeEvents.size());

                for (ChaincodeEventCapture chaincodeEventCapture : chaincodeEvents) {
                    assertEquals(chaincodeEventListenerHandle, chaincodeEventCapture.handle);
                    assertEquals(testTxID, chaincodeEventCapture.chaincodeEvent.getTxId());
                    assertEquals(EXPECTED_EVENT_NAME, chaincodeEventCapture.chaincodeEvent.getEventName());
                    assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEventCapture.chaincodeEvent.getPayload()));
                    assertEquals(CHAIN_CODE_NAME, chaincodeEventCapture.chaincodeEvent.getChaincodeId());

                    BlockEvent blockEvent = chaincodeEventCapture.blockEvent;
                    assertEquals(channelName, blockEvent.getChannelId());

                }

            } else {
                assertTrue(chaincodeEvents.isEmpty());
            }

            out("Running for Channel %s done", channelName);

        } catch (Exception e) {
            out("Caught an exception running channel %s", channel.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }

    Channel constructChannel(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        ////////////////////////////
        //Construct the channel
        //

        out("Constructing channel %s", name);

        //boolean doPeerEventing = false;
        boolean doPeerEventing = !testConfig.isRunningAgainstFabric10() && BAR_CHANNEL_NAME.equals(name);
//        boolean doPeerEventing = !testConfig.isRunningAgainstFabric10() && FOO_CHANNEL_NAME.equals(name);
        //Only peer Admin org
        SampleUser peerAdmin = sampleOrg.getPeerAdmin();
        client.setUserContext(peerAdmin);

        Collection<Orderer> orderers = new LinkedList<>();

        for (String orderName : sampleOrg.getOrdererNames()) {

            Properties ordererProperties = testConfig.getOrdererProperties(orderName);

            //example of setting keepAlive to avoid timeouts on inactive http2 connections.
            // Under 5 minutes would require changes to server side to accept faster ping rates.
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[] {true});

            orderers.add(client.newOrderer(orderName, sampleOrg.getOrdererLocation(orderName),
                    ordererProperties));
        }

        //Just pick the first orderer in the list to create the channel.

        Orderer anOrderer = orderers.iterator().next();
        orderers.remove(anOrderer);

        String path = TEST_FIXTURES_PATH + "/sdkintegration/e2e-2Orgs/" + testConfig.getFabricConfigGenVers() + "/" + name + ".tx";
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(path));

        //Create channel that has only one signer that is this orgs peer admin. If channel creation policy needed more signature they would need to be added too.
        Channel newChannel = client.newChannel(name, anOrderer, channelConfiguration, client.getChannelConfigurationSignature(channelConfiguration, peerAdmin));

        out("Created channel %s", name);

        boolean everyother = true; //test with both cases when doing peer eventing.
        for (String peerName : sampleOrg.getPeerNames()) {
            String peerLocation = sampleOrg.getPeerLocation(peerName);

            Properties peerProperties = testConfig.getPeerProperties(peerName); //test properties for peer.. if any.
            if (peerProperties == null) {
                peerProperties = new Properties();
            }

            //Example of setting specific options on grpc's NettyChannelBuilder
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

            Peer peer = client.newPeer(peerName, peerLocation, peerProperties);
            if (testConfig.isFabricVersionAtOrAfter("1.3")) {
                newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.

            } else {
                if (doPeerEventing && everyother) {
                    newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.
                } else {
                    // Set peer to not be all roles but eventing.
                    newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY)));
                }
            }
            out("Peer %s joined channel %s", peerName, name);
            everyother = !everyother;
        }
        //just for testing ...
        if (doPeerEventing || testConfig.isFabricVersionAtOrAfter("1.3")) {
            // Make sure there is one of each type peer at the very least.
            assertFalse(newChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty());
            assertFalse(newChannel.getPeers(PeerRole.NO_EVENT_SOURCE).isEmpty());
        }

        for (Orderer orderer : orderers) { //add remaining orderers if any.
            newChannel.addOrderer(orderer);
        }


        newChannel.initialize();

        out("Finished initialization channel %s", name);

        //Just checks if channel can be serialized and deserialized .. otherwise this is just a waste :)
        byte[] serializedChannelBytes = newChannel.serializeChannel();
        newChannel.shutdown(true);

        return client.deSerializeChannel(serializedChannelBytes).initialize();

    }

    private void waitOnFabric(int additional) {
        //NOOP today

    }

    void blockWalker(HFClient client, Channel channel) throws InvalidArgumentException, ProposalException, IOException {
        try {
            BlockchainInfo channelInfo = channel.queryBlockchainInfo();

            for (long current = channelInfo.getHeight() - 1; current > -1; --current) {
                BlockInfo returnedBlock = channel.queryBlockByNumber(current);
                final long blockNumber = returnedBlock.getBlockNumber();

                out("current block number %d has data hash: %s", blockNumber, Hex.encodeHexString(returnedBlock.getDataHash()));
                out("current block number %d has previous hash id: %s", blockNumber, Hex.encodeHexString(returnedBlock.getPreviousHash()));
                out("current block number %d has calculated block hash is %s", blockNumber, Hex.encodeHexString(SDKUtils.calculateBlockHash(client,
                        blockNumber, returnedBlock.getPreviousHash(), returnedBlock.getDataHash())));

                final int envelopeCount = returnedBlock.getEnvelopeCount();
                assertEquals(1, envelopeCount);
                out("current block number %d has %d envelope count:", blockNumber, returnedBlock.getEnvelopeCount());
                int i = 0;
                int transactionCount = 0;
                for (BlockInfo.EnvelopeInfo envelopeInfo : returnedBlock.getEnvelopeInfos()) {
                    ++i;

                    out("  Transaction number %d has transaction id: %s", i, envelopeInfo.getTransactionID());
                    final String channelId = envelopeInfo.getChannelId();
                    assertTrue("foo".equals(channelId) || "bar".equals(channelId));

                    out("  Transaction number %d has channel id: %s", i, channelId);
                    out("  Transaction number %d has epoch: %d", i, envelopeInfo.getEpoch());
                    out("  Transaction number %d has transaction timestamp: %tB %<te,  %<tY  %<tT %<Tp", i, envelopeInfo.getTimestamp());
                    out("  Transaction number %d has type id: %s", i, "" + envelopeInfo.getType());
                    out("  Transaction number %d has nonce : %s", i, "" + Hex.encodeHexString(envelopeInfo.getNonce()));
                    out("  Transaction number %d has submitter mspid: %s,  certificate: %s", i, envelopeInfo.getCreator().getMspid(), envelopeInfo.getCreator().getId());

                    if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                        ++transactionCount;
                        BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;

                        out("  Transaction number %d has %d actions", i, transactionEnvelopeInfo.getTransactionActionInfoCount());
                        assertEquals(1, transactionEnvelopeInfo.getTransactionActionInfoCount()); // for now there is only 1 action per transaction.
                        out("  Transaction number %d isValid %b", i, transactionEnvelopeInfo.isValid());
                        assertEquals(transactionEnvelopeInfo.isValid(), true);
                        out("  Transaction number %d validation code %d", i, transactionEnvelopeInfo.getValidationCode());
                        assertEquals(0, transactionEnvelopeInfo.getValidationCode());

                        int j = 0;
                        for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                            ++j;
                            out("   Transaction action %d has response status %d", j, transactionActionInfo.getResponseStatus());

                            long excpectedStatus = current == 2 && i == 1 && j == 1 ? expectedMoveRCMap.get(channel.getName()) : 200; // only transaction we changed the status code.
                            assertEquals(format("channel %s current: %d, i: %d.  transaction action j=%d", channel.getName(), current, i, j), excpectedStatus, transactionActionInfo.getResponseStatus());
                            out("   Transaction action %d has response message bytes as string: %s", j,
                                    printableString(new String(transactionActionInfo.getResponseMessageBytes(), UTF_8)));
                            out("   Transaction action %d has %d endorsements", j, transactionActionInfo.getEndorsementsCount());
                            assertEquals(2, transactionActionInfo.getEndorsementsCount());

                            for (int n = 0; n < transactionActionInfo.getEndorsementsCount(); ++n) {
                                BlockInfo.EndorserInfo endorserInfo = transactionActionInfo.getEndorsementInfo(n);
                                out("Endorser %d signature: %s", n, Hex.encodeHexString(endorserInfo.getSignature()));
                                out("Endorser %d endorser: mspid %s \n certificate %s", n, endorserInfo.getMspid(), endorserInfo.getId());
                            }
                            out("   Transaction action %d has %d chaincode input arguments", j, transactionActionInfo.getChaincodeInputArgsCount());
                            for (int z = 0; z < transactionActionInfo.getChaincodeInputArgsCount(); ++z) {
                                out("     Transaction action %d has chaincode input argument %d is: %s", j, z,
                                        printableString(new String(transactionActionInfo.getChaincodeInputArgs(z), UTF_8)));
                            }

                            out("   Transaction action %d proposal response status: %d", j,
                                    transactionActionInfo.getProposalResponseStatus());
                            out("   Transaction action %d proposal response payload: %s", j,
                                    printableString(new String(transactionActionInfo.getProposalResponsePayload())));

                            String chaincodeIDName = transactionActionInfo.getChaincodeIDName();
                            String chaincodeIDVersion = transactionActionInfo.getChaincodeIDVersion();
                            String chaincodeIDPath = transactionActionInfo.getChaincodeIDPath();
                            out("   Transaction action %d proposal chaincodeIDName: %s, chaincodeIDVersion: %s,  chaincodeIDPath: %s ", j,
                                    chaincodeIDName, chaincodeIDVersion, chaincodeIDPath);

                            // Check to see if we have our expected event.
                            if (blockNumber == 2) {
                                ChaincodeEvent chaincodeEvent = transactionActionInfo.getEvent();
                                assertNotNull(chaincodeEvent);

                                assertTrue(Arrays.equals(EXPECTED_EVENT_DATA, chaincodeEvent.getPayload()));
                                assertEquals(testTxID, chaincodeEvent.getTxId());
                                assertEquals(CHAIN_CODE_NAME, chaincodeEvent.getChaincodeId());
                                assertEquals(EXPECTED_EVENT_NAME, chaincodeEvent.getEventName());
                                assertEquals(CHAIN_CODE_NAME, chaincodeIDName);
                                assertEquals("github.com/example_cc", chaincodeIDPath);
                                assertEquals("1", chaincodeIDVersion);

                            }

                            TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
                            if (null != rwsetInfo) {
                                out("   Transaction action %d has %d name space read write sets", j, rwsetInfo.getNsRwsetCount());

                                for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                                    final String namespace = nsRwsetInfo.getNamespace();
                                    KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();

                                    int rs = -1;
                                    for (KvRwset.KVRead readList : rws.getReadsList()) {
                                        rs++;

                                        out("     Namespace %s read set %d key %s  version [%d:%d]", namespace, rs, readList.getKey(),
                                                readList.getVersion().getBlockNum(), readList.getVersion().getTxNum());

                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if ("example_cc_go".equals(namespace)) {
                                                if (rs == 0) {
                                                    assertEquals("a", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else if (rs == 1) {
                                                    assertEquals("b", readList.getKey());
                                                    assertEquals(1, readList.getVersion().getBlockNum());
                                                    assertEquals(0, readList.getVersion().getTxNum());
                                                } else {
                                                    fail(format("unexpected readset %d", rs));
                                                }

                                                TX_EXPECTED.remove("readset1");
                                            }
                                        }
                                    }

                                    rs = -1;
                                    for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                                        rs++;
                                        String valAsString = printableString(new String(writeList.getValue().toByteArray(), UTF_8));

                                        out("     Namespace %s write set %d key %s has value '%s' ", namespace, rs,
                                                writeList.getKey(),
                                                valAsString);

                                        if ("bar".equals(channelId) && blockNumber == 2) {
                                            if (rs == 0) {
                                                assertEquals("a", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else if (rs == 1) {
                                                assertEquals("b", writeList.getKey());
                                                assertEquals("400", valAsString);
                                            } else {
                                                fail(format("unexpected writeset %d", rs));
                                            }

                                            TX_EXPECTED.remove("writeset1");
                                        }
                                    }
                                }
                            }
                        }
                    }

                    assertEquals(transactionCount, returnedBlock.getTransactionCount());

                }
            }
            if (!TX_EXPECTED.isEmpty()) {
                fail(TX_EXPECTED.get(0));
            }
        } catch (InvalidProtocolBufferRuntimeException e) {
            throw e.getCause();
        }
    }

}
