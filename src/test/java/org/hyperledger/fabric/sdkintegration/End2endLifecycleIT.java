/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.hyperledger.fabric.sdkintegration;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;

import com.google.common.io.Closer;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest;
import io.opentelemetry.proto.collector.trace.v1.ExportTraceServiceResponse;
import io.opentelemetry.proto.collector.trace.v1.TraceServiceGrpc;
import io.opentelemetry.proto.trace.v1.ResourceSpans;
import org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent;
import org.hyperledger.fabric.sdk.ChaincodeCollectionConfiguration;
import org.hyperledger.fabric.sdk.ChaincodeResponse;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.ChannelConfiguration;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleApproveChaincodeDefinitionForMyOrgRequest;
import org.hyperledger.fabric.sdk.LifecycleChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.LifecycleChaincodePackage;
import org.hyperledger.fabric.sdk.LifecycleCheckCommitReadinessProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleCheckCommitReadinessRequest;
import org.hyperledger.fabric.sdk.LifecycleCommitChaincodeDefinitionProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleCommitChaincodeDefinitionRequest;
import org.hyperledger.fabric.sdk.LifecycleInstallChaincodeProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleInstallChaincodeRequest;
import org.hyperledger.fabric.sdk.LifecycleQueryChaincodeDefinitionProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleQueryChaincodeDefinitionsProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleQueryChaincodeDefinitionsRequest;
import org.hyperledger.fabric.sdk.LifecycleQueryChaincodeDefinitionsResult;
import org.hyperledger.fabric.sdk.LifecycleQueryInstalledChaincodeProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleQueryInstalledChaincodeRequest;
import org.hyperledger.fabric.sdk.LifecycleQueryInstalledChaincodesProposalResponse;
import org.hyperledger.fabric.sdk.LifecycleQueryInstalledChaincodesProposalResponse.LifecycleQueryInstalledChaincodesResult;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.Peer.PeerRole;
import org.hyperledger.fabric.sdk.ProposalResponse;
import org.hyperledger.fabric.sdk.QueryByChaincodeRequest;
import org.hyperledger.fabric.sdk.QueryLifecycleQueryChaincodeDefinitionRequest;
import org.hyperledger.fabric.sdk.TestConfigHelper;
import org.hyperledger.fabric.sdk.TransactionProposalRequest;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.ChaincodeCollectionConfigurationException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
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
import static org.hyperledger.fabric.sdk.Channel.PeerOptions.createPeerOptions;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.getPEMStringFromPrivateKey;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.resetConfig;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test end to end scenario
 */
public class End2endLifecycleIT {

    static final String TEST_ADMIN_NAME = "admin";
    private static final TestConfig testConfig = TestConfig.getConfig();
    private static final String TEST_FIXTURES_PATH = "src/test/fixture";
    private static final String CHANNEL_NAME = "v2channel";
    private static final String BAR_CHANNEL_NAME = "bar";
    private static final int DEPLOYWAITTIME = testConfig.getDeployWaitTime();
    private static final byte[] EXPECTED_EVENT_DATA = "!".getBytes(UTF_8);
    private static final String EXPECTED_EVENT_NAME = "event";
    private static final Map<String, String> TX_EXPECTED;
    private static final String DEFAULT_ENDORSMENT_PLUGIN = "escc";
    private static final String DEFAULT_VALDITATION_PLUGIN = "vscc";
    private static final String ORG_1_MSP = "Org1MSP";
    private static final String ORG_2_MSP = "Org2MSP";
    static String testUser1 = "user1";
    private static Random random = new Random();

    static {
        TX_EXPECTED = new HashMap<>();
        TX_EXPECTED.put("readset1", "Missing readset for channel bar block 1");
        TX_EXPECTED.put("writeset1", "Missing writeset for channel bar block 1");
    }

    private static final class FakeCollector extends TraceServiceGrpc.TraceServiceImplBase {
        private final List<ResourceSpans> receivedSpans = new ArrayList<>();
        private Status returnedStatus = Status.OK;

        @Override
        public void export(
                final ExportTraceServiceRequest request,
                final StreamObserver<ExportTraceServiceResponse> responseObserver) {
            receivedSpans.addAll(request.getResourceSpansList());
            responseObserver.onNext(ExportTraceServiceResponse.newBuilder().build());
            if (!returnedStatus.isOk()) {
                if (returnedStatus.getCode() == Status.Code.DEADLINE_EXCEEDED) {
                    // Do not call onCompleted to simulate a deadline exceeded.
                    return;
                }
                responseObserver.onError(returnedStatus.asRuntimeException());
                return;
            }
            responseObserver.onCompleted();
        }

        List<ResourceSpans> getReceivedSpans() {
            return receivedSpans;
        }

        void setReturnedStatus(final Status returnedStatus) {
            this.returnedStatus = returnedStatus;
        }
    }

    private final Closer closer = Closer.create();
    private final FakeCollector fakeTracesCollector = new FakeCollector();
    private final TestConfigHelper configHelper = new TestConfigHelper();
    String testName = "End2endLifecycleIT";

    String CHAIN_CODE_PATH = "github.com/example_cc";
    String CHAIN_CODE_VERSION = "1";
    // String CHAINCODE_LABEL = "lc_example_cc_go_1"; // This is totally arbitrary! can be anything you like.

    SampleStore sampleStore = null;
    Map<String, Properties> clientTLSProperties = new HashMap<>();
    File sampleStoreFile = new File(System.getProperty("java.io.tmpdir") + "/HFCSampletest.properties");
    //CHECKSTYLE.ON: Method length is 320 lines (max allowed is 150).
    Map<String, Long> expectedMoveRCMap = new HashMap<>(); // map from channel name to move chaincode's return code.
    private Collection<SampleOrg> testSampleOrgs;

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(format(format, args));
        System.err.flush();
        System.out.flush();

    }

    @Before
    public void checkConfig() throws Exception {
        out("\n\n\nRUNNING: %s.\n", testName);
        Server server =
                NettyServerBuilder.forPort(4317)
                        .addService(fakeTracesCollector)
                        .build()
                        .start();
        closer.register(server::shutdownNow);
        //   configHelper.clearConfig();
        //   assertEquals(256, Config.getConfig().getSecurityLevel());
        System.setProperty("OTEL_TRACES_SAMPLER", "always_on");
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

    @Test
    public void setup() throws Exception {
        //Persistence is not part of SDK. Sample file store is for demonstration purposes only!
        //   MUST be replaced with more robust application implementation  (Database, LDAP)

//        if (sampleStoreFile.exists()) { //For testing start fresh
//            sampleStoreFile.delete();
//        }

        sampleStore = new SampleStore(sampleStoreFile);
        enrollUsersSetup(sampleStore); //This enrolls users with fabric ca and setups sample store to get users later.
        runFabricTest(); //Runs Fabric tests with constructing channels, joining peers, exercising chaincode

    }

    public void runFabricTest() throws Exception {

        ////////////////////////////
        // Setup client

        //Create instance of client.
        HFClient org1Client = HFClient.createNewInstance();

        org1Client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        ////////////////////////////
        //Construct and run the channels
        SampleOrg org1 = testConfig.getIntegrationTestsSampleOrg("peerOrg1");
        Channel org1Channel = constructChannel(CHANNEL_NAME, org1Client, org1, true);

        Collection<Peer> org1MyPeers = org1Channel.getPeers();

        // Now lets be the other organization which really should be running in another application.

        verifyNoInstalledChaincodes(org1Client, org1MyPeers);

        // verifyNotInstalledChaincode(org1Client, org1MyPeers, CHAIN_CODE_NAME, CHAIN_CODE_VERSION);

        HFClient org2Client = HFClient.createNewInstance();

        org2Client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

        ////////////////////////////
        //Construct channel object for org2
        SampleOrg org2 = testConfig.getIntegrationTestsSampleOrg("peerOrg2");
        Channel org2Channel = constructChannel(CHANNEL_NAME, org2Client, org2,
                false); // Don't create the fabric channel as org1 has done that.

        Collection<Peer> org2MyPeers = org2Channel.getPeers();

        verifyNoInstalledChaincodes(org2Client, org2MyPeers);
        //    verifyNotInstalledChaincode(org2Client, org2MyPeers, CHAIN_CODE_NAME, CHAIN_CODE_VERSION);

        //Add to the channel peers from other org.
        Collection<Peer> org2OtherPeers = addOtherOrgPeers(org2Client, org2Channel, org1);

        //Since org2's peers has joined channel can now add them to org1 too
        Collection<Peer> org1OtherPeers = addOtherOrgPeers(org1Client, org1Channel, org2);

        final Map<String, Object> expectedMap = new HashMap<String, Object>() {{
            put("sequence", 1L);
            put("queryBvalue", "310");
        }};

        //////////////
        ////  DO Go with our own endorsement policy
        out("---   Running GO Chaincode with own endorsement   ---");
        LifecycleChaincodePackage lifecycleChaincodePackage = createLifecycleChaincodePackage(
                "lc_example_cc_go_1", // some label
                Type.GO_LANG,
                IntegrationSuite.getGoChaincodePath("sample1").toString(),
                CHAIN_CODE_PATH,
                "src/test/fixture/meta-infs/end2endit");

        //Org1 also creates the endorsement policy for the chaincode. // also known as validationParameter !
        LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy = LifecycleChaincodeEndorsementPolicy.fromSignaturePolicyYamlFile(Paths.get(TEST_FIXTURES_PATH +
                "/sdkintegration/chaincodeendorsementpolicy.yaml"));

        final String goChaincodeName = "lc_example_cc_go";
        runChannel(org1Client, org1Channel, org1, org1MyPeers, org1OtherPeers,
                org2Client, org2Channel, org2, org2MyPeers, org2OtherPeers,
                lifecycleChaincodePackage, goChaincodeName,
                "1", //Version - bump up next time.
                chaincodeEndorsementPolicy,
                null, // ChaincodeCollectionConfiguration
                true,  // initRequired
                expectedMap);

        //// Do Go update. Use same chaincode name, new version and chaincode package. This chaincode doubles move result so we know it changed.
        out("---   Running GO Chaincode with update new version.   ---");

        LifecycleChaincodePackage lifecycleChaincodePackageUpdate = createLifecycleChaincodePackage(
                "lc_example_cc_go_11", // some label
                Type.GO_LANG,
                IntegrationSuite.getGoChaincodePath("sample_11").toString(),
                CHAIN_CODE_PATH,
                null); // no metadata this time.

        runChannel(org1Client, org1Channel, org1, org1MyPeers, org1OtherPeers,
                org2Client, org2Channel, org2, org2MyPeers, org2OtherPeers,
                lifecycleChaincodePackageUpdate, goChaincodeName,
                "2", //version is 2 it's an update.
                chaincodeEndorsementPolicy,
                ChaincodeCollectionConfiguration.fromYamlFile(new File("src/test/fixture/collectionProperties/PrivateDataIT.yaml")),
                true,  // initRequired
                new HashMap<String, Object>() {{
                    put("sequence", 2L);  // this is an update sequence should be 2
                    put("queryBvalue", "320");  // init is run which set back to 300.  new chaincoode doubles the move of 10 to 20 so expect 320
                }});

        //////////////
        ////  DO Java
        out("---  Running Java Chaincode.---  \n\n");
        LifecycleChaincodePackage lifecycleChaincodePackageJava = createLifecycleChaincodePackage(
                "JavaLABEL", // some label
                Type.JAVA, IntegrationSuite.getJavaChaincodePath("sample1").toString(),
                "", // no path in Java.
                null); // no metaInf data

        runChannel(org1Client, org1Channel, org1, org1MyPeers, org1OtherPeers,
                org2Client, org2Channel, org2, org2MyPeers, org2OtherPeers,
                lifecycleChaincodePackageJava, "example_cc_java", // chaincode name
                CHAIN_CODE_VERSION,
                null, // use default endorsement policy
                null, //ChaincodeCollectionConfiguration
                true,  // initRequired
                expectedMap);

        //////////////
        ////  DO Node
        out("---   Running Node Chaincode.   ---");
        LifecycleChaincodePackage lifecycleChaincodePackageNode = createLifecycleChaincodePackage(
                "ImNodeSeeMeRun", // some label
                Type.NODE,
                IntegrationSuite.getNodeChaincodePath("sample1").toString(),
                "", // no path in node.
                null); // no metaInf data

        runChannel(org1Client, org1Channel, org1, org1MyPeers, org1OtherPeers,
                org2Client, org2Channel, org2, org2MyPeers, org2OtherPeers,
                lifecycleChaincodePackageNode, "example_cc_node", // chaincode name
                CHAIN_CODE_VERSION,
                null, // use default endorsement policy
                null, //ChaincodeCollectionConfiguration
                true,  // initRequired
                expectedMap);

        //////////////
        ////  DO Go without any standard init required.
        out("---   Running GO Chaincode with no init.   ---");
        LifecycleChaincodePackage lifecycleChaincodePackageNoInit = createLifecycleChaincodePackage(
                "lc_example_cc_go_1", // some label
                Type.GO_LANG,
                IntegrationSuite.getGoChaincodePath("sample1NoInit").toString(),
                CHAIN_CODE_PATH,
                null);

        runChannel(org1Client, org1Channel, org1, org1MyPeers, org1OtherPeers,
                org2Client, org2Channel, org2, org2MyPeers, org2OtherPeers,
                lifecycleChaincodePackageNoInit,
                "lc_example_cc_goNOIT", // chaincode name
                CHAIN_CODE_VERSION,
                null, // use default endorsement policy
                null, // ChaincodeCollectionConfiguration
                false,  // initRequired is now false
                expectedMap);

        assertFalse(org1Channel.isShutdown());
        org1Channel.shutdown(true); // Force foo channel to shutdown clean up resources.
        assertTrue(org1Channel.isShutdown());

        assertNull(org1Client.getChannel(CHANNEL_NAME));
        out("\n");

        assertFalse(fakeTracesCollector.receivedSpans.isEmpty());

        out("That's all folks!");
    }

    //CHECKSTYLE.OFF: ParameterNumber
    void runChannel(HFClient org1Client, Channel org1Channel, SampleOrg org1, Collection<Peer> org1MyPeers, Collection<Peer> org1OtherPeers,
                    HFClient org2Client, Channel org2Channel, SampleOrg org2, Collection<Peer> org2MyPeers, Collection<Peer> org2OtherPeers,
                    LifecycleChaincodePackage lifecycleChaincodePackage, String chaincodeName,
                    String chaincodeVersion, LifecycleChaincodeEndorsementPolicy lifecycleChaincodeEndorsementPolicy,
                    ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired,
                    Map<String, Object> expected) {

        try {
            //Should be no chaincode installed at this time.

            org1Client.setUserContext(org1.getPeerAdmin());

            final String chaincodeLabel = lifecycleChaincodePackage.getLabel();
            final Type chaincodeType = lifecycleChaincodePackage.getType();

            //Org1 installs the chaincode on its peers.
            out("Org1 installs the chaincode on its peers.");
            String org1ChaincodePackageID = lifecycleInstallChaincode(org1Client, org1MyPeers, lifecycleChaincodePackage);
            assertTrue(org1ChaincodePackageID.contains(chaincodeLabel)); // the packageId should have the label in it so you have some idea what it is.

            //Sanity check to see if chaincode really is on it's peers and has the hash as expected by querying all chaincodes.
            out("Org1 check installed chaincode on peers.");

            verifyByQueryInstalledChaincodes(org1Client, org1MyPeers, chaincodeLabel, org1ChaincodePackageID);
            // another query test if it works
            verifyByQueryInstalledChaincode(org1Client, org1MyPeers, org1ChaincodePackageID, chaincodeLabel);

            // Sequence  number increase with each change and is used to make sure you are referring to the same change.
            long sequence = -1L;
            final QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest = org1Client.newQueryLifecycleQueryChaincodeDefinitionRequest();
            queryLifecycleQueryChaincodeDefinitionRequest.setChaincodeName(chaincodeName);

            Collection<LifecycleQueryChaincodeDefinitionProposalResponse> firstQueryDefininitions = org1Channel.lifecycleQueryChaincodeDefinition(queryLifecycleQueryChaincodeDefinitionRequest, org1MyPeers);

            for (LifecycleQueryChaincodeDefinitionProposalResponse firstDefinition : firstQueryDefininitions) {
                if (firstDefinition.getStatus() == ProposalResponse.Status.SUCCESS) {
                    sequence = firstDefinition.getSequence() + 1L; //Need to bump it up to the next.
                    break;
                } else { //Failed but why?
                    if (404 == firstDefinition.getChaincodeActionResponseStatus()) {
                        // not found .. done set sequence to 1;
                        sequence = 1;
                        break;
                    }
                }
            }

            if (null != expected) {
                assertEquals(expected.get("sequence"), sequence);
            }

            //     ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = collectionConfiguration == null ? null : ChaincodeCollectionConfiguration.fromYamlFile(new File(collectionConfiguration));
//            // ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = ChaincodeCollectionConfiguration.fromYamlFile(new File("src/test/fixture/collectionProperties/PrivateDataIT.yaml"));
//            chaincodeCollectionConfiguration = null;
            final Peer anOrg1Peer = org1MyPeers.iterator().next();
            out("Org1 approving chaincode definition for my org.");
            TransactionEvent transactionEvent = lifecycleApproveChaincodeDefinitionForMyOrg(org1Client, org1Channel,
                    Collections.singleton(anOrg1Peer),  //support approve on multiple peers but really today only need one. Go with minimum.
                    sequence, chaincodeName, chaincodeVersion, lifecycleChaincodeEndorsementPolicy, chaincodeCollectionConfiguration, initRequired, org1ChaincodePackageID)
                    .get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            assertTrue(transactionEvent.isValid());

            verifyByCheckCommitReadinessStatus(org1Client, org1Channel, sequence, chaincodeName, chaincodeVersion,
                    lifecycleChaincodeEndorsementPolicy, chaincodeCollectionConfiguration, initRequired, org1MyPeers,
                    new HashSet<>(Arrays.asList(ORG_1_MSP)), // Approved
                    new HashSet<>(Arrays.asList(ORG_2_MSP))); // Un approved.

            //Serialize these to bytes to give to other organizations.
            byte[] chaincodePackageBtyes = lifecycleChaincodePackage.getAsBytes();
            final byte[] chaincodeEndorsementPolicyAsBytes = lifecycleChaincodeEndorsementPolicy == null ? null : lifecycleChaincodeEndorsementPolicy.getSerializedPolicyBytes();

            ///////////////////////////////////
            //org1 communicates to org2 out of bounds (email, floppy, etc) : CHAIN_CODE_NAME, CHAIN_CODE_VERSION, chaincodeHash, definitionSequence, chaincodePackageBtyes and chaincodeEndorsementPolicyAsBytes.
            ////  Now as org2
            LifecycleChaincodePackage org2LifecycleChaincodePackage = LifecycleChaincodePackage.fromBytes(chaincodePackageBtyes);
            LifecycleChaincodeEndorsementPolicy org2ChaincodeEndorsementPolicy = chaincodeEndorsementPolicyAsBytes == null ? null :
                    LifecycleChaincodeEndorsementPolicy.fromBytes(chaincodeEndorsementPolicyAsBytes);

            org2Client.setUserContext(org2.getPeerAdmin());

            //Org2 installs the chaincode on its peers
            out("Org2 installs the chaincode on its peers.");
            String org2ChaincodePackageID = lifecycleInstallChaincode(org2Client, org2MyPeers, org2LifecycleChaincodePackage);

            //Sanity check to see if chaincode really is on it's peers and has the hash as expected.
            out("Org2 check installed chaincode on peers.");
            verifyByQueryInstalledChaincodes(org2Client, org2MyPeers, chaincodeLabel, org2ChaincodePackageID);
            // check by querying for specific chaincode
            verifyByQueryInstalledChaincode(org2Client, org2MyPeers, org2ChaincodePackageID, chaincodeLabel);

            //Approve the chaincode for the peer's in org2
            out("Org2 approving chaincode definition for my org.");
            TransactionEvent org2TransactionEvent = lifecycleApproveChaincodeDefinitionForMyOrg(org2Client, org2Channel,
                    Collections.singleton(org2MyPeers.iterator().next()),  //support approve on multiple peers but really today only need one. Go with minimum.
                    sequence, chaincodeName, chaincodeVersion, org2ChaincodeEndorsementPolicy, chaincodeCollectionConfiguration, initRequired, org2ChaincodePackageID)
                    .get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            assertTrue(org2TransactionEvent.isValid());

            out("Checking on org2's network for approvals");
            verifyByCheckCommitReadinessStatus(org2Client, org2Channel, sequence, chaincodeName, chaincodeVersion, lifecycleChaincodeEndorsementPolicy, chaincodeCollectionConfiguration, initRequired, org2MyPeers,
                    new HashSet<>(Arrays.asList(ORG_1_MSP, ORG_2_MSP)), // Approved
                    Collections.emptySet()); // Un approved.

            out("Checking on org1's network for approvals");
            verifyByCheckCommitReadinessStatus(org1Client, org1Channel, sequence, chaincodeName, chaincodeVersion, lifecycleChaincodeEndorsementPolicy, chaincodeCollectionConfiguration, initRequired, org1MyPeers,
                    new HashSet<>(Arrays.asList(ORG_1_MSP, ORG_2_MSP)), // Approved
                    Collections.emptySet()); // unapproved.

            // Org2 knows org1 has approved already so it does the chaincode definition commit, but this could be done by org1 too.
            out("Org2 now doing the commit chaincode definition.");

            // Get collection of one of org2 orgs peers and one from the other.
            out("Org2 doing commit chaincode definition");
            Collection<Peer> org2EndorsingPeers = Arrays.asList(org2MyPeers.iterator().next(), org2OtherPeers.iterator().next());
            transactionEvent = commitChaincodeDefinitionRequest(org2Client, org2Channel, sequence, chaincodeName, chaincodeVersion, org2ChaincodeEndorsementPolicy, chaincodeCollectionConfiguration, initRequired, org2EndorsingPeers)
                    .get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            assertTrue(transactionEvent.isValid());

            out("Org2 done with commit. block #%d!", transactionEvent.getBlockEvent().getBlockNumber());

            verifyByQueryChaincodeDefinition(org2Client, org2Channel, chaincodeName, org2MyPeers, sequence, initRequired, chaincodeEndorsementPolicyAsBytes, chaincodeCollectionConfiguration);
            verifyByQueryChaincodeDefinition(org1Client, org1Channel, chaincodeName, org1MyPeers, sequence, initRequired, chaincodeEndorsementPolicyAsBytes, chaincodeCollectionConfiguration);

            verifyByQueryChaincodeDefinitions(org2Client, org2Channel, org2MyPeers, chaincodeName);
            verifyByQueryChaincodeDefinitions(org1Client, org1Channel, org1MyPeers, chaincodeName);

            //Now org2 could also do the init for the chaincode but it just informs org2 admin of the commit so it does it.
            out("Org1 doing init");
            transactionEvent = executeChaincode(org1Client, org1.getPeerAdmin(), org1Channel, "init",
                    initRequired ? true : null, // doInit don't even specify it has it should default to false
                    chaincodeName, chaincodeType, "a,", "100", "b", "300").get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            assertTrue(transactionEvent.isValid());

            if (initRequired) {
                assertTrue(transactionEvent.getTransactionActionInfo(0).getChaincodeInputIsInit());
            }

            transactionEvent = executeChaincode(org2Client, org2.getPeerAdmin(), org2Channel, "move",
                    false, // doInit
                    chaincodeName, chaincodeType, "a,", "b", "10").get(testConfig.getTransactionWaitTime(), TimeUnit.SECONDS);
            assertTrue(transactionEvent.isValid());

            if (null != expected) {
                executeVerifyByQuery(org1Client, org1Channel, chaincodeName, (String) expected.get("queryBvalue"));
                executeVerifyByQuery(org2Client, org2Channel, chaincodeName, (String) expected.get("queryBvalue"));
            }

            /// Upgrading chaincode is really the same processes as the initial install. Any change requires a new sequence.
            /// Upgrading the actual code will need same chaincode name,  new chaincode package and version.
            /// Cases where running init is never needed include updating the endorsement policy, or adding collections.
            // For that no chaincode install is needed. As always a new sequence is needed and the same chaincode name, version and hash would be used
            // in the ApproveChaincodeDefinitionForMyOrg and commitChaincodeDefinition operations.
            // If chaincode has been committed by other organizations, to run own your own organization peers besides installing it
            //  also the ApproveChaincodeDefinitionForMyOrg operation is needed which in this case would use the same sequence number since there is
            // no actual change to the definition.

        } catch (Exception e) {
            out("Caught an exception running org1Channel %s", org1Channel.getName());
            e.printStackTrace();
            fail("Test failed with error : " + e.getMessage());
        }
    }

    private LifecycleChaincodePackage createLifecycleChaincodePackage(String chaincodeLabel, Type chaincodeType, String chaincodeSourceLocation, String chaincodePath, String metadadataSource) throws IOException, InvalidArgumentException {
        out("creating install package %s.", chaincodeLabel);

        Path metadataSourcePath = null;
        if (metadadataSource != null) {
            metadataSourcePath = Paths.get(metadadataSource);
        }
        LifecycleChaincodePackage lifecycleChaincodePackage = LifecycleChaincodePackage.fromSource(chaincodeLabel, Paths.get(chaincodeSourceLocation),
                chaincodeType,
                chaincodePath, metadataSourcePath);
        assertEquals(chaincodeLabel, lifecycleChaincodePackage.getLabel()); // what we expect ?
        assertEquals(chaincodeType, lifecycleChaincodePackage.getType());
        assertEquals(chaincodePath, lifecycleChaincodePackage.getPath());

        return lifecycleChaincodePackage;
    }

    private String lifecycleInstallChaincode(HFClient client, Collection<Peer> peers, LifecycleChaincodePackage lifecycleChaincodePackage) throws InvalidArgumentException, ProposalException, InvalidProtocolBufferException {

        int numInstallProposal = 0;

        numInstallProposal = numInstallProposal + peers.size();

        LifecycleInstallChaincodeRequest installProposalRequest = client.newLifecycleInstallChaincodeRequest();
        installProposalRequest.setLifecycleChaincodePackage(lifecycleChaincodePackage);
        installProposalRequest.setProposalWaitTime(DEPLOYWAITTIME);

        Collection<LifecycleInstallChaincodeProposalResponse> responses = client.sendLifecycleInstallChaincodeRequest(installProposalRequest, peers);
        assertNotNull(responses);

        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();
        String packageID = null;
        for (LifecycleInstallChaincodeProposalResponse response : responses) {
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                out("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successful.add(response);
                if (packageID == null) {
                    packageID = response.getPackageId();
                    assertNotNull(format("Hashcode came back as null from peer: %s ", response.getPeer()), packageID);
                } else {
                    assertEquals("Miss match on what the peers returned back as the packageID", packageID, response.getPackageId());
                }
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

        assertNotNull(packageID);
        assertFalse(packageID.isEmpty());

        return packageID;

    }

    CompletableFuture<TransactionEvent> lifecycleApproveChaincodeDefinitionForMyOrg(HFClient client, Channel channel,
                                                                                    Collection<Peer> peers, long sequence,
                                                                                    String chaincodeName, String chaincodeVersion, LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy, ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired, String org1ChaincodePackageID) throws InvalidArgumentException, ProposalException {

        LifecycleApproveChaincodeDefinitionForMyOrgRequest lifecycleApproveChaincodeDefinitionForMyOrgRequest = client.newLifecycleApproveChaincodeDefinitionForMyOrgRequest();
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setSequence(sequence);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeName(chaincodeName);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeVersion(chaincodeVersion);
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setInitRequired(initRequired);

        if (null != chaincodeCollectionConfiguration) {
            lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }

        if (null != chaincodeEndorsementPolicy) {
            lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }

        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setPackageId(org1ChaincodePackageID);

        Collection<LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse> lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse = channel.sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(lifecycleApproveChaincodeDefinitionForMyOrgRequest,
                peers);

        assertEquals(peers.size(), lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse.size());
        for (LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse response : lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse) {
            final Peer peer = response.getPeer();

            assertEquals(format("failure on %s  message is: %s", peer, response.getMessage()), ChaincodeResponse.Status.SUCCESS, response.getStatus());
            assertFalse(peer + " " + response.getMessage(), response.isInvalid());
            assertTrue(format("failure on %s", peer), response.isVerified());
        }

        return channel.sendTransaction(lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse);

    }

    private CompletableFuture<TransactionEvent> commitChaincodeDefinitionRequest(HFClient client, Channel channel, long definitionSequence, String chaincodeName, String chaincodeVersion,
                                                                                 LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                                                 ChaincodeCollectionConfiguration chaincodeCollectionConfiguration,
                                                                                 boolean initRequired, Collection<Peer> endorsingPeers) throws ProposalException, InvalidArgumentException, InterruptedException, ExecutionException, TimeoutException {
        LifecycleCommitChaincodeDefinitionRequest lifecycleCommitChaincodeDefinitionRequest = client.newLifecycleCommitChaincodeDefinitionRequest();

        lifecycleCommitChaincodeDefinitionRequest.setSequence(definitionSequence);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeName(chaincodeName);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }
        if (null != chaincodeCollectionConfiguration) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }
        lifecycleCommitChaincodeDefinitionRequest.setInitRequired(initRequired);

        Collection<LifecycleCommitChaincodeDefinitionProposalResponse> lifecycleCommitChaincodeDefinitionProposalResponses = channel.sendLifecycleCommitChaincodeDefinitionProposal(lifecycleCommitChaincodeDefinitionRequest,
                endorsingPeers);

        for (LifecycleCommitChaincodeDefinitionProposalResponse resp : lifecycleCommitChaincodeDefinitionProposalResponses) {

            final Peer peer = resp.getPeer();
            assertEquals(format("%s had unexpected status.", peer.toString()), ChaincodeResponse.Status.SUCCESS, resp.getStatus());
            assertTrue(format("%s not verified.", peer.toString()), resp.isVerified());
        }

        return channel.sendTransaction(lifecycleCommitChaincodeDefinitionProposalResponses);

    }

    // Lifecycle Queries to used to verify code...

    private void verifyByCheckCommitReadinessStatus(HFClient client, Channel channel, long definitionSequence, String chaincodeName,
                                                    String chaincodeVersion, LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                    ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired, Collection<Peer> org1MyPeers,
                                                    Set<String> expectedApproved, Set<String> expectedUnApproved) throws InvalidArgumentException, ProposalException {
        LifecycleCheckCommitReadinessRequest lifecycleCheckCommitReadinessRequest = client.newLifecycleSimulateCommitChaincodeDefinitionRequest();
        lifecycleCheckCommitReadinessRequest.setSequence(definitionSequence);
        lifecycleCheckCommitReadinessRequest.setChaincodeName(chaincodeName);
        lifecycleCheckCommitReadinessRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {
            lifecycleCheckCommitReadinessRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }
        if (null != chaincodeCollectionConfiguration) {
            lifecycleCheckCommitReadinessRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }
        lifecycleCheckCommitReadinessRequest.setInitRequired(initRequired);

        Collection<LifecycleCheckCommitReadinessProposalResponse> lifecycleSimulateCommitChaincodeDefinitionProposalResponse = channel.sendLifecycleCheckCommitReadinessRequest(lifecycleCheckCommitReadinessRequest, org1MyPeers);
        for (LifecycleCheckCommitReadinessProposalResponse resp : lifecycleSimulateCommitChaincodeDefinitionProposalResponse) {
            final Peer peer = resp.getPeer();
            assertEquals(ChaincodeResponse.Status.SUCCESS, resp.getStatus());
            assertEquals(format("Approved orgs failed on %s", peer), expectedApproved, resp.getApprovedOrgs());
            assertEquals(format("UnApproved orgs failed on %s", peer), expectedUnApproved, resp.getUnApprovedOrgs());
        }
    }

    private void verifyByQueryChaincodeDefinitions(HFClient client, Channel channel, Collection<Peer> peers, String expectChaincodeName) throws InvalidArgumentException, ProposalException {

        final LifecycleQueryChaincodeDefinitionsRequest request = client.newLifecycleQueryChaincodeDefinitionsRequest();

        Collection<LifecycleQueryChaincodeDefinitionsProposalResponse> proposalResponses = channel.lifecycleQueryChaincodeDefinitions(request, peers);
        for (LifecycleQueryChaincodeDefinitionsProposalResponse proposalResponse : proposalResponses) {
            Peer peer = proposalResponse.getPeer();

            assertEquals(ChaincodeResponse.Status.SUCCESS, proposalResponse.getStatus());
            Collection<LifecycleQueryChaincodeDefinitionsResult> chaincodeDefinitions = proposalResponse.getLifecycleQueryChaincodeDefinitionsResult();

            Optional<String> matchingName = chaincodeDefinitions.stream()
                    .map(LifecycleQueryChaincodeDefinitionsResult::getName)
                    .filter(Predicate.isEqual(expectChaincodeName))
                    .findAny();
            assertTrue(format("On peer %s return namespace for chaincode %s", peer, expectChaincodeName), matchingName.isPresent());
        }
    }

    private void verifyByQueryChaincodeDefinition(HFClient client, Channel channel, String chaincodeName, Collection<Peer> peers, long expectedSequence, boolean expectedInitRequired, byte[] expectedValidationParameter,
                                                ChaincodeCollectionConfiguration expectedChaincodeCollectionConfiguration) throws ProposalException, InvalidArgumentException, ChaincodeCollectionConfigurationException {

        final QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest = client.newQueryLifecycleQueryChaincodeDefinitionRequest();
        queryLifecycleQueryChaincodeDefinitionRequest.setChaincodeName(chaincodeName);

        Collection<LifecycleQueryChaincodeDefinitionProposalResponse> queryChaincodeDefinitionProposalResponses = channel.lifecycleQueryChaincodeDefinition(queryLifecycleQueryChaincodeDefinitionRequest, peers);

        assertNotNull(queryChaincodeDefinitionProposalResponses);
        assertEquals(peers.size(), queryChaincodeDefinitionProposalResponses.size());
        for (LifecycleQueryChaincodeDefinitionProposalResponse response : queryChaincodeDefinitionProposalResponses) {
            assertEquals(ChaincodeResponse.Status.SUCCESS, response.getStatus());
            assertEquals(expectedSequence, response.getSequence());
            if (expectedValidationParameter != null) {
                byte[] validationParameter = response.getValidationParameter();
                assertNotNull(validationParameter);
                assertArrayEquals(expectedValidationParameter, validationParameter);
            }

            if (null != expectedChaincodeCollectionConfiguration) {
                final ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = response.getChaincodeCollectionConfiguration();
                assertNotNull(chaincodeCollectionConfiguration);
                assertArrayEquals(expectedChaincodeCollectionConfiguration.getAsBytes(), chaincodeCollectionConfiguration.getAsBytes());
            }

            ChaincodeCollectionConfiguration collections = response.getChaincodeCollectionConfiguration();
            assertEquals(expectedInitRequired, response.getInitRequired());
            assertEquals(DEFAULT_ENDORSMENT_PLUGIN, response.getEndorsementPlugin());
            assertEquals(DEFAULT_VALDITATION_PLUGIN, response.getValidationPlugin());
        }
    }

    private void verifyByQueryInstalledChaincode(HFClient client, Collection<Peer> peers, String packageId, String expectedLabel) throws ProposalException, InvalidArgumentException {

        final LifecycleQueryInstalledChaincodeRequest lifecycleQueryInstalledChaincodeRequest = client.newLifecycleQueryInstalledChaincodeRequest();
        lifecycleQueryInstalledChaincodeRequest.setPackageID(packageId);

        Collection<LifecycleQueryInstalledChaincodeProposalResponse> responses = client.sendLifecycleQueryInstalledChaincode(lifecycleQueryInstalledChaincodeRequest, peers);
        assertNotNull(responses);
        assertEquals("responses not same as peers", peers.size(), responses.size());

        for (LifecycleQueryInstalledChaincodeProposalResponse response : responses) {
            assertEquals(ChaincodeResponse.Status.SUCCESS, response.getStatus());
            String peerName = response.getPeer().getName();
            assertEquals(format("Peer %s returned back bad status code", peerName), ChaincodeResponse.Status.SUCCESS, response.getStatus());
            assertEquals(format("Peer %s returned back different label", peerName), expectedLabel, response.getLabel());

        }
    }

    private void verifyByQueryInstalledChaincodes(HFClient client, Collection<Peer> peers, String excpectedChaincodeLabel, String excpectedPackageId) throws ProposalException, InvalidArgumentException {

        Collection<LifecycleQueryInstalledChaincodesProposalResponse> results = client.sendLifecycleQueryInstalledChaincodes(client.newLifecycleQueryInstalledChaincodesRequest(), peers);
        assertNotNull(results);
        assertEquals(peers.size(), results.size());

        for (LifecycleQueryInstalledChaincodesProposalResponse peerResults : results) {
            boolean found = false;
            final String peerName = peerResults.getPeer().getName();

            assertEquals(format("Peer returned back bad status %s", peerName), peerResults.getStatus(), ChaincodeResponse.Status.SUCCESS);

            for (LifecycleQueryInstalledChaincodesResult lifecycleQueryInstalledChaincodesResult : peerResults.getLifecycleQueryInstalledChaincodesResult()) {

                if (excpectedPackageId.equals(lifecycleQueryInstalledChaincodesResult.getPackageId())) {
                    assertEquals(format("Peer %s had chaincode lable mismatch", peerName), excpectedChaincodeLabel, lifecycleQueryInstalledChaincodesResult.getLabel());
                    found = true;
                    break;
                }

            }
            assertTrue(format("Chaincode label %s, packageId %s not found on peer %s ", excpectedChaincodeLabel, excpectedPackageId, peerName), found);

        }
        return;

    }

    private void verifyNoInstalledChaincodes(HFClient client, Collection<Peer> peers) throws ProposalException, InvalidArgumentException {

        Collection<LifecycleQueryInstalledChaincodesProposalResponse> results = client.sendLifecycleQueryInstalledChaincodes(client.newLifecycleQueryInstalledChaincodesRequest(), peers);
        assertNotNull(results);
        assertEquals(peers.size(), results.size());

        for (LifecycleQueryInstalledChaincodesProposalResponse result : results) {

            final String peerName = result.getPeer().getName();
            assertEquals(format("Peer returned back bad status %s", peerName), result.getStatus(), ChaincodeResponse.Status.SUCCESS);
            Collection<LifecycleQueryInstalledChaincodesResult> lifecycleQueryInstalledChaincodesResult = result.getLifecycleQueryInstalledChaincodesResult();
            assertNotNull(format("Peer %s returned back null result.", peerName), lifecycleQueryInstalledChaincodesResult);
            assertTrue(format("Peer %s returned back result with chaincode installed.", peerName), lifecycleQueryInstalledChaincodesResult.isEmpty());

        }

    }

    // Not new =================

    CompletableFuture<TransactionEvent> executeChaincode(HFClient client, User userContext, Channel channel, String fcn, Boolean doInit, String chaincodeName, Type chaincodeType, String... args) throws InvalidArgumentException, ProposalException {

        final ExecutionException[] executionExceptions = new ExecutionException[1];

        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();

        TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
        transactionProposalRequest.setChaincodeName(chaincodeName);
        transactionProposalRequest.setChaincodeLanguage(chaincodeType);
        transactionProposalRequest.setUserContext(userContext);

        transactionProposalRequest.setFcn(fcn);
        transactionProposalRequest.setProposalWaitTime(testConfig.getProposalWaitTime());
        transactionProposalRequest.setArgs(args);
        if (null != doInit) {
            transactionProposalRequest.setInit(doInit);
        }

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
            fail("Not enough endorsers for executeChaincode(move a,b,100):" + failed.size() + " endorser error: " +
                    firstTransactionProposalResponse.getMessage() +
                    ". Was verified: " + firstTransactionProposalResponse.isVerified());
        }
        out("Successfully received transaction proposal responses.");

        //  System.exit(10);

        ////////////////////////////
        // Send Transaction Transaction to orderer
        out("Sending chaincode transaction(move a,b,100) to orderer.");
        return channel.sendTransaction(successful);

    }

    void executeVerifyByQuery(HFClient client, Channel channel, String chaincodeName, String expect) throws ProposalException, InvalidArgumentException {
        out("Now query chaincode for the value of b.");
        QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
        queryByChaincodeRequest.setArgs("b");
        queryByChaincodeRequest.setFcn("query");
        queryByChaincodeRequest.setChaincodeName(chaincodeName);

        Collection<ProposalResponse> queryProposals = channel.queryByChaincode(queryByChaincodeRequest, channel.getPeers());
        for (ProposalResponse proposalResponse : queryProposals) {
            if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                fail("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                        ". Messages: " + proposalResponse.getMessage()
                        + ". Was verified : " + proposalResponse.isVerified());
            } else {
                String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                out("Query payload of b from peer %s returned %s", proposalResponse.getPeer().getName(), payload);
                assertEquals(expect, payload);
            }
        }

    }

    private Collection<Peer> addOtherOrgPeers(HFClient myClient, Channel myChannel, SampleOrg otherOrg) throws InvalidArgumentException {

        Collection<Peer> ret = new LinkedList<>();

        for (String peerName : otherOrg.getPeerNames()) {
            String peerLocation = otherOrg.getPeerLocation(peerName);

            Properties peerProperties = testConfig.getPeerProperties(peerName); //test properties for peer.. if any.
            if (peerProperties == null) {
                peerProperties = new Properties();
            }

            //Example of setting specific options on grpc's NettyChannelBuilder
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

            Peer peer = myClient.newPeer(peerName, peerLocation, peerProperties);

            ret.add(peer);

            myChannel.addPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.

        }

        return ret;

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

    Channel constructChannel(String name, HFClient client, SampleOrg myOrg, boolean createFabricChannel) throws Exception {
        ////////////////////////////
        //Construct the channel
        //

        out("Constructing channel %s", name);

        SampleUser peerAdmin = myOrg.getPeerAdmin();
        client.setUserContext(peerAdmin);

        Collection<Orderer> orderers = new LinkedList<>();

        for (String orderName : myOrg.getOrdererNames()) {

            Properties ordererProperties = testConfig.getOrdererProperties(orderName);

            //example of setting keepAlive to avoid timeouts on inactive http2 connections.
            // Under 5 minutes would require changes to server side to accept faster ping rates.
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[] {5L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[] {8L, TimeUnit.SECONDS});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[] {true});

            orderers.add(client.newOrderer(orderName, myOrg.getOrdererLocation(orderName),
                    ordererProperties));
        }

        //Just pick the first orderer in the list to create the channel.

        Orderer anOrderer = orderers.iterator().next();
        orderers.remove(anOrderer);

        String path = TEST_FIXTURES_PATH + "/sdkintegration/e2e-2Orgs/" + testConfig.getFabricConfigGenVers() + "/" + name + ".tx";
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(path));

        Channel newChannel = createFabricChannel ? client.newChannel(name, anOrderer, channelConfiguration, client.getChannelConfigurationSignature(channelConfiguration, peerAdmin)) :
                client.newChannel(name).addOrderer(anOrderer);

        out("Created channel %s", name);

        for (String peerName : myOrg.getPeerNames()) {
            String peerLocation = myOrg.getPeerLocation(peerName);

            Properties peerProperties = testConfig.getPeerProperties(peerName); //test properties for peer.. if any.
            if (peerProperties == null) {
                peerProperties = new Properties();
            }

            //Example of setting specific options on grpc's NettyChannelBuilder
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);

            Peer peer = client.newPeer(peerName, peerLocation, peerProperties);

            newChannel.joinPeer(peer, createPeerOptions().setPeerRoles(EnumSet.of(PeerRole.ENDORSING_PEER, PeerRole.LEDGER_QUERY, PeerRole.CHAINCODE_QUERY, PeerRole.EVENT_SOURCE))); //Default is all roles.

            out("Peer %s joined channel %s", peerName, name);
        }
        // Make sure there is one of each type peer at the very least.
        assertFalse(newChannel.getPeers(EnumSet.of(PeerRole.EVENT_SOURCE)).isEmpty());
        assertFalse(newChannel.getPeers(PeerRole.NO_EVENT_SOURCE).isEmpty());

        for (Orderer orderer : orderers) { //add remaining orderers if any.
            newChannel.addOrderer(orderer);
        }

        newChannel.initialize();
        return newChannel;

    }

}
