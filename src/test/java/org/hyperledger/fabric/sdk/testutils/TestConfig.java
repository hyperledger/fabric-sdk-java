/*
 *  Copyright 2016, 2017 IBM, DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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
package org.hyperledger.fabric.sdk.testutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdkintegration.SampleOrg;

/**
 * Config allows for a global config of the toolkit. Central location for all
 * toolkit configuration defaults. Has a local config file that can override any
 * property defaults. Config file can be relocated via a system property
 * "org.hyperledger.fabric.sdk.configuration". Any property can be overridden
 * with environment variable and then overridden
 * with a java system property. Property hierarchy goes System property
 * overrides environment variable which overrides config file for default values specified here.
 */

public class TestConfig {
    private static final Log logger = LogFactory.getLog(TestConfig.class);

    private static final String DEFAULT_CONFIG = "src/test/java/org/hyperledger/fabric/sdk/testutils.properties";
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.hyperledger.fabric.sdktest.configuration";

    private static final String PROPBASE = "org.hyperledger.fabric.sdktest.";

    private static final String GOSSIPWAITTIME = PROPBASE + "GossipWaitTime";
    private static final String INVOKEWAITTIME = PROPBASE + "InvokeWaitTime";
    private static final String DEPLOYWAITTIME = PROPBASE + "DeployWaitTime";
    private static final String INTEGRATIONTESTSMSPIDS = PROPBASE + "integrationTests.mspids";
    private static final String INTEGRATIONTESTS_ORG = PROPBASE + "integrationTests.org.";
    private static final String INTEGRATIONTESTPEERS = PROPBASE + "integrationTests.peers";
    private static final String INTEGRATIONTESTSORDERERS = PROPBASE + "integrationTests.orderers";
    private static final String INTEGRATIONTESTSEVENTHUBS = PROPBASE + "integrationTests.eventhubs";
    private static final String INTEGRATIONTESTSFABRICCA = PROPBASE + "integrationTests.fabric_ca";
    private static final  Pattern orgPat = Pattern.compile("^" + Pattern.quote(INTEGRATIONTESTS_ORG) + "([^\\.]+)\\.mspid$");


    private static TestConfig config;
    private final static Properties sdkProperties = new Properties();
    private final static HashMap<String, SampleOrg> sampleOrgs = new HashMap<>();

    private TestConfig() {
        File loadFile;
        FileInputStream configProps;


        try {
            loadFile = new File(System.getProperty(ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION, DEFAULT_CONFIG))
                    .getAbsoluteFile();
            logger.debug(String.format("Loading configuration from %s and it is present: %b", loadFile.toString(),
                    loadFile.exists()));
            configProps = new FileInputStream(loadFile);
            sdkProperties.load(configProps);

        } catch (IOException e) { // if not there no worries just use defaults
//            logger.warn(String.format("Failed to load any test configuration from: %s. Using toolkit defaults",
//                    DEFAULT_CONFIG));
        } finally {

            // Default values

            defaultProperty(GOSSIPWAITTIME, "5000");
            defaultProperty(INVOKEWAITTIME, "100000");
            defaultProperty(DEPLOYWAITTIME, "120000");

            //////
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.mspid", "Org1MSP");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.ca_location", "http://localhost:7054");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.peer_locations", "peer0@grpc://localhost:7051, peer1@grpc://localhost:7056");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.orderer_locations", "orderer0@grpc://localhost:7050");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.eventhub_locations", "eventhub1@grpc://localhost:7053");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.mspid", "Org2MSP");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.ca_location", "http://localhost:8054");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.peer_locations", "peer2@grpc://localhost:8051,peer3@grpc://localhost:8056");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.orderer_locations", "orderer0@grpc://localhost:7050");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.eventhub_locations", "eventhub1@grpc://localhost:8053");



            for (Map.Entry<Object, Object> x : sdkProperties.entrySet()) {
                String key = x.getKey() + "";
                String val = x.getValue() + "";


                if (key.startsWith(INTEGRATIONTESTS_ORG)) {

                    Matcher match = orgPat.matcher(key);


                    if (match.matches() &&match.groupCount() == 1) {
                        String orgname = match.group(1).trim();
                        sampleOrgs.put(orgname, new SampleOrg(orgname, val.trim()));

                    }

                }

            }

            for( Map.Entry<String, SampleOrg> org : sampleOrgs.entrySet()){
                final SampleOrg sampleOrg = org.getValue();

                String peerNames=  sdkProperties.getProperty(INTEGRATIONTESTS_ORG + org.getKey() + ".peer_locations");
                String[] ps = peerNames.split("[ \t]*,[ \t]*");
                for( String peer : ps){
                    String[] nl = peer.split("[ \t]*@[ \t]*");
                    sampleOrg.addPeerLocation(nl[0], nl[1]);
                }


                String ordererNames=  sdkProperties.getProperty(INTEGRATIONTESTS_ORG + org.getKey() + ".orderer_locations");
                ps = ordererNames.split("[ \t]*,[ \t]*");
                for( String peer : ps){
                    String[] nl = peer.split("[ \t]*@[ \t]*");
                    sampleOrg.addOrdererLocation(nl[0], nl[1]);
                }

                String eventHubNames=  sdkProperties.getProperty(INTEGRATIONTESTS_ORG + org.getKey() + ".eventhub_locations");
                ps = eventHubNames.split("[ \t]*,[ \t]*");
                for( String peer : ps){
                    String[] nl = peer.split("[ \t]*@[ \t]*");
                    sampleOrg.addEventHubLocation(nl[0], nl[1]);
                }

                sampleOrg.setCALocation( sdkProperties.getProperty(INTEGRATIONTESTS_ORG + org.getKey() + ".ca_location"));

            }

        }

    }

    /**
     * getConfig return back singleton for SDK configuration.
     *
     * @return Global configuration
     */
    public static TestConfig getConfig() {
        if (null == config) {
            config = new TestConfig();
        }
        return config;

    }

    /**
     * getProperty return back property for the given value.
     *
     * @param property
     * @return String value for the property
     */
    private String getProperty(String property) {

        String ret = sdkProperties.getProperty(property);

        if (null == ret) {
            logger.warn(String.format("No configuration value found for '%s'", property));
        }
        return ret;
    }

    /**
     * getProperty returns the value for given property key. If not found, it
     * will set the property to defaultValue
     *
     * @param property
     * @param defaultValue
     * @return property value as a String
     */
    private String getProperty(String property, String defaultValue) {

        return sdkProperties.getProperty(property, defaultValue);
    }

    static private void defaultProperty(String key, String value) {


        String ret = System.getProperty(key);
        if (ret != null) {
            sdkProperties.put(key, ret);
        } else {
            String envKey = key.toUpperCase().replaceAll("\\.", "_");
            ret = System.getenv(envKey);
            if (null != ret) {
                sdkProperties.put(key, ret);
            } else {
                if (null == sdkProperties.getProperty(key)) {
                    sdkProperties.put(key, value);
                }

            }

        }
    }

    public int getInvokeWaitTime() {
        return Integer.parseInt(getProperty(INVOKEWAITTIME));
    }

    public int getDeployWaitTime() {
        return Integer.parseInt(getProperty(DEPLOYWAITTIME));
    }

    public String getIntegrationTestsMSPIDs() {
        return getProperty(INTEGRATIONTESTSMSPIDS);
    }

    public String getIntegrationTestsPeers() {
        return getProperty(INTEGRATIONTESTPEERS);
    }

    public String getIntegrationTestsOrderers() {
        return getProperty(INTEGRATIONTESTSORDERERS);
    }

    public String getIntegrationtestsEventhubs() {
        return getProperty(INTEGRATIONTESTSEVENTHUBS);
    }

    public String getIntegrationtestsFabricCA() {
        return getProperty(INTEGRATIONTESTSFABRICCA);
    }

    public int getGossipWaitTime() {
        return Integer.parseInt(getProperty(GOSSIPWAITTIME));
    }

    public Collection<SampleOrg>  getIntegrationTestsSampleOrgs(){
        return Collections.unmodifiableCollection(sampleOrgs.values());
    }

    public SampleOrg getIntegrationTestsSampleOrg(String name) {
        return sampleOrgs.get(name);

    }
}
