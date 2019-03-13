/*
 *  Copyright 2016, 2017 IBM, DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.helper.Utils;
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

/**
 * Test Configuration
 */

public class TestConfig {
    private static final Log logger = LogFactory.getLog(TestConfig.class);

    private static final String DEFAULT_CONFIG = "src/test/java/org/hyperledger/fabric/sdk/testutils.properties";
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.hyperledger.fabric.sdktest.configuration";
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST = "ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST";
    private static final String LOCALHOST = //Change test to reference another host .. easier config for my testing on Windows !
            System.getenv(ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST) == null ? "localhost" : System.getenv(ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST);

    private static final String PROPBASE = "org.hyperledger.fabric.sdktest.";

    private static final String INVOKEWAITTIME = PROPBASE + "InvokeWaitTime";
    private static final String DEPLOYWAITTIME = PROPBASE + "DeployWaitTime";
    private static final String PROPOSALWAITTIME = PROPBASE + "ProposalWaitTime";
    private static final String RUNIDEMIXMTTEST = PROPBASE + "RunIdemixMTTest";  // org.hyperledger.fabric.sdktest.RunIdemixMTTest ORG_HYPERLEDGER_FABRIC_SDKTEST_RUNIDEMIXMTTEST
    private static final String RUNSERVICEDISCOVERYIT = PROPBASE + "runServiceDiscoveryIT";  // org.hyperledger.fabric.sdktest.RunIdemixMTTest ORG_HYPERLEDGER_FABRIC_SDKTEST_RUNIDEMIXMTTEST

    private static final String INTEGRATIONTESTS_ORG = PROPBASE + "integrationTests.org.";

    private static final Pattern orgPat = Pattern.compile("^" + Pattern.quote(INTEGRATIONTESTS_ORG) + "([^\\.]+)\\.mspid$");

    private static final String INTEGRATIONTESTSTLS = PROPBASE + "integrationtests.tls";
    // location switching between fabric cryptogen and configtxgen artifacts for v1.0 and v1.1 in src/test/fixture/sdkintegration/e2e-2Orgs
    private String FAB_CONFIG_GEN_VERS;
    //   Objects.equals(System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION"), "1.0.0") ? "v1.0" : "v1.3";

    private static TestConfig config;
    private static final Properties sdkProperties = new Properties();
    private final boolean runningTLS;
    private final boolean runningFabricCATLS;

    public boolean isRunningFabricTLS() {
        return runningFabricTLS;
    }

    private final boolean runningFabricTLS;
    private final HashMap<String, SampleOrg> sampleOrgs = new HashMap<>();

    private static final String ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION
            = System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION") == null ? "2.0.0" : System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION");

    int[] fabricVersion = new int[3];

    private TestConfig() {

        final String[] fvs = ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION.split("\\.");
        if (fvs.length != 3 && fvs.length != 2) {
            throw new AssertionError("Expected environment variable 'ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION' to be two or three numbers separated by dots (1.0.0)  but got: " + ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION);

        }
        fabricVersion[0] = Integer.parseInt(fvs[0].trim());
        fabricVersion[1] = Integer.parseInt(fvs[1].trim());
        if (fvs.length == 3) {
            fabricVersion[2] = Integer.parseInt(fvs[2].trim());
        }

        FAB_CONFIG_GEN_VERS = "v" + fabricVersion[0] + "." + fabricVersion[1];
        if (FAB_CONFIG_GEN_VERS.equalsIgnoreCase("v1.4") || FAB_CONFIG_GEN_VERS.equalsIgnoreCase("v2.0")) { //TODO REMOVE WHEN WE GET A V2.0 GEN
            FAB_CONFIG_GEN_VERS = "v1.3";
        }

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

            defaultProperty(INVOKEWAITTIME, "32000");
            defaultProperty(DEPLOYWAITTIME, "120000");
            defaultProperty(PROPOSALWAITTIME, "120000");
            defaultProperty(RUNIDEMIXMTTEST, "false");
            defaultProperty(RUNSERVICEDISCOVERYIT, "false");

            //////
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.mspid", "Org1MSP");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.domname", "org1.example.com");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.ca_location", "http://" + LOCALHOST + ":7054");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.caName", "ca0");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.peer_locations", "peer0.org1.example.com@grpc://" + LOCALHOST + ":7051, peer1.org1.example.com@grpc://" + LOCALHOST + ":7056");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg1.orderer_locations", "orderer.example.com@grpc://" + LOCALHOST + ":7050");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.mspid", "Org2MSP");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.domname", "org2.example.com");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.ca_location", "http://" + LOCALHOST + ":8054");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.peer_locations", "peer0.org2.example.com@grpc://" + LOCALHOST + ":8051,peer1.org2.example.com@grpc://" + LOCALHOST + ":8056");
            defaultProperty(INTEGRATIONTESTS_ORG + "peerOrg2.orderer_locations", "orderer.example.com@grpc://" + LOCALHOST + ":7050");

            defaultProperty(INTEGRATIONTESTSTLS, null);
            runningTLS = null != sdkProperties.getProperty(INTEGRATIONTESTSTLS, null);
            runningFabricCATLS = runningTLS;
            runningFabricTLS = runningTLS;

            for (Map.Entry<Object, Object> x : sdkProperties.entrySet()) {
                final String key = x.getKey() + "";
                final String val = x.getValue() + "";

                if (key.startsWith(INTEGRATIONTESTS_ORG)) {

                    Matcher match = orgPat.matcher(key);

                    if (match.matches() && match.groupCount() == 1) {
                        String orgName = match.group(1).trim();
                        sampleOrgs.put(orgName, new SampleOrg(orgName, val.trim()));

                    }
                }
            }

            for (Map.Entry<String, SampleOrg> org : sampleOrgs.entrySet()) {
                final SampleOrg sampleOrg = org.getValue();
                final String orgName = org.getKey();

                String peerNames = sdkProperties.getProperty(INTEGRATIONTESTS_ORG + orgName + ".peer_locations");
                String[] ps = peerNames.split("[ \t]*,[ \t]*");
                for (String peer : ps) {
                    String[] nl = peer.split("[ \t]*@[ \t]*");
                    sampleOrg.addPeerLocation(nl[0], grpcTLSify(nl[1]));
                }

                final String domainName = sdkProperties.getProperty(INTEGRATIONTESTS_ORG + orgName + ".domname");

                sampleOrg.setDomainName(domainName);

                String ordererNames = sdkProperties.getProperty(INTEGRATIONTESTS_ORG + orgName + ".orderer_locations");
                ps = ordererNames.split("[ \t]*,[ \t]*");
                for (String peer : ps) {
                    String[] nl = peer.split("[ \t]*@[ \t]*");
                    sampleOrg.addOrdererLocation(nl[0], grpcTLSify(nl[1]));
                }

                sampleOrg.setCALocation(httpTLSify(sdkProperties.getProperty((INTEGRATIONTESTS_ORG + org.getKey() + ".ca_location"))));

                sampleOrg.setCAName(sdkProperties.getProperty((INTEGRATIONTESTS_ORG + org.getKey() + ".caName")));

                if (runningFabricCATLS) {
                    String cert = "src/test/fixture/sdkintegration/e2e-2Orgs/FAB_CONFIG_GEN_VERS/crypto-config/peerOrganizations/DNAME/ca/ca.DNAME-cert.pem"
                            .replaceAll("DNAME", domainName).replaceAll("FAB_CONFIG_GEN_VERS", FAB_CONFIG_GEN_VERS);
                    File cf = new File(cert);
                    if (!cf.exists() || !cf.isFile()) {
                        throw new RuntimeException("TEST is missing cert file " + cf.getAbsolutePath());
                    }
                    Properties properties = new Properties();
                    properties.setProperty("pemFile", cf.getAbsolutePath());

                    properties.setProperty("allowAllHostNames", "true"); //testing environment only NOT FOR PRODUCTION!

                    sampleOrg.setCAProperties(properties);
                }

                //FIX Node chaincode to reference chaincode shim package according to fabric version.

                String ncCv = 2 == fabricVersion[0] ? "\"unstable\"" : String.format("\"~%d.%d.0\"", fabricVersion[0], fabricVersion[1]);

                try {
                    List<Path> collect = null;
                    try (Stream<Path> filess = Files.walk(Paths.get("src/test/fixture/sdkintegration/nodecc"))) {
                        collect = filess.filter(f -> f.getFileName().toString().equals("package.json.TEMPLATE"))
                                .collect(Collectors.toList());
                    }

                    for (Path jspf : collect) {
                        String jpff = new String(Files.readAllBytes(jspf)).replaceAll(Pattern.quote("${1}"), ncCv).replaceAll("(?m)^#.*$\n", "");
                        Path pkgjson = Paths.get(jspf.getParent().toFile().getAbsolutePath(), "package.json");
                        pkgjson.toFile().deleteOnExit();
                        Files.write(pkgjson, jpff.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                    }

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            }

        }

    }

    public String getFabricConfigGenVers() {
        return FAB_CONFIG_GEN_VERS;
    }

    public boolean isFabricVersionAtOrAfter(String version) {

        final int[] vers = parseVersion(version);
        for (int i = 0; i < 3; ++i) {
            if (vers[i] < fabricVersion[i]) {
                return true;
            } else if (vers[i] > fabricVersion[i]) {
                return false;

            }
        }
        return vers[2] == fabricVersion[2];
    }

    public boolean isFabricVersionBefore(String version) {

        return !isFabricVersionAtOrAfter(version);
    }

    /**
     * Service discovery needs enteries in et/hosts to resolve names to run successfully.
     * By default turn off.
     *
     * @return true to run service discovery integration test.
     */

    public boolean runServiceDiscoveryIT() {
        return Objects.equals("true", sdkProperties.get(RUNSERVICEDISCOVERYIT));
    }

    private static int[] parseVersion(String version) {
        if (null == version || version.isEmpty()) {
            throw new AssertionError("Version is bad :" + version);
        }
        String[] split = version.split("[ \\t]*\\.[ \\t]*");
        if (split.length < 1 || split.length > 3) {
            throw new AssertionError("Version is bad :" + version);
        }
        int[] ret = new int[3];
        int i = 0;
        for (; i < split.length; ++i) {
            ret[i] = Integer.parseInt(split[i]);
        }
        for (; i < 3; ++i) {
            ret[i] = 0;
        }
        return ret;

    }

    private String grpcTLSify(String location) {
        location = location.trim();
        Exception e = Utils.checkGrpcUrl(location);
        if (e != null) {
            throw new RuntimeException(String.format("Bad TEST parameters for grpc url %s", location), e);
        }
        return runningFabricTLS ?
                location.replaceFirst("^grpc://", "grpcs://") : location;

    }

    private String httpTLSify(String location) {
        location = location.trim();

        return runningFabricCATLS ?
                location.replaceFirst("^http://", "https://") : location;
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

    public void destroy() {
        // config.sampleOrgs = null;
        config = null;

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

    private static void defaultProperty(String key, String value) {

        String ret = System.getProperty(key);
        if (ret != null) {
            sdkProperties.put(key, ret);
        } else {
            String envKey = key.toUpperCase().replaceAll("\\.", "_");
            ret = System.getenv(envKey);
            if (null != ret) {
                sdkProperties.put(key, ret);
            } else {
                if (null == sdkProperties.getProperty(key) && value != null) {
                    sdkProperties.put(key, value);
                }

            }

        }
    }

    public int getTransactionWaitTime() {
        return Integer.parseInt(getProperty(INVOKEWAITTIME));
    }

    public int getDeployWaitTime() {
        return Integer.parseInt(getProperty(DEPLOYWAITTIME));
    }

    public long getProposalWaitTime() {
        return Integer.parseInt(getProperty(PROPOSALWAITTIME));
    }

    public boolean getRunIdemixMTTest() {
        return Boolean.valueOf(getProperty(RUNIDEMIXMTTEST));
    }

    public Collection<SampleOrg> getIntegrationTestsSampleOrgs() {
        return Collections.unmodifiableCollection(sampleOrgs.values());
    }

    public SampleOrg getIntegrationTestsSampleOrg(String name) {
        return sampleOrgs.get(name);

    }

    public Properties getPeerProperties(String name) {

        return getEndPointProperties("peer", name);

    }

    public Properties getOrdererProperties(String name) {

        return getEndPointProperties("orderer", name);

    }

    public Properties getEndPointProperties(final String type, final String name) {
        Properties ret = new Properties();

        final String domainName = getDomainName(name);

        File cert = Paths.get(getTestChannelPath(), "crypto-config/ordererOrganizations".replace("orderer", type), domainName, type + "s",
                name, "tls/server.crt").toFile();
        if (!cert.exists()) {
            throw new RuntimeException(String.format("Missing cert file for: %s. Could not find at location: %s", name,
                    cert.getAbsolutePath()));
        }

        if (!isRunningAgainstFabric10()) {
            File clientCert;
            File clientKey;
            if ("orderer".equals(type)) {
                clientCert = Paths.get(getTestChannelPath(), "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.crt").toFile();

                clientKey = Paths.get(getTestChannelPath(), "crypto-config/ordererOrganizations/example.com/users/Admin@example.com/tls/client.key").toFile();
            } else {
                clientCert = Paths.get(getTestChannelPath(), "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.crt").toFile();
                clientKey = Paths.get(getTestChannelPath(), "crypto-config/peerOrganizations/", domainName, "users/User1@" + domainName, "tls/client.key").toFile();
            }

            if (!clientCert.exists()) {
                throw new RuntimeException(String.format("Missing  client cert file for: %s. Could not find at location: %s", name,
                        clientCert.getAbsolutePath()));
            }

            if (!clientKey.exists()) {
                throw new RuntimeException(String.format("Missing  client key file for: %s. Could not find at location: %s", name,
                        clientKey.getAbsolutePath()));
            }
            ret.setProperty("clientCertFile", clientCert.getAbsolutePath());
            ret.setProperty("clientKeyFile", clientKey.getAbsolutePath());
        }

        ret.setProperty("pemFile", cert.getAbsolutePath());

        ret.setProperty("hostnameOverride", name);
        ret.setProperty("sslProvider", "openSSL");
        ret.setProperty("negotiationType", "TLS");

        return ret;
    }

    public String getTestChannelPath() {

        return "src/test/fixture/sdkintegration/e2e-2Orgs/" + FAB_CONFIG_GEN_VERS;

    }

    public boolean isRunningAgainstFabric10() {
        return isFabricVersionBefore("1.1");
    }

    /**
     * url location of configtxlator
     *
     * @return
     */

    public String getFabricConfigTxLaterLocation() {
        return "http://" + LOCALHOST + ":7059";
    }

    /**
     * Returns the appropriate Network Config YAML file based on whether TLS is currently
     * enabled or not
     *
     * @return The appropriate Network Config YAML file
     */
    public File getTestNetworkConfigFileYAML() {
        String fname = runningTLS ? "network-config-tls.yaml" : "network-config.yaml";
        String pname = "src/test/fixture/sdkintegration/network_configs/";
        File ret = new File(pname, fname);

        if (!"localhost".equals(LOCALHOST) || isFabricVersionAtOrAfter("1.3")) {
            // change on the fly ...
            File temp = null;

            try {
                //create a temp file
                temp = File.createTempFile(fname, "-FixedUp.yaml");

                if (temp.exists()) { //For testing start fresh
                    temp.delete();
                }

                byte[] data = Files.readAllBytes(Paths.get(ret.getAbsolutePath()));

                String sourceText = new String(data, StandardCharsets.UTF_8);

                sourceText = sourceText.replaceAll("https://localhost", "https://" + LOCALHOST);
                sourceText = sourceText.replaceAll("http://localhost", "http://" + LOCALHOST);
                sourceText = sourceText.replaceAll("grpcs://localhost", "grpcs://" + LOCALHOST);
                sourceText = sourceText.replaceAll("grpc://localhost", "grpc://" + LOCALHOST);

                Files.write(Paths.get(temp.getAbsolutePath()), sourceText.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);

                if (!Objects.equals("true", System.getenv(ORG_HYPERLEDGER_FABRIC_SDK_TEST_FABRIC_HOST + "_KEEP"))) {
                    temp.deleteOnExit();
                } else {
                    System.err.println("produced new network-config.yaml file at:" + temp.getAbsolutePath());
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ret = temp;
        }

        return ret;
    }

    private String getDomainName(final String name) {
        int dot = name.indexOf(".");
        if (-1 == dot) {
            return null;
        } else {
            return name.substring(dot + 1);
        }

    }

    public static void main(String[] ars) {

        final TestConfig config = getConfig();
        final boolean runningAgainstFabric10 = config.isRunningAgainstFabric10();

        System.out.println(runningAgainstFabric10);
    }

}
