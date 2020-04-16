/*
 Copyright IBM Corp. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/
package org.hyperledger.fabric.sdkintegration;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.JUnit4TestAdapter;
import junit.framework.TestSuite;
import org.hyperledger.fabric_ca.sdkintegration.HFCAClientIT;
import org.junit.runner.RunWith;
import org.junit.runners.AllTests;

@RunWith (AllTests.class)
public class IntegrationSuite {
    public static final Path TEST_FIXTURE_PATH = Paths.get("src", "test", "fixture");

    private static final int fabricMajorVersion;
    private static final int fabricMinorVersion;
    private static final Map<String, List<Class>> runmap = new HashMap<>();
    private static final Path SDK_INTEGRATION_PATH = TEST_FIXTURE_PATH.resolve("sdkintegration");
    private static final Path GO_CHAINCODE_PATH = SDK_INTEGRATION_PATH.resolve("gocc");
    private static final Path NODE_CHAINCODE_PATH = SDK_INTEGRATION_PATH.resolve("nodecc");
    private static final Path JAVA_CHAINCODE_PATH = SDK_INTEGRATION_PATH.resolve("javacc");

    static {
        String sdkTestVersion = System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION");
        if (null == sdkTestVersion) {
            sdkTestVersion = "2.1";
        }
        final String[] fvs = sdkTestVersion.split("\\.");
        if (fvs.length < 2) {
            throw new AssertionError("Unexpected version format in 'ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION' environment variable: " + sdkTestVersion);
        }
        fabricMajorVersion = Integer.parseInt(fvs[0].trim());
        fabricMinorVersion = Integer.parseInt(fvs[1].trim());

        runmap.put("1.0", Arrays.asList(End2endIT.class, End2endAndBackAgainIT.class, HFCAClientIT.class));

        runmap.put("1.2", Arrays.asList(End2endIT.class, End2endAndBackAgainIT.class, UpdateChannelIT.class,
                NetworkConfigIT.class, End2endNodeIT.class, End2endAndBackAgainNodeIT.class,
                PrivateDataIT.class, ServiceDiscoveryIT.class,
                HFCAClientIT.class
        ));
        runmap.put("1.3", Arrays.asList(End2endIT.class, End2endAndBackAgainIT.class, UpdateChannelIT.class,
                NetworkConfigIT.class, End2endNodeIT.class, End2endJavaIT.class, End2endAndBackAgainNodeIT.class,
                End2endIdemixIT.class, PrivateDataIT.class, ServiceDiscoveryIT.class, HFCAClientIT.class));
        runmap.put("1.4", runmap.get("1.3"));

        runmap.put("2.1", Arrays.asList(End2endIT.class, End2endAndBackAgainIT.class, UpdateChannelIT.class,
                NetworkConfigIT.class, End2endNodeIT.class, End2endJavaIT.class, End2endAndBackAgainNodeIT.class,
                End2endIdemixIT.class, PrivateDataIT.class, End2endLifecycleIT.class, ServiceDiscoveryIT.class, HFCAClientIT.class));
    }

    public static TestSuite suite() {
        TestSuite suite = new TestSuite();

        final String fabricVersion = fabricMajorVersion + "." + fabricMinorVersion;

        final List<Class> classes = runmap.get(fabricVersion);
        if (classes == null || classes.isEmpty()) {
            throw new RuntimeException("Have no classes to run for Fabric version: " + fabricVersion);
        }

        classes.forEach(aClass -> suite.addTest(new JUnit4TestAdapter(aClass)));

        return suite;
    }

    public static Path getGoChaincodePath(String chaincodeName) {
        return GO_CHAINCODE_PATH.resolve(chaincodeName);
    }

    public static Path getNodeChaincodePath(String chaincodeName) {
        return NODE_CHAINCODE_PATH.resolve(chaincodeName);
    }

    public static Path getJavaChaincodePath(String chaincodeName) {
        final Path chaincodeRootPath;
        if (fabricMajorVersion == 1 && fabricMinorVersion == 4) {
            chaincodeRootPath = JAVA_CHAINCODE_PATH.resolve("1.4");
        } else if (fabricMajorVersion == 2) {
            chaincodeRootPath = JAVA_CHAINCODE_PATH.resolve("2.1");
        } else {
            throw new RuntimeException(String.format("Unexpected Fabric version for Java chaincode: %d.%d",
                    fabricMajorVersion, fabricMinorVersion));
        }

        return chaincodeRootPath.resolve(chaincodeName);
    }

    private void checkStyleWorkAround() {  //avoid utility class issue
    }

}