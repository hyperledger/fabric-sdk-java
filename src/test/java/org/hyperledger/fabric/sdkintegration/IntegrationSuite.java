/*
 Copyright IBM Corp. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/
package org.hyperledger.fabric.sdkintegration;

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

    private static final String ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION
            = System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION") == null ? "2.0.0" : System.getenv("ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION");

    static Integer[] fabricVersion = new Integer[3];

    static Map<String, List<Class>> runmap = new HashMap<>();

    static {
        final String[] fvs = ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION.split("\\.");
        if (fvs.length != 3 && fvs.length != 2) {
            throw new AssertionError("Expected environment variable 'ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION' to be two or three numbers separated by dots (1.0.0)  but got: " + ORG_HYPERLEDGER_FABRIC_SDKTEST_VERSION);

        }
        fabricVersion[0] = Integer.parseInt(fvs[0].trim());
        fabricVersion[1] = Integer.parseInt(fvs[1].trim());
        if (fvs.length == 3) {
            fabricVersion[2] = Integer.parseInt(fvs[2].trim());
        }

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
        runmap.put("2.0", runmap.get("1.3"));

    }

    public static TestSuite suite() {
        TestSuite suite = new TestSuite();

        final String pluck = fabricVersion[0] + "." + fabricVersion[1];

        final List<Class> classes = runmap.get(pluck);
        if (classes == null || classes.isEmpty()) {
            throw new RuntimeException("Have no classes to run for Fabric version: " + pluck);
        }

        classes.forEach(aClass -> suite.addTest(new JUnit4TestAdapter(aClass)));

        return suite;
    }

    private void checkStyleWorkAround() {  //avoid utility class issue
    }

}