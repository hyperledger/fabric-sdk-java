/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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
package org.hyperledger.fabric.sdk;

import java.util.Properties;

import org.hyperledger.fabric.sdk.helper.Config;

/**
 * Container for methods to set SDK environment before running unit+integration tests
 *
 */
public class TestConfigHelper {

    public static final String CONFIG_OVERRIDES = "FABRICSDKOVERRIDES";

    /**
     * clearConfig "resets" Config so that the Config testcases can run without interference from other test suites.
     * Depending on what order JUnit decides to run the tests, Config could have been instantiated earlier and could
     * contain values that make the tests here fail.
     *
     * @throws SecurityException
     * @throws NoSuchFieldException
     * @throws IllegalAccessException
     * @throws IllegalArgumentException
     *
     */
    public void clearConfig()
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

        Config config = Config.getConfig();

        // Set the private static variable Config.config = null
        java.lang.reflect.Field configInstance = config.getClass().getDeclaredField("config");
        configInstance.setAccessible(true);
        configInstance.set(null, null);

        // Clear the sdkProperties map - Config.sdkProperties.clear()
        java.lang.reflect.Field sdkPropInstance = config.getClass().getDeclaredField("sdkProperties");
        sdkPropInstance.setAccessible(true);
        Properties sdkProperties = (Properties) sdkPropInstance.get(config);
        sdkProperties.clear();

    }

    /**
     * clearCaConfig "resets" Config used by fabric_ca so that the Config testcases can run without interference from
     * other test suites.
     *
     * @throws SecurityException
     * @throws NoSuchFieldException
     * @throws IllegalAccessException
     * @throws IllegalArgumentException
     *
     * @see #clearConfig()
     */
    public void clearCaConfig()
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

        org.hyperledger.fabric_ca.sdk.helper.Config config = org.hyperledger.fabric_ca.sdk.helper.Config.getConfig();

        // Set the private static variable Config.config = null
        java.lang.reflect.Field configInstance = config.getClass().getDeclaredField("config");
        configInstance.setAccessible(true);
        configInstance.set(null, null);

        // Clear the sdkProperties map - Config.sdkProperties.clear()
        java.lang.reflect.Field sdkPropInstance = config.getClass().getDeclaredField("sdkProperties");
        sdkPropInstance.setAccessible(true);
        Properties sdkProperties = (Properties) sdkPropInstance.get(config);
        sdkProperties.clear();

    }

    /**
     * customizeConfig() sets up the properties listed by env var CONFIG_OVERRIDES The value of the env var is
     * <i>property1=value1,property2=value2</i> and so on where each <i>property</i> is a property from the SDK's config
     * file.
     *
     * @throws NoSuchFieldException
     * @throws SecurityException
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     */
    public void customizeConfig()
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        String fabricSdkConfig = System.getenv(CONFIG_OVERRIDES);
        if (fabricSdkConfig != null && fabricSdkConfig.length() > 0) {
            String[] configs = fabricSdkConfig.split(",");
            String[] configKeyValue;
            for (String config : configs) {
                configKeyValue = config.split("=");
                if (configKeyValue != null && configKeyValue.length == 2) {
                    System.setProperty(configKeyValue[0], configKeyValue[1]);
                }
            }
        }
    }

}