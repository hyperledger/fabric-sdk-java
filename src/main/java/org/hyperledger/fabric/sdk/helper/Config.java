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
package org.hyperledger.fabric.sdk.helper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Config allows for a global config of the toolkit. Central location for all
 * toolkit configuration defaults. Has a local config file that can override any
 * property defaults. Config file can be relocated via a system property
 * "org.hyperledger.fabric.sdk.configuration". Any property can be overridden
 * with environment variable and then overridden
 * with a java system property. Property hierarchy goes System property
 * overrides environment variable which overrides config file for default values specified here.
 */

public class Config {
    private static final Log logger = LogFactory.getLog(Config.class);

    private static final String DEFAULT_CONFIG = "config.properties";
    private static final String ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.hyperledger.fabric.sdk.configuration";
    private static final String SECURITY_LEVEL = "org.hyperledger.fabric.sdk.security_level";
    private static final String HASH_ALGORITHM = "org.hyperledger.fabric.sdk.hash_algorithm";
    private static final String CACERTS = "org.hyperledger.fabric.sdk.cacerts";
    private static final String PROPOSAL_WAIT_TIME = "org.hyperledger.fabric.sdk.proposal.wait.time";
    private static Config config;
    private final static Properties sdkProperties = new Properties();

    private Config() {
        File loadFile;
        FileInputStream configProps;

        try {
            loadFile = new File(System.getProperty(ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION, DEFAULT_CONFIG))
                    .getAbsoluteFile();
            logger.debug(String.format("Loading configuration from %s and it is present: %b", loadFile.toString(),
                    loadFile.exists()));
            configProps = new FileInputStream(loadFile);
            sdkProperties.load(configProps);

        } catch (IOException e) {
            logger.warn(String.format("Failed to load any configuration from: %s. Using toolkit defaults",
                    DEFAULT_CONFIG));
        } finally {

            // Default values
            defaultProperty(SECURITY_LEVEL, "256");
            defaultProperty(HASH_ALGORITHM, "SHA2");
            // TODO remove this once we have implemented MSP and get the peer certs from the channel
            defaultProperty(CACERTS, "/genesisblock/peercacert.pem");
            defaultProperty(PROPOSAL_WAIT_TIME, "12000");

        }

    }

    /**
     * getConfig return back singleton for SDK configuration.
     *
     * @return Global configuration
     */
    public static Config getConfig() {
        if (null == config) {
            config = new Config();
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

    /**
     * Returns security level.
     *
     * @return
     */
    public int getSecurityLevel() {

        return Integer.parseInt(getProperty(SECURITY_LEVEL));

    }

    /**
     * Returns hash algorithm
     *
     * @return
     */
    public String getHashAlgorithm() {
        return getProperty(HASH_ALGORITHM);

    }

    public String[] getPeerCACerts() {
        return getProperty(CACERTS).split("'");
    }

    /**
     * Returns the timeout for a single proposal request to endorser in milliseconds.
     *
     * @return the timeout for a single proposal request to endorser in milliseconds
     */
    public long getProposalWaitTime() {
        return Long.parseLong(getProperty(PROPOSAL_WAIT_TIME));
    }
}