/*
 *  Copyright 2016, 2017 IBM, DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.log4j.Level;

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
    public static final String ORG_HYPERLEDGER_FABRIC_SDK_CONFIGURATION = "org.hyperledger.fabric.sdk.configuration";
    public static final String SECURITY_LEVEL = "org.hyperledger.fabric.sdk.security_level";
    public static final String HASH_ALGORITHM = "org.hyperledger.fabric.sdk.hash_algorithm";
    public static final String CACERTS = "org.hyperledger.fabric.sdk.cacerts";
    public static final String PROPOSAL_WAIT_TIME = "org.hyperledger.fabric.sdk.proposal.wait.time";
    public static final String CHANNEL_CONFIG_WAIT_TIME = "org.hyperledger.fabric.sdk.channelconfig.wait_time";
    public static final String ORDERER_RETRY_WAIT_TIME = "org.hyperledger.fabric.sdk.orderer_retry.wait_time";
    public static final String EVENTHUB_CONNECTION_WAIT_TIME = "org.hyperledger.fabric.sdk.eventhub_connection.wait_time";
    public static final String PROPOSAL_CONSISTENCY_VALIDATION = "org.hyperledger.fabric.sdk.proposal.consistency_validation";
    public static final String GENESISBLOCK_WAIT_TIME = "org.hyperledger.fabric.sdk.channel.genesisblock_wait_time";
    public static final String ASYMMETRIC_KEY_TYPE = "org.hyperledger.fabric.sdk.crypto.asymmetric_key_type";
    public static final String KEY_AGREEMENT_ALGORITHM = "org.hyperledger.fabric.sdk.crypto.key_agreement_algorithm";
    public static final String SYMMETRIC_KEY_TYPE = "org.hyperledger.fabric.sdk.crypto.symmetric_key_type";
    public static final String SYMMETRIC_KEY_BYTE_COUNT = "org.hyperledger.fabric.sdk.crypto.symmetric_key_byte_count";
    public static final String SYMMETRIC_ALGORITHM = "org.hyperledger.fabric.sdk.crypto.symmetric_algorithm";
    public static final String MAC_KEY_BYTE_COUNT = "org.hyperledger.fabric.sdk.crypto.mac_key_byte_count";
    public static final String CERTIFICATE_FORMAT = "org.hyperledger.fabric.sdk.crypto.certificate_format";
    public static final String SIGNATURE_ALGORITHM = "org.hyperledger.fabric.sdk.crypto.default_signature_algorithm";
    public static final String MAX_LOG_STRING_LENGTH = "org.hyperledger.fabric.sdk.log.stringlengthmax";
    public static final String EXTRALOGLEVEL = "org.hyperledger.fabric.sdk.log.extraloglevel";
    public static final String LOGGERLEVEL = "org.hyperledger.fabric.sdk.loglevel";  // ORG_HYPERLEDGER_FABRIC_SDK_LOGLEVEL=TRACE,DEBUG
    public static final String DIAGNOTISTIC_FILE_DIRECTORY = "org.hyperledger.fabric.sdk.diagnosticFileDir"; //ORG_HYPERLEDGER_FABRIC_SDK_DIAGNOSTICFILEDIR

    private static Config config;
    private static final Properties sdkProperties = new Properties();

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
            defaultProperty(ASYMMETRIC_KEY_TYPE, "EC");
            defaultProperty(KEY_AGREEMENT_ALGORITHM, "ECDH");
            defaultProperty(SYMMETRIC_KEY_TYPE, "AES");
            defaultProperty(SYMMETRIC_KEY_BYTE_COUNT, "32");
            defaultProperty(SYMMETRIC_ALGORITHM, "AES/CFB/NoPadding");
            defaultProperty(MAC_KEY_BYTE_COUNT, "32");
            defaultProperty(CERTIFICATE_FORMAT, "X.509");
            defaultProperty(SIGNATURE_ALGORITHM, "SHA256withECDSA");
            defaultProperty(SECURITY_LEVEL, "256");
            defaultProperty(HASH_ALGORITHM, "SHA2");
            defaultProperty(PROPOSAL_CONSISTENCY_VALIDATION, "true");
            // TODO remove this once we have implemented MSP and get the peer certs from the channel
            defaultProperty(CACERTS, "/genesisblock/peercacert.pem");

            defaultProperty(PROPOSAL_WAIT_TIME, "20000");
            defaultProperty(GENESISBLOCK_WAIT_TIME, "5000");
            defaultProperty(MAX_LOG_STRING_LENGTH, "64");
            defaultProperty(EXTRALOGLEVEL, "0");
            defaultProperty(LOGGERLEVEL, null);
            defaultProperty(DIAGNOTISTIC_FILE_DIRECTORY, null);
            defaultProperty(CHANNEL_CONFIG_WAIT_TIME, "10000");
            defaultProperty(ORDERER_RETRY_WAIT_TIME, "200");
            defaultProperty(EVENTHUB_CONNECTION_WAIT_TIME, "1000");

            final String inLogLevel = sdkProperties.getProperty(LOGGERLEVEL);

            if (null != inLogLevel) {

                org.apache.log4j.Level setTo = null;

                switch (inLogLevel) {

                    case "TRACE":
                        setTo = org.apache.log4j.Level.TRACE;
                        break;

                    case "DEBUG":
                        setTo = org.apache.log4j.Level.DEBUG;
                        break;

                    case "INFO":
                        setTo = Level.INFO;
                        break;

                    case "WARN":
                        setTo = Level.WARN;
                        break;

                    case "ERROR":
                        setTo = Level.ERROR;
                        break;

                    default:
                        setTo = Level.INFO;
                        break;

                }

                if (null != setTo) {
                    org.apache.log4j.Logger.getLogger("org.hyperledger.fabric").setLevel(setTo);
                }

            }

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

    /**
     * Get the configured security level. The value determines the elliptic curve used to generate keys.
     *
     * @return the security level.
     */
    public int getSecurityLevel() {

        return Integer.parseInt(getProperty(SECURITY_LEVEL));

    }

    /**
     * Get the name of the configured hash algorithm, used for digital signatures.
     *
     * @return the hash algorithm name.
     */
    public String getHashAlgorithm() {
        return getProperty(HASH_ALGORITHM);

    }

    public String[] getPeerCACerts() {
        return getProperty(CACERTS).split("'");
    }

    /**
     * Get the timeout for a single proposal request to endorser.
     *
     * @return the timeout in milliseconds.
     */
    public long getProposalWaitTime() {
        return Long.parseLong(getProperty(PROPOSAL_WAIT_TIME));
    }

    /**
     * Get the configured time to wait for genesis block.
     *
     * @return time in milliseconds.
     */
    public long getGenesisBlockWaitTime() {
        return Long.parseLong(getProperty(GENESISBLOCK_WAIT_TIME));
    }

    /**
     * Time to wait for channel to be configured.
     *
     * @return
     */
    public long getChannelConfigWaitTime() {
        return Long.parseLong(getProperty(CHANNEL_CONFIG_WAIT_TIME));
    }

    /**
     * Time to wait before retrying an operation.
     *
     * @return
     */
    public long getOrdererRetryWaitTime() {
        return Long.parseLong(getProperty(ORDERER_RETRY_WAIT_TIME));
    }

    public long getEventHubConnectionWaitTime() {
        return Long.parseLong(getProperty(EVENTHUB_CONNECTION_WAIT_TIME));
    }

    public String getAsymmetricKeyType() {
        return getProperty(ASYMMETRIC_KEY_TYPE);
    }

    public String getKeyAgreementAlgorithm() {
        return getProperty(KEY_AGREEMENT_ALGORITHM);
    }

    public String getSymmetricKeyType() {
        return getProperty(SYMMETRIC_KEY_TYPE);
    }

    public int getSymmetricKeyByteCount() {
        return Integer.parseInt(getProperty(SYMMETRIC_KEY_BYTE_COUNT));
    }

    public String getSymmetricAlgorithm() {
        return getProperty(SYMMETRIC_ALGORITHM);
    }

    public int getMACKeyByteCount() {
        return Integer.parseInt(getProperty(MAC_KEY_BYTE_COUNT));
    }

    public String getCertificateFormat() {
        return getProperty(CERTIFICATE_FORMAT);
    }

    public String getSignatureAlgorithm() {
        return getProperty(SIGNATURE_ALGORITHM);
    }

    public int maxLogStringLength() {
        return Integer.parseInt(getProperty(MAX_LOG_STRING_LENGTH));
    }

    /**
     * getProposalConsistencyValidation determine if validation of the proposals should
     * be done before sending to the orderer.
     *
     * @return if true proposals will be checked they are consistent with each other before sending to the Orderer
     */

    public boolean getProposalConsistencyValidation() {
        return Boolean.parseBoolean(getProperty(PROPOSAL_CONSISTENCY_VALIDATION));

    }

    public int extraLogLevel = -1;

    public boolean extraLogLevel(int val) {
        if (extraLogLevel == -1) {
            extraLogLevel = Integer.parseInt(getProperty(EXTRALOGLEVEL));
        }

        return val <= extraLogLevel;

    }

    DiagnosticFileDumper diagnosticFileDumper = null;

    /**
     * The directory where diagnostic dumps are to be place, null if none should be done.
     *
     * @return The directory where diagnostic dumps are to be place, null if none should be done.
     */

    public DiagnosticFileDumper getDiagnosticFileDumper() {

        if (diagnosticFileDumper != null) {
            return diagnosticFileDumper;
        }

        String dd = sdkProperties.getProperty(DIAGNOTISTIC_FILE_DIRECTORY);

        if (dd != null) {

            diagnosticFileDumper = DiagnosticFileDumper.configInstance(new File(dd));

        }

        return diagnosticFileDumper;
    }

}