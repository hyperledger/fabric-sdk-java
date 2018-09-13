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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.toHexString;

/**
 * A wrapper for the Hyperledger Channel update configuration
 */
public class UpdateChannelConfiguration {
    private static final Log logger = LogFactory.getLog(UpdateChannelConfiguration.class);
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private byte[] configBytes = null;

    /**
     * The  constructor for the UpdateChannelConfiguration wrapper. You will
     * need to use the {@link Channel#updateChannelConfiguration(UpdateChannelConfiguration, byte[]...)} method to
     * populate the update channel configuration
     */
    public UpdateChannelConfiguration() {
    }

    /**
     * constructs a UpdateChannelConfiguration object with the actual configuration gotten from the file system
     *
     * @param configFile The file containing the channel configuration.
     * @throws IOException
     */
    public UpdateChannelConfiguration(File configFile) throws IOException, InvalidArgumentException {
        if (configFile == null) {
            throw new InvalidArgumentException("UpdateChannelConfiguration configFile must be non-null");
        }
        logger.trace(format("Creating UpdateChannelConfiguration from file %s", configFile.getAbsolutePath()));

        try (InputStream is = new FileInputStream(configFile)) {
            configBytes = IOUtils.toByteArray(is);
        }
    }

    /**
     * constructs a UpdateChannelConfiguration object
     *
     * @param configAsBytes the byte array containing the serialized channel configuration
     */
    public UpdateChannelConfiguration(byte[] configAsBytes) throws InvalidArgumentException {
        if (configAsBytes == null) {
            throw new InvalidArgumentException("UpdateChannelConfiguration configAsBytes must be non-null");
        }
        logger.trace("Creating UpdateChannelConfiguration from bytes");
        configBytes = configAsBytes;
    }

    /**
     * sets the UpdateChannelConfiguration from a byte array
     *
     * @param updateChannelConfigurationAsBytes the byte array containing the serialized channel configuration
     */
    public void setUpdateChannelConfiguration(byte[] updateChannelConfigurationAsBytes) throws InvalidArgumentException {
        if (updateChannelConfigurationAsBytes == null) {
            throw new InvalidArgumentException("UpdateChannelConfiguration updateChannelConfigurationAsBytes must be non-null");
        }
        logger.trace("Creating setUpdateChannelConfiguration from bytes");
        configBytes = updateChannelConfigurationAsBytes;
    }

    /**
     * @return the channel configuration serialized per protobuf and ready for inclusion into channel configuration
     */
    public byte[] getUpdateChannelConfigurationAsBytes() {
        if (configBytes == null) {
            logger.error("UpdateChannelConfiguration configBytes is null!");
        } else if (IS_TRACE_LEVEL) {
            logger.trace(format("getUpdateChannelConfigurationAsBytes: %s", toHexString(configBytes)));
        }
        return configBytes;
    }
}
