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

package org.hyperledger.fabric.sdk;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

/**
 * A wrapper for the Hyperledger Channel configuration
 */
public class ChannelConfiguration {
    private byte[] configBytes = null;

    /**
     * The null constructor for the ChannelConfiguration wrapper. You will
     * need to use the {@link #setChannelConfiguration(byte[])} method to
     * populate the channel configuration
     */
    public ChannelConfiguration() {
    }

    /**
     * constructs a ChannelConfiguration object with the actual configuration gotten from the file system
     *
     * @param configFile The file containing the channel configuration.
     * @throws IOException
     */
    public ChannelConfiguration(File configFile) throws IOException {
        InputStream is = new FileInputStream(configFile);
        configBytes = IOUtils.toByteArray(is);
    }

    /**
     * constructs a ChannelConfiguration object
     *
     * @param configAsBytes the byte array containing the serialized channel configuration
     */
    public ChannelConfiguration(byte[] configAsBytes) {
        this.configBytes = configAsBytes;
    }

    /**
     * sets the ChannelConfiguration from a byte array
     *
     * @param channelConfigurationAsBytes the byte array containing the serialized channel configuration
     */
    public void setChannelConfiguration(byte[] channelConfigurationAsBytes) {
        this.configBytes = channelConfigurationAsBytes;
    }

    /**
     * @return the channel configuration serialized per protobuf and ready for inclusion into channel configuration
     */
    public byte[] getChannelConfigurationAsBytes() {
        return this.configBytes;
    }
}
