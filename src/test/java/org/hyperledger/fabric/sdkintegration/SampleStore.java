/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric.sdkintegration;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * A local file-based key value store.
 */
public class SampleStore {

    private String file;
    private Log logger = LogFactory.getLog(SampleStore.class);

    public SampleStore(File file) {

        this.file = file.getAbsolutePath();
    }

    /**
     * Get the value associated with name.
     *
     * @param name
     * @return value associated with the name
     */
    public String getValue(String name) {
        Properties properties = loadProperties();
        return properties.getProperty(name);
    }

    private Properties loadProperties() {
        Properties properties = new Properties();
        try (InputStream input = new FileInputStream(file)) {
            properties.load(input);
            input.close();
        } catch (FileNotFoundException e) {
            logger.warn(String.format("Could not find the file \"%s\"", file));
        } catch (IOException e) {
            logger.warn(String.format("Could not load keyvalue store from file \"%s\", reason:%s",
                    file, e.getMessage()));
        }

        return properties;
    }

    /**
     * Set the value associated with name.
     *
     * @param name  The name of the parameter
     * @param value Value for the parameter
     */
    public void setValue(String name, String value) {
        Properties properties = loadProperties();
        try (
                OutputStream output = new FileOutputStream(file)
        ) {
            properties.setProperty(name, value);
            properties.store(output, "");
            output.close();

        } catch (IOException e) {
            logger.warn(String.format("Could not save the keyvalue store, reason:%s", e.getMessage()));
        }
    }
    private final Map<String, SampleUser> members = new HashMap<>();
    /**
     * Get the user with a given name
     *
     * @return user
     */
    public SampleUser getMember(String name, String org) {

        // Try to get the SampleUser state from the cache
        SampleUser sampleUser = members.get(SampleUser.toKeyValStoreName(name, org));
        if (null != sampleUser) return sampleUser;

        // Create the SampleUser and try to restore it's state from the key value store (if found).
        sampleUser = new SampleUser(name, org, this);

        return sampleUser;

    }


}