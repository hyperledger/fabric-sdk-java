/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
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

package org.hyperledger.fabric.sdk;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A local file-based key value store.
 * This implements the KeyValStore interface.
 */
public class FileKeyValStore implements KeyValStore {

    private String file;
    private Log logger = LogFactory.getLog(FileKeyValStore.class);

    public FileKeyValStore(String file) {
    	this.file = file;
    }

    /**
     * Get the value associated with name.
     * @param name
     * @return value associated with the name
     */
    public String getValue(String name) {
	    	Properties properties = loadProperties();
	    	return properties.getProperty(name);
    }

    private Properties loadProperties() {
    	Properties properties = new Properties();
    	try ( InputStream input = new FileInputStream(file)) {
	    	properties.load(input);
	    	input.close();
    	} catch(FileNotFoundException e) {
    		logger.warn(String.format("Could not find the file \"%s\"", file));
    	} catch(IOException e) {
    		logger.warn(String.format("Could not load keyvalue store from file \"%s\", reason:%s", 
    				file, e.getMessage()));
    	}

    	return properties;
    }

    /**
     * Set the value associated with name.
     * @param name
     * @param value
     */
    public void setValue(String name, String value) {
    	Properties properties = loadProperties();
    	try (
    	    	OutputStream output = new FileOutputStream(file)
        ) {
    	    	properties.setProperty(name, value);
    	    	properties.store(output, "");
    	    	output.close();

        	} catch(IOException e) {
        		logger.warn(String.format("Could not save the keyvalue store, reason:%s", e.getMessage()));
        	}
    }

}