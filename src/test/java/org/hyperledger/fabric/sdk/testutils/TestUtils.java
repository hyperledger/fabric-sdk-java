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

package org.hyperledger.fabric.sdk.testutils;

import java.lang.reflect.Field;
import java.util.Properties;

import org.hyperledger.fabric.sdk.helper.Config;

public class TestUtils {

    private TestUtils() {
    }

    /**
     * Sets the value of a field on an object
     *
     * @param o The object that contains the field
     * @param fieldName The name of the field
     * @param value The new value
     * @return The previous value of the field
     */
    public static Object setField(Object o, String fieldName, Object value) {
        Object oldVal = null;
        try {
            final Field field = o.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            oldVal = field.get(o);
            field.set(o, value);
        } catch (Exception e) {
            throw new RuntimeException("Cannot get value of field " + fieldName, e);
        }
        return oldVal;
    }

    /**
     * Sets a Config property value
     *
     * The Config instance is initialized once on startup which means that
     * its properties don't change throughout its lifetime.
     * This method allows a Config property to be changed temporarily for testing purposes
     *
     * @param key The key of the property (eg Config.LOGGERLEVEL)
     * @param value The new value
     * @return The previous value
     */
    public static String setConfigProperty(String key, String value) throws Exception {

        String oldVal = null;

        try {
            Config config = Config.getConfig();

            final Field sdkPropertiesInstance = config.getClass().getDeclaredField("sdkProperties");
            sdkPropertiesInstance.setAccessible(true);

            final Properties sdkProperties = (Properties) sdkPropertiesInstance.get(config);
            oldVal = sdkProperties.getProperty(key);
            sdkProperties.put(key, value);

        } catch (Exception e) {
            throw new RuntimeException("Failed to set Config property " + key, e);
        }

        return oldVal;
    }


}
