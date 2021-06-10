/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric_ca.sdk;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

// An attribute name and value which is used when registering a new user
public class Attribute {
    private final Boolean ecert;
    private String name;
    private String value;

    public Attribute(String name, String value) {
        this(name, value, null);
    }

    /**
     * @param name             Attribute name.
     * @param value            Attribute value.
     * @param defaultAttribute Attribute should be included in certificate even if not specified during enrollment.
     */
    public Attribute(String name, String value, Boolean defaultAttribute) {
        this.name = name;
        this.value = value;
        this.ecert = defaultAttribute;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public JsonObject toJsonObject() {
        JsonObjectBuilder ob = Json.createObjectBuilder();
        ob.add("name", name);
        ob.add("value", value);
        if (ecert != null) {
            ob.add("ecert", ecert);
        }
        return ob.build();
    }

}
