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

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.json.JsonWriter;

import org.hyperledger.fabric.sdk.idemix.IdemixCredRequest;

/**
 * An enrollment request is information required to enroll the user with member service.
 */
public class IdemixEnrollmentRequest {

    private IdemixCredRequest idemixCredReq = null;

    private String caName;

    IdemixEnrollmentRequest() {
    }

    IdemixEnrollmentRequest(IdemixCredRequest credRequest) {
        this.idemixCredReq = credRequest;
    }

    void setCAName(String caName) {
        this.caName = caName;
    }

    void setIdemixCredReq(IdemixCredRequest idemixCredReq) {
        this.idemixCredReq = idemixCredReq;
    }

    // Convert the enrollment request to a JSON string
    String toJson() {
        StringWriter stringWriter = new StringWriter();
        JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
        jsonWriter.writeObject(toJsonObject());
        jsonWriter.close();
        return stringWriter.toString();
    }

    // Convert the enrollment request to a JSON object
    private JsonObject toJsonObject() {
        JsonObjectBuilder factory = Json.createObjectBuilder();
        if (idemixCredReq != null) {
            factory.add("request", idemixCredReq.toJsonObject());
        } else {
            factory.add("request", JsonValue.NULL);
        }
        if (caName != null) {
            factory.add(HFCAClient.FABRIC_CA_REQPROP, caName);
        }
        return factory.build();
    }
}
