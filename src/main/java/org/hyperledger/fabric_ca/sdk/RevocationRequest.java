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
import javax.json.JsonWriter;

import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;

/**
 * A RevocationRequest defines the attributes required to revoke credentials with member service.
 */
class RevocationRequest {

    private final String caName;
    // Enrollment ID whose certificates are to be revoked
    private String enrollmentID;
    // Serial number of certificate to be revoked
    private String serial;
    // Authority key identifier of certificate to be revoked
    private String aki;
    // Reason for revocation
    private String reason;

    // Constructor
    RevocationRequest(String caNmae, String id, String serial, String aki, String reason) throws Exception {
        if (isNullOrEmpty(id)) {
            if (isNullOrEmpty(serial) || isNullOrEmpty(aki)) {
                throw new Exception("Enrollment ID is empty, thus both aki and serial must have non-empty values");
            }
        }
        this.enrollmentID = id;
        this.serial = serial;
        this.aki = aki;
        this.reason = reason;
        this.caName = caNmae;
    }

    String getUser() {
        return enrollmentID;
    }

    void setUser(String user) {
        this.enrollmentID = user;
    }

    String getSerial() {
        return serial;
    }

    void setSerial(String serial) {
        this.serial = serial;
    }

    String getAki() {
        return aki;
    }

    void setAki(String aki) {
        this.aki = aki;
    }

    String getReason() {
        return reason;
    }

    void setReason(String reason) {
        this.reason = reason;
    }

    // Convert the revocation request to a JSON string
    String toJson() {
        StringWriter stringWriter = new StringWriter();
        JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
        jsonWriter.writeObject(this.toJsonObject());
        jsonWriter.close();
        return stringWriter.toString();
    }

    // Convert the revocation request to a JSON object
    private JsonObject toJsonObject() {
        JsonObjectBuilder factory = Json.createObjectBuilder();
        if (enrollmentID != null) {
            // revoke all enrollments of this user, serial and aki are ignored in this case
            factory.add("id", enrollmentID);
        } else {
            // revoke one particular enrollment
            factory.add("serial", "0" + serial);
            factory.add("aki", aki);
        }

        if (null != reason) {
            factory.add("reason", reason);
        }

        if (caName != null) {
            factory.add(HFCAClient.FABRIC_CA_REQPROP, caName);
        }
        factory.add("reason", reason);
        return factory.build();
    }
}
