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
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonWriter;

/**
 * An enrollment request is information required to enroll the user with member service.
 */
public class EnrollmentRequest {

    // A PEM-encoded string containing the CSR (Certificate Signing Request) based on PKCS #10
    private String csr;
    // Comma-separated list of host names to associate with the certificate
    private Collection<String> hosts;
    // Name of the signing profile to use when issuing the certificate
    private String profile;
    // Label used in HSM operations
    private String label;
    // Key pair for generating certification request
    private KeyPair keypair;
    // The Certificate Authority's name
    private String caName;

    /**
     * The certificate signing request if it's not supplied it will be generated.
     *
     * @param csr
     */

    public void setCsr(String csr) {
        this.csr = csr;
    }

    // Constructor
    public EnrollmentRequest() {
        this.csr = null;
        this.hosts = new ArrayList<String>();
        this.profile = null;
        this.label = null;
        this.keypair = null;
    }

    String getCsr() {
        return csr;
    }

    /**
     * EnrollmentRequest All the fields are optional
     *
     * @param profile
     * @param label
     * @param keypair Keypair used to sign or create the certificate if needed.
     */
    public EnrollmentRequest(String profile, String label, KeyPair keypair) {
        this.csr = null;
        this.hosts = new ArrayList<String>();
        this.profile = profile;
        this.label = label;
        this.keypair = keypair;
    }

    KeyPair getKeyPair() {
        return keypair;
    }

    /**
     * The keypair used to create the certificate request if it's not supplied.
     * @param keypair
     */

    /**
     * The Key pair to create the signing certificate if not supplied it will be generated.
     *
     * @param keypair
     */
    public void setKeyPair(KeyPair keypair) {
        this.keypair = keypair;
    }

    void setCSR(String csr) {
        this.csr = csr;
    }

    void setCAName(String caName) {
        this.caName = caName;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Collection<String> getHosts() {
        return hosts;
    }

    public void addHost(String host) {
        this.hosts.add(host);
    }

    // Convert the enrollment request to a JSON string
    String toJson() {
        StringWriter stringWriter = new StringWriter();
        JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
        jsonWriter.writeObject(this.toJsonObject());
        jsonWriter.close();
        return stringWriter.toString();
    }

    // Convert the enrollment request to a JSON object
    private JsonObject toJsonObject() {
        JsonObjectBuilder factory = Json.createObjectBuilder();
        if (profile != null) {
            factory.add("profile", profile);
        }
        if (!hosts.isEmpty()) {
            JsonArrayBuilder ab = Json.createArrayBuilder();
            for (String host : hosts) {
                ab.add(host);
            }
            factory.add("hosts", ab.build());
        }
        if (label != null) {
            factory.add("label", label);
        }

        if (caName != null) {
            factory.add(HFCAClient.FABRIC_CA_REQPROP, caName);
        }
        factory.add("certificate_request", csr);
        return factory.build();
    }
}
