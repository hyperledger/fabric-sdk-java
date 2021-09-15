/*
 *
 *  Copyright 2016,2017,2018 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric_ca.sdk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric_ca.sdk.exception.HTTPException;
import org.hyperledger.fabric_ca.sdk.exception.IdentityException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;

import static java.lang.String.format;
// Hyperledger Fabric CA Identity information

public class HFCAIdentity {

    // The enrollment ID of the user
    private final String enrollmentID;
    // Type of identity
    private String type = "user";
    // Optional secret
    private String secret;
    // Maximum number of enrollments with the secret
    private Integer maxEnrollments = null;
    // Affiliation for a user
    private String affiliation;
    // Array of attribute names and values
    private Collection<Attribute> attrs = new ArrayList<>();

    private HFCAClient client;
    private int statusCode;

    private boolean deleted;

    static final String HFCA_IDENTITY = HFCAClient.HFCA_CONTEXT_ROOT + "identities";
    private static final Log logger = LogFactory.getLog(HFCAIdentity.class);
    //These attributes can not be modified with REST put request.
    private static final Set<String> filtredUpdateAttrNames = new HashSet<>(Arrays.asList("hf.EnrollmentID", "hf.Type", "hf.Affiliation"));

    HFCAIdentity(String enrollmentID, HFCAClient client) throws InvalidArgumentException {
        if (Utils.isNullOrEmpty(enrollmentID)) {
            throw new InvalidArgumentException("EnrollmentID cannot be null or empty");
        }

        if (client.getCryptoSuite() == null) {
            throw new InvalidArgumentException("Client's crypto primitives not set");
        }

        this.enrollmentID = enrollmentID;
        this.client = client;
    }

    HFCAIdentity(JsonObject result) {
        this.enrollmentID = result.getString("id");
        getHFCAIdentity(result);
    }

    /**
     * The name of the identity
     *
     * @return The identity name.
     */

    public String getEnrollmentId() {
        return enrollmentID;
    }

    /**
     * The type of the identity
     *
     * @return The identity type.
     */

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    /**
     * The secret of the identity
     *
     * @return The identity secret.
     */

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    /**
     * The max enrollment value of the identity
     *
     * @return The identity max enrollment.
     */

    public Integer getMaxEnrollments() {
        return maxEnrollments;
    }

    public void setMaxEnrollments(Integer maxEnrollments) {
        this.maxEnrollments = maxEnrollments;
    }

    /**
     * The affiliation of the identity
     *
     * @return The identity affiliation.
     */

    public String getAffiliation() {
        return affiliation;
    }

    /**
     * Set affiliation of the identity
     *
     * @param affiliation Affiliation name
     */
    public void setAffiliation(String affiliation) {
        this.affiliation = affiliation;
    }

    /**
     * Set affiliation of the identity
     *
     * @param affiliation Affiliation name
     */
    public void setAffiliation(HFCAAffiliation affiliation) {
        this.affiliation = affiliation.getName();
    }

    /**
     * The attributes of the identity
     *
     * @return The identity attributes.
     */

    public Collection<Attribute> getAttributes() {
        return attrs;
    }

    public void setAttributes(Collection<Attribute> attributes) {
        this.attrs = attributes;
    }

    /**
     * Returns true if the identity has been deleted
     *
     * @return Returns true if the identity has been deleted
     */
    public boolean isDeleted() {
        return this.deleted;
    }

    /**
     * read retrieves a specific identity
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return statusCode The HTTP status code in the response
     * @throws IdentityException        if retrieving an identity fails.
     * @throws InvalidArgumentException Invalid (null) argument specified
     */

    public int read(User registrar) throws IdentityException, InvalidArgumentException {
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        String readIdURL = "";
        try {
            readIdURL = HFCA_IDENTITY + "/" + enrollmentID;
            logger.debug(format("identity  url: %s, registrar: %s", readIdURL, registrar.getName()));

            JsonObject result = client.httpGet(readIdURL, registrar);

            statusCode = result.getInt("statusCode");
            if (statusCode < 400) {
                type = result.getString("type");
                maxEnrollments = result.getInt("max_enrollments");
                affiliation = result.getString("affiliation");

                JsonArray attributes = result.getJsonArray("attrs");
                Collection<Attribute> attrs = new ArrayList<>();
                if (attributes != null && !attributes.isEmpty()) {
                    for (int i = 0; i < attributes.size(); i++) {
                        JsonObject attribute = attributes.getJsonObject(i);
                        Attribute attr = new Attribute(attribute.getString("name"), attribute.getString("value"), attribute.getBoolean("ecert", false));
                        attrs.add(attr);
                    }
                }
                this.attrs = attrs;

                logger.debug(format("identity  url: %s, registrar: %s done.", readIdURL, registrar));
            }
            this.deleted = false;
            return statusCode;
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while getting user '%s' from url '%s': %s", e.getStatusCode(), getEnrollmentId(), readIdURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        } catch (Exception e) {
            String msg = format("Error while getting user '%s' from url '%s': %s", enrollmentID, readIdURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        }

    }

    /**
     * create an identity
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return statusCode The HTTP status code in the response
     * @throws IdentityException        if creating an identity fails.
     * @throws InvalidArgumentException Invalid (null) argument specified
     */

    public int create(User registrar) throws IdentityException, InvalidArgumentException {
        if (this.deleted) {
            throw new IdentityException("Identity has been deleted");
        }
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        String createURL = "";
        try {
            createURL = client.getURL(HFCA_IDENTITY);
            logger.debug(format("identity  url: %s, registrar: %s", createURL, registrar.getName()));

            String body = client.toJson(idToJsonObject());
            JsonObject result = client.httpPost(createURL, body, registrar);
            statusCode = result.getInt("statusCode");
            if (statusCode < 400) {
                getHFCAIdentity(result);
                logger.debug(format("identity  url: %s, registrar: %s done.", createURL, registrar));
            }
            this.deleted = false;
            return statusCode;
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while creating user '%s' from url '%s': %s", e.getStatusCode(), getEnrollmentId(), createURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        } catch (Exception e) {
            String msg = format("Error while creating user '%s' from url '%s':  %s", getEnrollmentId(), createURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        }
    }

    /**
     * update an identity
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return statusCode The HTTP status code in the response
     * @throws IdentityException        if adding an identity fails.
     * @throws InvalidArgumentException Invalid (null) argument specified
     */

    public int update(User registrar) throws IdentityException, InvalidArgumentException {
        if (this.deleted) {
            throw new IdentityException("Identity has been deleted");
        }
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        String updateURL = "";
        try {
            updateURL = client.getURL(HFCA_IDENTITY + "/" + getEnrollmentId());
            logger.debug(format("identity  url: %s, registrar: %s", updateURL, registrar.getName()));

            String body = client.toJson(idToJsonObject(filtredUpdateAttrNames));
            JsonObject result = client.httpPut(updateURL, body, registrar);

            statusCode = result.getInt("statusCode");
            if (statusCode < 400) {
                getHFCAIdentity(result);
                logger.debug(format("identity  url: %s, registrar: %s done.", updateURL, registrar));
            }
            return statusCode;
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while updating user '%s' from url '%s': %s", e.getStatusCode(), getEnrollmentId(), updateURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        } catch (Exception e) {
            String msg = format("Error while updating user '%s' from url '%s':  %s", getEnrollmentId(), updateURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        }
    }

    /**
     * delete an identity
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return statusCode The HTTP status code in the response
     * @throws IdentityException        if adding an identity fails.
     * @throws InvalidArgumentException Invalid (null) argument specified
     */

    public int delete(User registrar) throws IdentityException, InvalidArgumentException {
        if (this.deleted) {
            throw new IdentityException("Identity has been deleted");
        }
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        String deleteURL = "";
        try {
            deleteURL = client.getURL(HFCA_IDENTITY + "/" + getEnrollmentId());
            logger.debug(format("identity  url: %s, registrar: %s", deleteURL, registrar.getName()));

            JsonObject result = client.httpDelete(deleteURL, registrar);

            statusCode = result.getInt("statusCode");
            if (statusCode < 400) {
                getHFCAIdentity(result);
                logger.debug(format("identity  url: %s, registrar: %s done.", deleteURL, registrar));
            }
            this.deleted = true;
            return statusCode;
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while deleting user '%s' from url '%s': %s", e.getStatusCode(), getEnrollmentId(), deleteURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        } catch (Exception e) {
            String msg = format("Error while deleting user '%s' from url '%s':  %s", getEnrollmentId(), deleteURL, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        }
    }

    private void getHFCAIdentity(JsonObject result) {
        type = result.getString("type");
        if (result.containsKey("secret")) {
            this.secret = result.getString("secret");
        }
        maxEnrollments = result.getInt("max_enrollments");
        affiliation = result.getString("affiliation");
        JsonArray attributes = result.getJsonArray("attrs");

        Collection<Attribute> attrs = new ArrayList<>();
        if (attributes != null && !attributes.isEmpty()) {
            for (int i = 0; i < attributes.size(); i++) {
                JsonObject attribute = attributes.getJsonObject(i);
                Attribute attr = new Attribute(attribute.getString("name"), attribute.getString("value"), attribute.getBoolean("ecert", false));
                attrs.add(attr);
            }
        }
        this.attrs = attrs;
    }

    // Convert the identity request to a JSON object
    private JsonObject idToJsonObject() {
        return idToJsonObject(Collections.emptySet());
    }

    private JsonObject idToJsonObject(Set<String> filteredAttrs) {
        JsonObjectBuilder ob = Json.createObjectBuilder();
        ob.add("id", enrollmentID);
        ob.add("type", type);
        if (null != maxEnrollments) {
            ob.add("max_enrollments", maxEnrollments);
        }
        if (affiliation != null) {
            ob.add("affiliation", affiliation);
        }
        JsonArrayBuilder ab = Json.createArrayBuilder();
        for (Attribute attr : attrs) {
            if (!filteredAttrs.contains(attr.getName())) {
                ab.add(attr.toJsonObject());
            }
        }
        ob.add("attrs", ab.build());
        if (this.secret != null) {
            ob.add("secret", secret);
        }
        if (client.getCAName() != null) {
            ob.add(HFCAClient.FABRIC_CA_REQPROP, client.getCAName());
        }
        return ob.build();
    }
}
