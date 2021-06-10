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
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric_ca.sdk.exception.AffiliationException;
import org.hyperledger.fabric_ca.sdk.exception.HTTPException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;

import static java.lang.String.format;

// Hyperledger Fabric CA Affiliation information
public class HFCAAffiliation {

    private String name;
    private String updateName;

    private HFCAClient client;

    // Affiliations affected by this affiliation request
    private Collection<HFCAAffiliation> childHFCAAffiliations = new ArrayList<>();
    // Identities affected by this affiliation request
    private Collection<HFCAIdentity> identities = new ArrayList<>();

    private boolean deleted;

    static final String HFCA_AFFILIATION = HFCAClient.HFCA_CONTEXT_ROOT + "affiliations";
    private static final Log logger = LogFactory.getLog(HFCAAffiliation.class);

    HFCAAffiliation(String name, HFCAClient client) throws InvalidArgumentException {
        validateAffiliationNames(name);

        if (client.getCryptoSuite() == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

        this.name = name;
        this.client = client;
    }

    HFCAAffiliation(JsonObject result) {
        generateResponse(result);
    }

   /**
     * The name of the affiliation
     *
     * @return The affiliation name.
     */

    public String getName() {
        return name;
    }

    /**
     * The name of the new affiliation
     *
     * @return The affiliation name.
     * @throws AffiliationException
     */

    public String getUpdateName() throws AffiliationException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        return updateName;
    }

    /**
     * The name of the new affiliation
     * @throws AffiliationException
     *
     */

    public void setUpdateName(String updateName) throws AffiliationException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        this.updateName = updateName;
    }

    /**
     * The names of all affiliations
     * affected by request
     *
     * @return The affiliation name.
     * @throws AffiliationException
     */

    public Collection<HFCAAffiliation> getChildren() throws AffiliationException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        return childHFCAAffiliations;
    }

    /**
     * The identities affected during request. Identities are only returned
     * for update and delete requests. Read and Create do not return identities
     *
     * @return The identities affected.
     * @throws AffiliationException
     */

    public Collection<HFCAIdentity> getIdentities() throws AffiliationException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        return identities;
    }

    /**
     * The identities affected during request
     * @param name Name of the child affiliation
     *
     * @return The requested child affiliation
     * @throws InvalidArgumentException
     * @throws AffiliationException
     */
    public HFCAAffiliation createDecendent(String name) throws InvalidArgumentException, AffiliationException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        validateAffiliationNames(name);
        return new HFCAAffiliation(this.name + "." + name, this.client);
    }

    /**
     * Gets child affiliation by name
     * @param name Name of the child affiliation to get
     *
     * @return The requested child affiliation
     * @throws AffiliationException
     * @throws InvalidArgumentException
     */
    public HFCAAffiliation getChild(String name) throws AffiliationException, InvalidArgumentException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        validateSingleAffiliationName(name);
        for (HFCAAffiliation childAff : this.childHFCAAffiliations) {
            if (childAff.getName().equals(this.name + "." + name)) {
                return childAff;
            }
        }
        return null;
    }

    /**
     * Returns true if the affiliation has been deleted
     *
     * @return Returns true if the affiliation has been deleted
     */
    public boolean isDeleted() {
        return this.deleted;
    }

    /**
     * gets a specific affiliation
     *
     * @param registrar The identity of the registrar
     * @return Returns response
     * @throws AffiliationException if getting an affiliation fails.
     * @throws InvalidArgumentException
     */

    public int read(User registrar) throws AffiliationException, InvalidArgumentException {
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        String readAffURL = "";
        try {
            readAffURL = HFCA_AFFILIATION + "/" + name;
            logger.debug(format("affiliation  url: %s, registrar: %s", readAffURL, registrar.getName()));

            JsonObject result = client.httpGet(readAffURL, registrar);

            logger.debug(format("affiliation  url: %s, registrar: %s done.", readAffURL, registrar));
            HFCAAffiliationResp resp = getResponse(result);
            this.childHFCAAffiliations = resp.getChildren();

            this.identities = resp.getIdentities();
            this.deleted = false;
            return resp.statusCode;
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while getting affiliation '%s' from url '%s': %s", e.getStatusCode(), this.name, readAffURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        } catch (Exception e) {
            String msg = format("Error while getting affiliation %s url: %s  %s ", this.name, readAffURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        }
    }

    /**
     * create an affiliation
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return Response of request
     * @throws AffiliationException    if adding an affiliation fails.
     * @throws InvalidArgumentException
     */

    public HFCAAffiliationResp create(User registrar) throws AffiliationException, InvalidArgumentException {
        return create(registrar, false);
    }

    /**
     * create an affiliation
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @param force Forces the creation of parent affiliations
     * @return Response of request
     * @throws AffiliationException    if adding an affiliation fails.
     * @throws InvalidArgumentException
     */
    public HFCAAffiliationResp create(User registrar, boolean force) throws AffiliationException, InvalidArgumentException {
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        String createURL = "";
        try {
            createURL = client.getURL(HFCA_AFFILIATION);
            logger.debug(format("affiliation  url: %s, registrar: %s", createURL, registrar.getName()));

            Map<String, String> queryParm = new HashMap<>();
            queryParm.put("force", String.valueOf(force));
            String body = client.toJson(affToJsonObject());
            JsonObject result = client.httpPost(createURL, body, registrar);

            logger.debug(format("identity  url: %s, registrar: %s done.", createURL, registrar));
            this.deleted = false;
            return getResponse(result);
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while creating affiliation '%s' from url '%s': %s", e.getStatusCode(), this.name, createURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        } catch (Exception e) {
            String msg = format("Error while creating affiliation %s url: %s  %s ", this.name, createURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        }
    }

    /**
     * update an affiliation
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return Response of request
     * @throws AffiliationException If updating an affiliation fails
     * @throws InvalidArgumentException
     */

    public HFCAAffiliationResp update(User registrar) throws AffiliationException, InvalidArgumentException {
        return update(registrar, false);
    }

    /**
     * update an affiliation
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @param force Forces updating of child affiliations
     * @return Response of request
     * @throws AffiliationException If updating an affiliation fails
     * @throws InvalidArgumentException
     */
    public HFCAAffiliationResp update(User registrar, boolean force) throws AffiliationException, InvalidArgumentException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }
        if (Utils.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Affiliation name cannot be null or empty");
        }

        String updateURL = "";
        try {
            Map<String, String> queryParm = new HashMap<>();
            queryParm.put("force", String.valueOf(force));
            updateURL = client.getURL(HFCA_AFFILIATION + "/" + this.name, queryParm);

            logger.debug(format("affiliation  url: %s, registrar: %s", updateURL, registrar.getName()));

            String body = client.toJson(affToJsonObject());
            JsonObject result = client.httpPut(updateURL, body, registrar);

            generateResponse(result);
            logger.debug(format("identity  url: %s, registrar: %s done.", updateURL, registrar));
            HFCAAffiliationResp resp = getResponse(result);
            this.childHFCAAffiliations = resp.childHFCAAffiliations;
            this.identities = resp.identities;
            return getResponse(result);
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while updating affiliation '%s' from url '%s': %s", e.getStatusCode(), this.name, updateURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        } catch (Exception e) {
            String msg = format("Error while updating affiliation %s url: %s  %s ", this.name, updateURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        }
    }

    /**
     * delete an affiliation
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return Response of request
     * @throws AffiliationException    if deleting an affiliation fails.
     * @throws InvalidArgumentException
     */

    public HFCAAffiliationResp delete(User registrar) throws AffiliationException, InvalidArgumentException {
        return delete(registrar, false);
    }

    /**
     * delete an affiliation
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @param force Forces the deletion of affiliation
     * @return Response of request
     * @throws AffiliationException    if deleting an affiliation fails.
     * @throws InvalidArgumentException
     */
    public HFCAAffiliationResp delete(User registrar, boolean force) throws AffiliationException, InvalidArgumentException {
        if (this.deleted) {
            throw new AffiliationException("Affiliation has been deleted");
        }
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        String deleteURL = "";
        try {
            Map<String, String> queryParm = new HashMap<>();
            queryParm.put("force", String.valueOf(force));
            deleteURL = client.getURL(HFCA_AFFILIATION + "/" + this.name, queryParm);

            logger.debug(format("affiliation  url: %s, registrar: %s", deleteURL, registrar.getName()));

            JsonObject result = client.httpDelete(deleteURL, registrar);

            logger.debug(format("identity  url: %s, registrar: %s done.", deleteURL, registrar));
            this.deleted = true;
            return getResponse(result);
        } catch (HTTPException e) {
            String msg = format("[Code: %d] - Error while deleting affiliation '%s' from url '%s': %s", e.getStatusCode(), this.name, deleteURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        }  catch (Exception e) {
            String msg = format("Error while deleting affiliation %s url: %s  %s ", this.name, deleteURL, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        }
    }

    /**
     * Response of affiliation requests
     *
     */
    public static class HFCAAffiliationResp {

        // Affiliations affected by this affiliation request
        private Collection<HFCAAffiliation> childHFCAAffiliations = new ArrayList<>();
        // Identities affected by this affiliation request
        private Collection<HFCAIdentity> identities = new ArrayList<>();

        private int statusCode = 200;

        /**
         * The identities affected during request
         *
         * @return The identities affected.
         */

        public Collection<HFCAIdentity> getIdentities() {
            return identities;
        }

        /**
         * The names of all affiliations
         * affected by request
         *
         * @return The affiliation name.
         */

        public Collection<HFCAAffiliation> getChildren() {
            return childHFCAAffiliations;
        }

        /**
         * @return HTTP status code
         */
        public int getStatusCode() {
            return statusCode;
        }

        HFCAAffiliationResp(JsonObject result) {
            if (result.containsKey("affiliations")) {
                JsonArray affiliations = result.getJsonArray("affiliations");
                if (affiliations != null && !affiliations.isEmpty()) {
                    for (int i = 0; i < affiliations.size(); i++) {
                        JsonObject aff = affiliations.getJsonObject(i);
                        this.childHFCAAffiliations.add(new HFCAAffiliation(aff));
                    }
                }
            }
            if (result.containsKey("identities")) {
                JsonArray ids = result.getJsonArray("identities");
                if (ids != null && !ids.isEmpty()) {
                    for (int i = 0; i < ids.size(); i++) {
                        JsonObject id = ids.getJsonObject(i);
                        HFCAIdentity hfcaID = new HFCAIdentity(id);
                        this.identities.add(hfcaID);
                    }
                }
            }
            if (result.containsKey("statusCode")) {
                this.statusCode = result.getInt("statusCode");
            }
        }
    }

    HFCAAffiliationResp getResponse(JsonObject result) {
        if (result.containsKey("name")) {
            this.name = result.getString("name");
        }
        return new HFCAAffiliationResp(result);
    }

    private void generateResponse(JsonObject result) {
        if (result.containsKey("name")) {
            this.name = result.getString("name");
        }
        if (result.containsKey("affiliations")) {
            JsonArray affiliations = result.getJsonArray("affiliations");
            if (affiliations != null && !affiliations.isEmpty()) {
                for (int i = 0; i < affiliations.size(); i++) {
                    JsonObject aff = affiliations.getJsonObject(i);
                    this.childHFCAAffiliations.add(new HFCAAffiliation(aff));
                }
            }
        }
        if (result.containsKey("identities")) {
              JsonArray ids = result.getJsonArray("identities");
              if (ids != null && !ids.isEmpty()) {
                  for (int i = 0; i < ids.size(); i++) {
                      JsonObject id = ids.getJsonObject(i);
                      HFCAIdentity hfcaID = new HFCAIdentity(id);
                      this.identities.add(hfcaID);
                  }
              }
        }
    }

    // Convert the affiliation request to a JSON object
    private JsonObject affToJsonObject() {
        JsonObjectBuilder ob = Json.createObjectBuilder();
        if (client.getCAName() != null) {
            ob.add(HFCAClient.FABRIC_CA_REQPROP, client.getCAName());
        }
        if (this.updateName != null) {
            ob.add("name", updateName);
            this.updateName = null;
        } else {
            ob.add("name", name);
        }

        return ob.build();
    }

    /**
     * Validate affiliation name for proper formatting
     *
     * @param name the string to test.
     * @throws InvalidArgumentException
     */
    void validateAffiliationNames(String name) throws InvalidArgumentException {
        checkFormat(name);
        if (name.startsWith(".")) {
            throw new InvalidArgumentException("Affiliation name cannot start with a dot '.'");
        }
        if (name.endsWith(".")) {
            throw new InvalidArgumentException("Affiliation name cannot end with a dot '.'");
        }
        for (int i = 0; i < name.length(); i++) {
            if ((name.charAt(i) == '.') && (name.charAt(i) == name.charAt(i - 1))) {
                throw new InvalidArgumentException("Affiliation name cannot contain multiple consecutive dots '.'");
            }
        }
    }

    /**
     * Validate affiliation name for proper formatting
     *
     * @param name the string to test.
     * @throws InvalidArgumentException
     */
    void validateSingleAffiliationName(String name) throws InvalidArgumentException {
        checkFormat(name);
        if (name.contains(".")) {
            throw new InvalidArgumentException("Single affiliation name cannot contain any dots '.'");
        }
    }

    static void checkFormat(String name) throws InvalidArgumentException {
        if (Utils.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Affiliation name cannot be null or empty");
        }
        if (name.contains(" ") || name.contains("\t")) {
            throw new InvalidArgumentException("Affiliation name cannot contain an empty space or tab");
        }
    }

}
