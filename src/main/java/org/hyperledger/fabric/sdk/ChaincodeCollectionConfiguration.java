/*
 *
 *  Copyright 2016,2017,2018  IBM - All Rights Reserved.
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

package org.hyperledger.fabric.sdk;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.MspPrincipal.MSPPrincipal;
import org.hyperledger.fabric.protos.common.MspPrincipal.MSPRole;
import org.hyperledger.fabric.protos.common.Policies;
import org.hyperledger.fabric.protos.common.Policies.SignaturePolicy;
import org.hyperledger.fabric.protos.peer.Collection;
import org.hyperledger.fabric.sdk.exception.ChaincodeCollectionConfigurationException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import static java.lang.String.format;

public class ChaincodeCollectionConfiguration {
    private static final Log logger = LogFactory.getLog(ChaincodeCollectionConfiguration.class);
    private static final Pattern noofPattern = Pattern.compile("^(\\d+)-of$");

    Collection.CollectionConfigPackage getCollectionConfigPackage() {
        return collectionConfigPackage;
    }

    private final Collection.CollectionConfigPackage collectionConfigPackage;

    ChaincodeCollectionConfiguration(JsonArray jsonConfig) throws ChaincodeCollectionConfigurationException {

        collectionConfigPackage = parse(jsonConfig);
        if (collectionConfigPackage == null) {
            throw new ChaincodeCollectionConfigurationException("Parsing collection configuration produce null configuration.");
        }
    }

    ChaincodeCollectionConfiguration(Collection.CollectionConfigPackage collectionConfigPackage) {

        this.collectionConfigPackage = collectionConfigPackage;
    }

    public byte[] getAsBytes() throws ChaincodeCollectionConfigurationException {
        if (collectionConfigPackage == null) {
            throw new ChaincodeCollectionConfigurationException("Collection configuration was null.");
        }
        return collectionConfigPackage.toByteArray();
    }

    /**
     * Creates a new ChaincodeCollectionConfiguration instance configured with details supplied in a YAML file.
     *
     * @param configFile The file containing the network configuration
     * @return A new ChaincodeCollectionConfiguration instance
     * @throws InvalidArgumentException
     * @throws IOException
     */
    public static ChaincodeCollectionConfiguration fromYamlFile(File configFile) throws InvalidArgumentException, IOException, ChaincodeCollectionConfigurationException {
        return fromFile(configFile, false);
    }

    /**
     * Creates a new ChaincodeCollectionConfiguration instance configured with details supplied in a JSON file.
     *
     * @param configFile The file containing the network configuration
     * @return A new ChaincodeCollectionConfiguration instance
     * @throws InvalidArgumentException
     * @throws IOException
     */
    public static ChaincodeCollectionConfiguration fromJsonFile(File configFile) throws InvalidArgumentException, IOException, ChaincodeCollectionConfigurationException {
        return fromFile(configFile, true);
    }

    /**
     * Creates a new ChaincodeCollectionConfiguration instance configured with details supplied in YAML format
     *
     * @param configStream A stream opened on a YAML document containing network configuration details
     * @return A new ChaincodeCollectionConfiguration instance
     * @throws InvalidArgumentException
     */
    public static ChaincodeCollectionConfiguration fromYamlStream(InputStream configStream) throws InvalidArgumentException, ChaincodeCollectionConfigurationException {

        logger.trace("ChaincodeCollectionConfiguration.fromYamlStream...");

        // Sanity check
        if (configStream == null) {
            throw new InvalidArgumentException("ConfigStream must be specified");
        }

        Yaml yaml = new Yaml(new SafeConstructor());

        List<Object> map = yaml.load(configStream);

        JsonArrayBuilder builder = Json.createArrayBuilder(map);

        JsonArray jsonConfig = builder.build();
        return fromJsonObject(jsonConfig);
    }

    /**
     * Creates a new ChaincodeCollectionConfiguration instance configured with details supplied in JSON format
     *
     * @param configStream A stream opened on a JSON document containing network configuration details
     * @return A new ChaincodeCollectionConfiguration instance
     * @throws InvalidArgumentException
     */
    public static ChaincodeCollectionConfiguration fromJsonStream(InputStream configStream) throws InvalidArgumentException, ChaincodeCollectionConfigurationException {

        logger.trace("ChaincodeCollectionConfiguration.fromJsonStream...");

        // Sanity check
        if (configStream == null) {
            throw new InvalidArgumentException("configStream must be specified");
        }

        // Read the input stream and convert to JSON

        try (JsonReader reader = Json.createReader(configStream)) {

            return fromJsonObject((JsonArray) reader.read());
        }

    }

    /**
     * Creates a new ChaincodeCollectionConfiguration instance configured with details supplied in a JSON object
     *
     * @param jsonConfig JSON object containing network configuration details
     * @return A new ChaincodeCollectionConfiguration instance
     * @throws InvalidArgumentException
     */
    public static ChaincodeCollectionConfiguration fromJsonObject(JsonArray jsonConfig) throws InvalidArgumentException, ChaincodeCollectionConfigurationException {

        // Sanity check
        if (jsonConfig == null) {
            throw new InvalidArgumentException("jsonConfig must be specified");
        }

        if (logger.isTraceEnabled()) {
            logger.trace(format("ChaincodeCollectionConfiguration.fromJsonObject: %s", jsonConfig.toString()));
        }

        return load(jsonConfig);
    }
    /*
        public void setCollectionConfigPackage(Collection.CollectionConfigPackage collectionConfigPackage) {
        this.collectionConfigPackage = collectionConfigPackage;
    }
     */

    public static ChaincodeCollectionConfiguration fromCollectionConfigPackage(Collection.CollectionConfigPackage collectionConfigPackage) throws InvalidArgumentException {

        // Sanity check
        if (collectionConfigPackage == null) {
            throw new InvalidArgumentException("collectionConfigPackage must be specified");
        }

        return new ChaincodeCollectionConfiguration(collectionConfigPackage);
    }

    // Loads a ChaincodeCollectionConfiguration object from a Json or Yaml file
    private static ChaincodeCollectionConfiguration fromFile(File configFile, boolean isJson) throws InvalidArgumentException, IOException, ChaincodeCollectionConfigurationException {

        // Sanity check
        if (configFile == null) {
            throw new InvalidArgumentException("configFile must be specified");
        }

        if (logger.isTraceEnabled()) {
            logger.trace(format("ChaincodeCollectionConfiguration.fromFile: %s  isJson = %b", configFile.getAbsolutePath(), isJson));
        }

        // Json file
        try (InputStream stream = new FileInputStream(configFile)) {
            return isJson ? fromJsonStream(stream) : fromYamlStream(stream);
        }

    }

    /**
     * Returns a new ChaincodeCollectionConfiguration instance and populates it from the specified JSON object
     *
     * @param jsonConfig The JSON object containing the config details
     * @return A populated ChaincodeCollectionConfiguration instance
     * @throws InvalidArgumentException
     */
    private static ChaincodeCollectionConfiguration load(JsonArray jsonConfig) throws InvalidArgumentException, ChaincodeCollectionConfigurationException {

        // Sanity check
        if (jsonConfig == null) {
            throw new InvalidArgumentException("jsonConfig must be specified");
        }

        return new ChaincodeCollectionConfiguration(jsonConfig);
    }

    Collection.CollectionConfigPackage parse(JsonArray jsonConfig) throws ChaincodeCollectionConfigurationException {

        Collection.CollectionConfigPackage.Builder colcofbuilder = Collection.CollectionConfigPackage.newBuilder();
        for (int i = jsonConfig.size() - 1; i > -1; --i) {

            Collection.StaticCollectionConfig.Builder ssc = Collection.StaticCollectionConfig.newBuilder();

            JsonValue j = jsonConfig.get(i);
            if (j.getValueType() != JsonValue.ValueType.OBJECT) {
                throw new ChaincodeCollectionConfigurationException(format("Expected StaticCollectionConfig to be Object type but got: %s", j.getValueType().name()));
            }

            JsonObject jsonObject = j.asJsonObject();
            JsonObject scf = getJsonObject(jsonObject, "StaticCollectionConfig"); // oneof .. may have different values in the future
            ssc.setName(getJsonString(scf, "name"))
                    .setBlockToLive(getJsonLong(scf, "blockToLive"))
                    .setMaximumPeerCount(getJsonInt(scf, "maximumPeerCount"))
                    .setMemberOrgsPolicy(Collection.CollectionPolicyConfig.newBuilder()
                            .setSignaturePolicy(parseSignaturePolicyEnvelope(scf)).build())
                    .setRequiredPeerCount(getJsonInt(scf, "requiredPeerCount"));

            colcofbuilder.addConfig(Collection.CollectionConfig.newBuilder().setStaticCollectionConfig(ssc).build());

        }
        return colcofbuilder.build();

    }

    private Policies.SignaturePolicyEnvelope parseSignaturePolicyEnvelope(JsonObject scf) throws ChaincodeCollectionConfigurationException {

        JsonObject signaturePolicyEnvelope = getJsonObject(scf, "SignaturePolicyEnvelope"); // oneof

        IndexedHashMap<String, MSPPrincipal> identities = parseIdentities(getJsonArray(signaturePolicyEnvelope, "identities"));
        SignaturePolicy sp = parsePolicy(identities, getJsonObject(signaturePolicyEnvelope, "policy"));

        return Policies.SignaturePolicyEnvelope.newBuilder()
                .addAllIdentities(identities.values()).setRule(sp).build();

        //    .setVersion(getJsonInt(signaturePolicyEnvelope, "version")).addAllIdentities(identities.values()).setRule(sp).build();

    }

    private SignaturePolicy parsePolicy(IndexedHashMap<String, MSPPrincipal> identities, JsonObject policy) throws ChaincodeCollectionConfigurationException {

        if (policy.size() != 1) {
            throw new ChaincodeCollectionConfigurationException(format("Expected policy size of 1 but got %d", policy.size()));
        }
        final String key = policy.entrySet().iterator().next().getKey();

        if ("signed-by".equals(key)) {
            final String vo = getJsonString(policy, key);

            MSPPrincipal mspPrincipal = identities.get(vo);
            if (null == mspPrincipal) {
                throw new ChaincodeCollectionConfigurationException(format("No identity found by name %s in signed-by.", vo));
            }

            return SignaturePolicy.newBuilder()
                    .setSignedBy(identities.getKeysIndex(vo))
                    .build();

        } else {

            Matcher match = noofPattern.matcher(key);
            final JsonArray vo = getJsonArray(policy, key);

            if (match.matches() && match.groupCount() == 1) {

                String matchStingNo = match.group(1).trim();
                int matchNo = Integer.parseInt(matchStingNo);

                if (vo.size() < matchNo) {

                    throw new ChaincodeCollectionConfigurationException(format("%s expected to have at least %d items to match but only found %d.", key, matchNo, vo.size()));
                }

                SignaturePolicy.NOutOf.Builder spBuilder = SignaturePolicy.NOutOf.newBuilder()
                        .setN(matchNo);

                for (int i = vo.size() - 1; i >= 0; --i) {
                    JsonValue jsonValue = vo.get(i);
                    if (jsonValue.getValueType() != JsonValue.ValueType.OBJECT) {
                        throw new ChaincodeCollectionConfigurationException(format("Expected object type in Nof but got %s", jsonValue.getValueType().name()));
                    }

                    SignaturePolicy sp = parsePolicy(identities, jsonValue.asJsonObject());
                    spBuilder.addRules(sp);

                }

                return SignaturePolicy.newBuilder().setNOutOf(spBuilder.build()).build();

            } else {

                throw new ChaincodeCollectionConfigurationException(format("Unsupported policy type %s", key));
            }
        }

    }

    private IndexedHashMap<String, MSPPrincipal> parseIdentities(JsonArray identities) throws ChaincodeCollectionConfigurationException {
        IndexedHashMap<String, MSPPrincipal> ret = new IndexedHashMap<>();

        for (JsonValue jsonValue : identities) {
            if (jsonValue.getValueType() != JsonValue.ValueType.OBJECT) {
                throw new ChaincodeCollectionConfigurationException(format("Expected in identies user to be Object type but got: %s", jsonValue.getValueType().name()));
            }
            JsonObject user = jsonValue.asJsonObject();
            if (user.entrySet().size() != 1) {
                throw new ChaincodeCollectionConfigurationException("Only expected on property for user entry in identies.");
            }
            Map.Entry<String, JsonValue> next = user.entrySet().iterator().next();
            String name = next.getKey();
            jsonValue = next.getValue();
            if (jsonValue.getValueType() != JsonValue.ValueType.OBJECT) {
                throw new ChaincodeCollectionConfigurationException(format("Expected in identies role to be Object type but got: %s", jsonValue.getValueType().name()));
            }
            JsonObject role = jsonValue.asJsonObject();
            JsonObject roleObj = getJsonObject(role, "role");
            String roleName = getJsonString(roleObj, "name");
            String mspId = getJsonString(roleObj, "mspId");

            MSPRole.MSPRoleType mspRoleType;

            switch (roleName.intern()) {
                case "member":
                    mspRoleType = MSPRole.MSPRoleType.MEMBER;
                    break;
                case "admin":
                    mspRoleType = MSPRole.MSPRoleType.ADMIN;
                    break;
                case "client":
                    mspRoleType = MSPRole.MSPRoleType.CLIENT;
                    break;
                case "peer":
                    mspRoleType = MSPRole.MSPRoleType.PEER;
                    break;
                default:
                    throw new ChaincodeCollectionConfigurationException(format("In identities with key %s name expected member, admin, client, or peer in role got %s ", name, roleName));
            }

            MSPRole mspRole = MSPRole.newBuilder().setRole(mspRoleType)
                    .setMspIdentifier(mspId).build();

            MSPPrincipal principal = MSPPrincipal.newBuilder()
                    .setPrincipalClassification(MSPPrincipal.Classification.ROLE)
                    .setPrincipal(mspRole.toByteString()).build();

            ret.put(name, principal);

        }

        return ret;
    }

    private static JsonObject getJsonObject(JsonObject obj, String prop) throws ChaincodeCollectionConfigurationException {
        JsonValue ret = obj.get(prop);
        if (ret == null) {
            throw new ChaincodeCollectionConfigurationException(format("property %s missing", prop));
        }
        if (ret.getValueType() != JsonValue.ValueType.OBJECT) {
            throw new ChaincodeCollectionConfigurationException(format("property %s wrong type expected object got %s", prop, ret.getValueType().name()));
        }

        return ret.asJsonObject();

    }

    private static JsonArray getJsonArray(JsonObject obj, String prop) throws ChaincodeCollectionConfigurationException {
        JsonValue ret = obj.get(prop);
        if (ret == null) {
            throw new ChaincodeCollectionConfigurationException(format("property %s missing", prop));
        }
        if (ret.getValueType() != JsonValue.ValueType.ARRAY) {
            throw new ChaincodeCollectionConfigurationException(format("property %s wrong type expected array got %s", prop, ret.getValueType().name()));
        }

        return ret.asJsonArray();

    }

    private static String getJsonString(JsonObject obj, String prop) throws ChaincodeCollectionConfigurationException {
        JsonValue ret = obj.get(prop);
        if (ret == null) {
            throw new ChaincodeCollectionConfigurationException(format("property %s missing", prop));
        }
        if (ret.getValueType() != JsonValue.ValueType.STRING) {
            throw new ChaincodeCollectionConfigurationException(format("property %s wrong type expected string got %s", prop, ret.getValueType().name()));
        }

        return obj.getString(prop);

    }

    private static long getJsonLong(JsonObject obj, String prop) throws ChaincodeCollectionConfigurationException {
        JsonValue ret = obj.get(prop);
        if (ret == null) {
            throw new ChaincodeCollectionConfigurationException(format("property %s missing", prop));
        }
        if (ret.getValueType() != JsonValue.ValueType.NUMBER) {
            throw new ChaincodeCollectionConfigurationException(format("property %s wrong type expected number got %s", prop, ret.getValueType().name()));
        }

        return Long.parseLong(ret.toString());

    }

    private static int getJsonInt(JsonObject obj, String prop) throws ChaincodeCollectionConfigurationException {
        JsonValue ret = obj.get(prop);
        if (ret == null) {
            throw new ChaincodeCollectionConfigurationException(format("property %s missing", prop));
        }
        if (ret.getValueType() != JsonValue.ValueType.NUMBER) {
            throw new ChaincodeCollectionConfigurationException(format("property %s wrong type expected number got %s", prop, ret.getValueType().name()));
        }

        return Integer.parseInt(ret.toString());

    }

    private static class IndexedHashMap<K, V> extends LinkedHashMap<K, V> {
        final HashMap<K, Integer> kmap = new HashMap<>();

        @Override
        public V put(K key, V value) {
            kmap.put(key, size());
            return super.put(key, value);
        }

        Integer getKeysIndex(String n) {
            return kmap.get(n);
        }
    }

}
