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

import io.netty.util.internal.StringUtil;
import org.apache.commons.io.IOUtils;
import org.hyperledger.fabric.protos.common.MspPrincipal.MSPPrincipal;
import org.hyperledger.fabric.protos.common.MspPrincipal.MSPRole;
import org.hyperledger.fabric.protos.common.Policies;
import org.hyperledger.fabric.protos.common.Policies.SignaturePolicy;
import org.hyperledger.fabric.sdk.exception.ChaincodeEndorsementPolicyParseException;
import org.yaml.snakeyaml.Yaml;

import static java.lang.String.format;

/**
 * A wrapper for the Hyperledger Fabric Policy object
 */
public class ChaincodeEndorsementPolicy {
    private static final Pattern noofPattern = Pattern.compile("^(\\d+)-of$");
    private byte[] policyBytes = null;

    /**
     * The null constructor for the ChaincodeEndorsementPolicy wrapper. You will
     * need to use the {@link #fromBytes(byte[])} method to
     * populate the policy
     */
    public ChaincodeEndorsementPolicy() {
    }

    private static SignaturePolicy parsePolicy(IndexedHashMap<String, MSPPrincipal> identities, Map<?, ?> mp) throws ChaincodeEndorsementPolicyParseException {

        if (mp == null) {
            throw new ChaincodeEndorsementPolicyParseException("No policy section was found in the document.");
        }
        if (!(mp instanceof Map)) {
            throw new ChaincodeEndorsementPolicyParseException("Policy expected object section was not found in the document.");

        }

        for (Map.Entry<?, ?> ks : mp.entrySet()) {
            Object ko = ks.getKey();
            Object vo = ks.getValue();
            final String key = (String) ko;
            // String val = (String) vo;

            if ("signed-by".equals(key)) {

                if (!(vo instanceof String)) {
                    throw new ChaincodeEndorsementPolicyParseException("signed-by expecting a string value");
                }

                MSPPrincipal mspPrincipal = identities.get(vo);
                if (null == mspPrincipal) {
                    throw new ChaincodeEndorsementPolicyParseException(format("No identity found by name %s in signed-by.", vo));
                }

                return SignaturePolicy.newBuilder()
                        .setSignedBy(identities.getKeysIndex((String) vo))
                        .build();

            } else {

                Matcher match = noofPattern.matcher(key);

                if (match.matches() && match.groupCount() == 1) {

                    String matchStingNo = match.group(1).trim();
                    int matchNo = Integer.parseInt(matchStingNo);

                    if (!(vo instanceof List)) {
                        throw new ChaincodeEndorsementPolicyParseException(format("%s expected to have list but found %s.", key, String.valueOf(vo)));
                    }

                    @SuppressWarnings ("unchecked") final List<Map<?, ?>> voList = (List<Map<?, ?>>) vo;

                    if (voList.size() < matchNo) {

                        throw new ChaincodeEndorsementPolicyParseException(format("%s expected to have at least %d items to match but only found %d.", key, matchNo, voList.size()));
                    }

                    SignaturePolicy.NOutOf.Builder spBuilder = SignaturePolicy.NOutOf.newBuilder()
                            .setN(matchNo);

                    for (Map<?, ?> nlo : voList) {

                        SignaturePolicy sp = parsePolicy(identities, nlo);
                        spBuilder.addRules(sp);

                    }

                    return SignaturePolicy.newBuilder().setNOutOf(spBuilder.build()).build();

                } else {

                    throw new ChaincodeEndorsementPolicyParseException(format("Unsupported policy type %s", key));
                }

            }

        }
        throw new ChaincodeEndorsementPolicyParseException("No values found for policy");

    }

    private static IndexedHashMap<String, MSPPrincipal> parseIdentities(Map<?, ?> identities) throws ChaincodeEndorsementPolicyParseException {
        //Only Role types are excepted at this time.

        IndexedHashMap<String, MSPPrincipal> ret = new IndexedHashMap<>();

        for (Map.Entry<?, ?> kp : identities.entrySet()) {
            Object key = kp.getKey();
            Object val = kp.getValue();

            if (!(key instanceof String)) {
                throw new ChaincodeEndorsementPolicyParseException(format("In identities key expected String got %s ", key == null ? "null" : key.getClass().getName()));
            }

            if (null != ret.get(key)) {
                throw new ChaincodeEndorsementPolicyParseException(format("In identities with key %s is listed more than once ", key));
            }

            if (!(val instanceof Map)) {
                throw new ChaincodeEndorsementPolicyParseException(format("In identities with key %s value expected Map got %s ", key, val == null ? "null" : val.getClass().getName()));
            }

            Object role = ((Map<?, ?>) val).get("role");

            if (!(role instanceof Map)) {
                throw new ChaincodeEndorsementPolicyParseException(format("In identities with key %s value expected Map for role got %s ", key, role == null ? "null" : role.getClass().getName()));
            }
            final Map<?, ?> roleMap = (Map<?, ?>) role;

            Object name = (roleMap).get("name");

            if (!(name instanceof String)) {
                throw new ChaincodeEndorsementPolicyParseException(format("In identities with key %s name expected String in role got %s ", key, name == null ? "null" : name.getClass().getName()));
            }
            if (!"member".equals(name) && !"admin".equals(name)) {

                throw new ChaincodeEndorsementPolicyParseException(format("In identities with key %s name expected member or admin  in role got %s ", key, name));
            }

            Object mspId = roleMap.get("mspId");

            if (!(mspId instanceof String)) {
                throw new ChaincodeEndorsementPolicyParseException(format("In identities with key %s mspId expected String in role got %s ", key, mspId == null ? "null" : mspId.getClass().getName()));
            }

            if (StringUtil.isNullOrEmpty((String) mspId)) {

                throw new ChaincodeEndorsementPolicyParseException(format("In identities with key %s mspId must not be null or empty String in role ", key));

            }

            MSPRole mspRole = MSPRole.newBuilder().setRole(name.equals("member") ? MSPRole.MSPRoleType.MEMBER : MSPRole.MSPRoleType.ADMIN)
                    .setMspIdentifier((String) mspId).build();

            MSPPrincipal principal = MSPPrincipal.newBuilder()
                    .setPrincipalClassification(MSPPrincipal.Classification.ROLE)
                    .setPrincipal(mspRole.toByteString()).build();

            ret.put((String) key, principal);

        }

        if (ret.size() == 0) {
            throw new ChaincodeEndorsementPolicyParseException("No identities were found in the policy specification");
        }

        return ret;

    }

    /**
     * constructs a ChaincodeEndorsementPolicy object with the actual policy gotten from the file system
     *
     * @param policyFile The file containing the policy
     * @throws IOException
     */
    public void fromFile(File policyFile) throws IOException {
        InputStream is = new FileInputStream(policyFile);
        policyBytes = IOUtils.toByteArray(is);
    }

    /**
     * From a yaml file
     *
     * @param yamlPolicyFile File location for the chaincode endorsement policy specification.
     * @throws IOException
     * @throws ChaincodeEndorsementPolicyParseException
     */

    public void fromYamlFile(File yamlPolicyFile) throws IOException, ChaincodeEndorsementPolicyParseException {
        final Yaml yaml = new Yaml();
        final Map<?, ?> load = (Map<?, ?>) yaml.load(new FileInputStream(yamlPolicyFile));

        Map<?, ?> mp = (Map<?, ?>) load.get("policy");

        if (null == mp) {
            throw new ChaincodeEndorsementPolicyParseException("The policy file has no policy section");
        }

        IndexedHashMap<String, MSPPrincipal> identities = parseIdentities((Map<?, ?>) load.get("identities"));

        SignaturePolicy sp = parsePolicy(identities, mp);

        policyBytes = Policies.SignaturePolicyEnvelope.newBuilder()
                .setVersion(0)
                .addAllIdentities(identities.values())
                .setRule(sp)
                .build().toByteArray();
    }

    /**
     * Construct a chaincode endorsement policy from a stream.
     *
     * @param inputStream
     * @throws IOException
     */

    public void fromStream(InputStream inputStream) throws IOException {
        policyBytes = IOUtils.toByteArray(inputStream);
    }

    /**
     * sets the ChaincodeEndorsementPolicy from a byte array
     *
     * @param policyAsBytes the byte array containing the serialized policy
     */
    public void fromBytes(byte[] policyAsBytes) {
        this.policyBytes = policyAsBytes;
    }

    /**
     * @return the policy serialized per protobuf and ready for inclusion into the various Block/Envelope/ChaincodeInputSpec structures
     */
    public byte[] getChaincodeEndorsementPolicyAsBytes() {
        return policyBytes;
    }

    @SuppressWarnings ("serial")
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
