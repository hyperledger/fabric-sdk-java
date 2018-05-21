/*
 *
 *  Copyright 2018 IBM - All Rights Reserved.
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.hyperledger.fabric.protos.common.Collection.CollectionConfig;
import org.hyperledger.fabric.protos.common.Collection.CollectionConfigPackage;
import org.hyperledger.fabric.protos.common.Collection.CollectionPolicyConfig;
import org.hyperledger.fabric.protos.common.Collection.StaticCollectionConfig;
import org.hyperledger.fabric.protos.common.MspPrincipal;
import org.hyperledger.fabric.protos.common.Policies;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ChaincodeCollectionConfigTest {

    private static final String CHANNEL_NAME = "myChannel";
    private static final String CLIENT_ORG_NAME = "Org1";

    private static final String USER_NAME = "MockMe";
    private static final String USER_MSP_ID = "MockMSPID";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testLoadFromConfigNullStream() throws Exception {

        // Should not be able to instantiate a new instance of "Client" without a valid path to the configuration');
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("configStream must be specified");

        ChaincodeCollectionConfiguration.fromJsonStream((InputStream) null);
    }

    @Test
    public void testLoadFromConfigNullYamlFile() throws Exception {
        // Should not be able to instantiate a new instance of "Client" without a valid path to the configuration');
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("configFile must be specified");

        ChaincodeCollectionConfiguration.fromYamlFile((File) null);
    }

    @Test
    public void testLoadFromConfigNullJsonFile() throws Exception {
        // Should not be able to instantiate a new instance of "Client" without a valid path to the configuration');
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("configFile must be specified");

        ChaincodeCollectionConfiguration.fromJsonFile((File) null);
    }

    @Test
    public void testLoadFromConfigYamlFileNotExists() throws Exception {

        // Should not be able to instantiate a new instance of "Client" without an actual configuration file
        thrown.expect(FileNotFoundException.class);
        thrown.expectMessage("FileDoesNotExist.yaml");

        File f = new File("FileDoesNotExist.yaml");
        ChaincodeCollectionConfiguration.fromYamlFile(f);

    }

    @Test
    public void testLoadFromConfigJsonFileNotExists() throws Exception {

        // Should not be able to instantiate a new instance of "Client" without an actual configuration file
        thrown.expect(FileNotFoundException.class);
        thrown.expectMessage("FileDoesNotExist.json");

        File f = new File("FileDoesNotExist.json");
        ChaincodeCollectionConfiguration.fromJsonFile(f);

    }

    @Test
    public void testLoadFromConfigFileYamlBasic() throws Exception {

        File f = new File("src/test/fixture/collectionProperties/testCollection.yaml");
        ChaincodeCollectionConfiguration config = ChaincodeCollectionConfiguration.fromYamlFile(f);
        assertNotNull(config);
        byte[] configAsBytes = config.getAsBytes();
        assertNotNull(configAsBytes);
        assertEquals(configAsBytes.length, 137);
        CollectionConfigPackage collectionConfigPackage = CollectionConfigPackage.parseFrom(configAsBytes);
        assertEquals(collectionConfigPackage.getConfigCount(), 1);
        CollectionConfig colConfig = collectionConfigPackage.getConfig(0);
        assertNotNull(colConfig);

        StaticCollectionConfig staticCollectionConfig = colConfig.getStaticCollectionConfig();
        assertNotNull(staticCollectionConfig);
        assertEquals(staticCollectionConfig.getBlockToLive(), 3);
        assertEquals(staticCollectionConfig.getName(), "rick");
        assertEquals(staticCollectionConfig.getMaximumPeerCount(), 9);
        assertEquals(staticCollectionConfig.getRequiredPeerCount(), 7);
        CollectionPolicyConfig memberOrgsPolicy = staticCollectionConfig.getMemberOrgsPolicy();
        assertNotNull(memberOrgsPolicy);
        Policies.SignaturePolicyEnvelope signaturePolicy = memberOrgsPolicy.getSignaturePolicy();
        assertNotNull(signaturePolicy);
        assertEquals(signaturePolicy.getVersion(), 0);
        Policies.SignaturePolicy rule = signaturePolicy.getRule();
        assertNotNull(rule);
        assertEquals(rule.getTypeCase(), Policies.SignaturePolicy.TypeCase.N_OUT_OF);
        Policies.SignaturePolicy.NOutOf nOutOf = rule.getNOutOf();
        assertNotNull(nOutOf);
        assertEquals(2, nOutOf.getN());

        List<MspPrincipal.MSPPrincipal> identitiesList = signaturePolicy.getIdentitiesList();
        assertNotNull(identitiesList);
        assertEquals(3, identitiesList.size());

    }

    @Test
    public void testLoadFromConfigFileJsonBasic() throws Exception {

        File f = new File("src/test/fixture/collectionProperties/testCollection.yaml");
        ChaincodeCollectionConfiguration configYAML = ChaincodeCollectionConfiguration.fromYamlFile(f);
        assertNotNull(configYAML);
        byte[] configAsBytesYAML = configYAML.getAsBytes();
        assertNotNull(configAsBytesYAML);
        assertEquals(configAsBytesYAML.length, 137);

        f = new File("src/test/fixture/collectionProperties/testCollection.json");
        ChaincodeCollectionConfiguration configJson = ChaincodeCollectionConfiguration.fromJsonFile(f);
        assertNotNull(configJson);
        byte[] configAsBytesJson = configYAML.getAsBytes();
        assertNotNull(configAsBytesJson);
        assertEquals(configAsBytesJson.length, 137);

        assertTrue(Arrays.equals(configAsBytesYAML, configAsBytesJson));

    }

    @Test
    public void fromCollectionConfigPackageNULL() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("collectionConfigPackage must be specified");

        ChaincodeCollectionConfiguration.fromCollectionConfigPackage(null);

    }

    @Test
    public void fromCollectionConfigPackageAndStream() throws Exception {

        String yaml = "---\n" +
                "  - StaticCollectionConfig: \n" +
                "       name: rick \n" +
                "       blockToLive: 9999 \n" +
                "       maximumPeerCount: 0\n" +
                "       requiredPeerCount: 0\n" +
                "       SignaturePolicyEnvelope:\n" +
                "         identities:\n" +
                "             - user1: {\"role\": {\"name\": \"member\", \"mspId\": \"Org1MSP\"}}\n" +
                "         policy:\n" +
                "             1-of:\n" +
                "               - signed-by: \"user1\"";

        ChaincodeCollectionConfiguration chaincodeCollectionConfiguration =
                ChaincodeCollectionConfiguration.fromYamlStream(new ByteArrayInputStream(yaml.getBytes(UTF_8)));

        ChaincodeCollectionConfiguration chaincodeCollectionConfigurationFromProto =
                ChaincodeCollectionConfiguration.fromCollectionConfigPackage(CollectionConfigPackage.parseFrom(chaincodeCollectionConfiguration.getAsBytes()));

        assertTrue(Arrays.equals(chaincodeCollectionConfiguration.getAsBytes(),
                chaincodeCollectionConfigurationFromProto.getAsBytes()));

    }

}
