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

package org.hyperledger.fabric.sdk;

import java.io.ByteArrayInputStream;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

import javax.json.JsonObject;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LifecycleChaincodePackageTest {

    @Test
    public void testGoLangCode() throws Exception {
        LifecycleChaincodePackage lifecycleChaincodePackage = LifecycleChaincodePackage.fromSource("mylabel", Paths.get("src/test/fixture/sdkintegration/gocc/sample1"),
                TransactionRequest.Type.GO_LANG,
                "github.com/example_cc", Paths.get("src/test/fixture/meta-infs/end2endit"));

        assertNotNull(lifecycleChaincodePackage.getAsBytes());
        assertTrue(lifecycleChaincodePackage.getAsBytes().length > 1);

        JsonObject metaInfJson = lifecycleChaincodePackage.getMetaInfJson();
        Assert.assertEquals(metaInfJson.getString("path"), "github.com/example_cc");
        Assert.assertEquals(metaInfJson.getString("type"), "golang");
        Assert.assertEquals(lifecycleChaincodePackage.getType(), TransactionRequest.Type.GO_LANG);
        Assert.assertEquals(lifecycleChaincodePackage.getPath(), "github.com/example_cc");
        Assert.assertEquals(lifecycleChaincodePackage.getLabel(), "mylabel");

        byte[] chaincodePayloadBytes = lifecycleChaincodePackage.getChaincodePayloadBytes();
        assertNotNull(chaincodePayloadBytes);
        assertTrue(chaincodePayloadBytes.length > 1);

        Set<String> cpset = new HashSet<>(2); //files we expect.

        cpset.add("src/github.com/example_cc/example_cc.go");
        cpset.add("META-INF/statedb/couchdb/indexes/IndexA.json");

        try (TarArchiveInputStream tarInput = new TarArchiveInputStream(new GzipCompressorInputStream(new ByteArrayInputStream(chaincodePayloadBytes)))) {

            TarArchiveEntry currentEntry = tarInput.getNextTarEntry();
            while (currentEntry != null) {
                cpset.add(currentEntry.getName());

                assertTrue("Entry is not a file. " + currentEntry.getName(), currentEntry.isFile());

                assertTrue("Missing: " + currentEntry.getName(), cpset.remove(currentEntry.getName()));

                currentEntry = tarInput.getNextTarEntry();
            }
        }
        if (!cpset.isEmpty()) {
            fail("Not all expected tar entries found! " + cpset.toString());
        }

    }

}
