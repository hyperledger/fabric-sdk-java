/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric_ca.sdk;

import javax.json.JsonObject;
import org.junit.Assert;
import org.junit.Test;

public class AttributeTest {
    private static final String attrName = "some name";
    private static final String attrValue = "some value";

    @Test
    public void testNewInstance() {

        try {
            Attribute testAttribute = new Attribute(attrName, attrValue);
            Assert.assertNotNull(testAttribute.getName());
            Assert.assertSame(testAttribute.getName(), attrName);
            Assert.assertNotNull(testAttribute.getValue());
            Assert.assertSame(testAttribute.getValue(), attrValue);

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }

    @Test
    public void testJsonBuild() {

        try {
            Attribute testAttribute = new Attribute(attrName, attrValue);
            JsonObject attrJson = testAttribute.toJsonObject();
            Assert.assertNotNull(attrJson);
            Assert.assertEquals(attrJson.getString("name"), attrName);
            Assert.assertEquals(attrJson.getString("value"), attrValue);

        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
}
