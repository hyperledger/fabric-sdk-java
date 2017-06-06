/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.net.MalformedURLException;

import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.junit.Assert;
import org.junit.Test;

public class HFCAClientTest {
    public static class MemberServicesFabricCAImplTest {

        @Test
        public void testCOPCreation() {

            try {
                HFCAClient memberServices = HFCAClient.createNewInstance("http://localhost:99", null);
                Assert.assertNotNull(memberServices);
                Assert.assertSame(HFCAClient.class, memberServices.getClass());

            } catch (Exception e) {
                Assert.fail("Unexpected Exception " + e.getMessage());
            }
        }

        @Test
        public void testNullURL() {

            try {
                HFCAClient.createNewInstance(null, null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), MalformedURLException.class);

            }
        }

        @Test
        public void emptyURL() {

            try {
                HFCAClient.createNewInstance("", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), MalformedURLException.class);

            }
        }

        @Test
        public void testBadProto() {

            try {
                HFCAClient.createNewInstance("file://localhost", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), IllegalArgumentException.class);

            }
        }

        @Test
        public void testBadURLPath() {

            try {
                HFCAClient.createNewInstance("http://localhost/bad", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), IllegalArgumentException.class);

            }
        }

        @Test
        public void testBadURLQuery() {

            try {
                HFCAClient.createNewInstance("http://localhost?bad", null);
                Assert.fail("Expected exception");

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), IllegalArgumentException.class);

            }
        }

        @Test
        public void testNewInstanceNameUrlProperties() {

            try {
                HFCAClient memberServices = HFCAClient.createNewInstance("name", "http://localhost:99", null);
                Assert.assertNotNull(memberServices);
                Assert.assertSame(HFCAClient.class, memberServices.getClass());

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), IllegalArgumentException.class);

            }
        }

        @Test
        public void testNewInstanceNameUrlPropertiesSetNullName() {

            try {
                HFCAClient.createNewInstance(null, "http://localhost:99", null);
                Assert.fail("Expected exception when name is set to null");

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), InvalidArgumentException.class);
                Assert.assertEquals(e.getMessage(), "name must not be null or an empty string.");

            }
        }

        @Test
        public void testNewInstanceNameUrlPropertiesSetEmptyName() {

            try {
                HFCAClient.createNewInstance("", "http://localhost:99", null);
                Assert.fail("Expected exception when name is set to null");

            } catch (Exception e) {
                Assert.assertSame(e.getClass(), InvalidArgumentException.class);
                Assert.assertEquals(e.getMessage(), "name must not be null or an empty string.");

            }
        }
    }
}
