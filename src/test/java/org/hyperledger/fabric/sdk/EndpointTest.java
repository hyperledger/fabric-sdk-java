/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import org.junit.Assert;
import org.junit.Test;
import org.junit.Ignore;

//@Ignore
public class EndpointTest {
	@Test
	public void testEndpointNonPEM() {
		Endpoint ep = new Endpoint("grpc://localhost:524", null);
		Assert.assertEquals("localhost", ep.getHost());
		Assert.assertEquals(524, ep.getPort());

		ep = new Endpoint( "grpcs://localhost:524", null);
		Assert.assertEquals("localhost", ep.getHost());

		try {
			ep = new Endpoint("grpcs2://localhost:524",null);
			Assert.fail("protocol grpcs2 should have been invalid");
		} catch(RuntimeException rex) {
			Assert.assertEquals("Invalid protocol expected grpc or grpcs and found grpcs2.", rex.getMessage());
		}

		try {
			ep = new Endpoint("grpcs://localhost", null);
			Assert.fail("should have thrown error as there is no port in the url");
		} catch(RuntimeException rex) {
			Assert.assertEquals("URL must be of the format protocol://host:port", rex.getMessage());
		}

		try {
			ep = new Endpoint("", null);
			Assert.fail("should have thrown error as url is empty");
		} catch(RuntimeException rex) {
			Assert.assertEquals("URL cannot be null or empty", rex.getMessage());
		}

		try {
			ep = new Endpoint(null, null);
			Assert.fail("should have thrown error as url is empty");
		} catch(RuntimeException rex) {
			Assert.assertEquals("URL cannot be null or empty", rex.getMessage());
		}
	}


}
