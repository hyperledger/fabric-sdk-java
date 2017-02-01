package org.hyperledger.fabric.sdk;

import org.junit.Assert;
import org.junit.Test;
import org.junit.Ignore;

@Ignore
public class EndpointTest {
	@Test
	public void testEndpointNonPEM() {
		Endpoint ep = new Endpoint("grpc://localhost:524", "");
		Assert.assertEquals("localhost", ep.getHost());
		Assert.assertEquals(524, ep.getPort());

		ep = new Endpoint("grpcs://localhost:524", "");
		Assert.assertEquals("localhost", ep.getHost());

		try {
			ep = new Endpoint("grpcs2://localhost:524", "");
			Assert.fail("protocol grpcs2 should have been invalid");
		} catch(RuntimeException rex) {
			Assert.assertEquals("invalid protocol: grpcs2", rex.getMessage());
		}

		try {
			ep = new Endpoint("grpcs://localhost", "");
			Assert.fail("should have thrown error as there is no port in the url");
		} catch(RuntimeException rex) {
			Assert.assertEquals("URL must be of the format protocol://host:port", rex.getMessage());
		}

		try {
			ep = new Endpoint("", "");
			Assert.fail("should have thrown error as url is empty");
		} catch(RuntimeException rex) {
			Assert.assertEquals("URL cannot be null or empty", rex.getMessage());
		}

		try {
			ep = new Endpoint(null, "");
			Assert.fail("should have thrown error as url is empty");
		} catch(RuntimeException rex) {
			Assert.assertEquals("URL cannot be null or empty", rex.getMessage());
		}
	}

	//TODO: Write test cases for SSL
	//TODO: Write test cases for channel builder
}
