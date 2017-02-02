/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.hyperledger.fabric.sdk;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.junit.Assert;
import org.junit.Test;
import org.junit.Ignore;

@Ignore
public class SDKUtilTest {

	@Test
	public void testGenerateParameterHash() {
		List<String> args = new ArrayList<>();
		args.add("a");
		args.add("b");
		String hash = SDKUtil.generateParameterHash("mypath", "myfunc", args);
		Assert.assertEquals(Hex.toHexString(SDKUtil.hash("mypathmyfuncab".getBytes(), new SHA3Digest())), hash);
	}

	@Test
	@Ignore //TODO NEED to bring back ?
	public void testGenerateDirectoryHash() throws IOException {
		// valid hash
		String hash = SDKUtil.generateDirectoryHash(System.getenv("GOPATH"), "/src/github.com/hyperledger/fabric/examples/chaincode/java/Example", "");
		Assert.assertEquals("3c08029b52176eacf802dee93129a9f1fd115008950e1bb968465dcd51bbbb9d", hash);

		// non-existing directory
		try {
			SDKUtil.generateDirectoryHash(null, "/src/github.com/hyperledger/fabric/examples/chaincode/java/Example", "");
			Assert.fail("Should have failed as the directory does not exist");
		} catch(IOException iex) {
			Assert.assertEquals(String.format("The chaincode path \"%s\" is invalid", Paths.get("/src/github.com/hyperledger/fabric/examples/chaincode/java/Example")), iex.getMessage());
		}

		//create an empty directory and test on that
		File file = new File(System.getProperty("java.io.tmpdir")+File.separator+"testdir");
		file.mkdir();

		try {
			SDKUtil.generateDirectoryHash(null, file.getAbsolutePath(), "");
			Assert.fail("Should have failed as the directory is empty");
		} catch(IOException iex) {
			Assert.assertEquals(String.format("The chaincode directory \"%s\" has no files", file.getAbsolutePath()), iex.getMessage());
		} finally {
			file.delete();
		}
	}

	@Test
	@Ignore //TODO NEED to bring back ?
	public void testReadFileFromClasspath() throws IOException {
		byte[] data = SDKUtil.readFileFromClasspath("Go.Docker");
		Assert.assertNotNull(data);
		Assert.assertTrue(data.length > 0);

		data = SDKUtil.readFileFromClasspath("Java.Docker");
		Assert.assertNotNull(data);
		Assert.assertTrue(data.length > 0);
	}
}
