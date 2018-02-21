/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
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
package org.hyperledger.fabric.sdk.helper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import com.google.protobuf.ByteString;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.testutils.TestUtils.assertArrayListEquals;

public class UtilsTest {

    private static final String SAMPLE_GO_CC = "src/test/fixture/sdkintegration/gocc/sample1";
    // Create a temp folder to hold temp files for various file I/O operations
    // These are automatically deleted when each test completes
    @Rule
    public final TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void testGenerateParameterHash() {
        List<String> args = new ArrayList<>();
        args.add("a");
        args.add("b");
        String hash = Utils.generateParameterHash("mypath", "myfunc", args);
        Assert.assertEquals(Hex.toHexString(Utils.hash("mypathmyfuncab".getBytes(UTF_8), new SHA3Digest())), hash);
    }

    // Tests generateDirectoryHash passing it a null rootDir and no previous hash
    @Test
    public void testGenerateDirectoryHash() throws Exception {
        doGenerateDirectoryHash(false, false);
    }

    // Tests generateDirectoryHash passing it a rootDir and no previous hash
    @Test
    public void testGenerateDirectoryHashWithRootDir() throws Exception {
        doGenerateDirectoryHash(true, false);
    }

    // Tests generateDirectoryHash passing it a previous hash
    @Test
    public void testGenerateDirectoryHashWithPrevHash() throws Exception {
        doGenerateDirectoryHash(true, true);
    }

    // Test generateDirectoryHash with a non-existent directory
    @Test (expected = IOException.class)
    public void testGenerateDirectoryHashNoDirectory() throws Exception {
        File rootDir = tempFolder.getRoot().getAbsoluteFile();
        File nonExistentDir = new File(rootDir, "temp");

        Utils.generateDirectoryHash(null, nonExistentDir.getAbsolutePath(), "");
        Assert.fail("Expected an IOException as the directory does not exist");
    }

    // Test generateDirectoryHash with an empty directory
    @Test (expected = IOException.class)
    public void testGenerateDirectoryHashEmptyDirectory() throws Exception {
        // create an empty temp directory
        File emptyDir = tempFolder.newFolder("subfolder");

        Utils.generateDirectoryHash(null, emptyDir.getAbsolutePath(), "");
        Assert.fail("Expected an IOException as the directory is empty");
    }

    // Test generateDirectoryHash by passing it a file
    @Test (expected = IOException.class)
    public void testGenerateDirectoryHashWithFile() throws Exception {
        // Create a temp file
        File tempFile = tempFolder.newFile("temp.txt");

        Utils.generateDirectoryHash(null, tempFile.getAbsolutePath(), "");
        Assert.fail("Expected an IOException as we passed it a file");
    }

    // Test reading a small file
    @Test
    public void testReadFile() throws Exception {

        // create a small temp file
        byte[] expectedData = "TheQuickBrownFox".getBytes();
        File tempFile = tempFolder.newFile("temp.txt");
        Path file = Paths.get(tempFile.getAbsolutePath());
        Files.write(file, expectedData);

        byte[] actualData = Utils.readFile(tempFile);
        Assert.assertArrayEquals(expectedData, actualData);
    }

    // Test an attempt to read a non-existent file
    @Test (expected = IOException.class)
    public void testReadFileNoFile() throws Exception {
        File rootDir = tempFolder.getRoot().getAbsoluteFile();
        Utils.readFile(new File(rootDir, "temp.txt"));
        Assert.fail("Expected an IOException as the file does not exist");
    }

    @Test
    public void testReadFileFromClasspath() throws Exception {
        // Attempt to read the Utils class...
        byte[] data = Utils.readFileFromClasspath("org/hyperledger/fabric/sdk/helper/Utils.class");
        Assert.assertNotNull(data);
    }

    // Test an attempt to read a non-existent file from the classpath
    @Ignore // See todo comment below...
    @Test (expected = IOException.class)
    public void testReadFileFromClasspathNoFile() throws Exception {
        // Attempt to read a file that does not exist
        // TODO: readFileFromClasspath is not properly handling this use case and throws a NPE!
        // For consistency with readFile, readFileFromClasspath should throw an IOException if the file does not exist!
        byte[] data = Utils.readFileFromClasspath("a/b/c/b/a/thisfiledoesnotexist.txt");
        Assert.assertNotNull(data);
        Assert.fail("Expected an IOException as the file should not exist");
    }

    // Tests deleting a file
    @Test
    public void testDeleteFileOrDirectoryFile() throws Exception {

        // create an empty temp file
        File tempFile = tempFolder.newFile("temp.txt");

        // Ensure the file exists
        Assert.assertTrue(tempFile.exists());

        Utils.deleteFileOrDirectory(tempFile);

        // Ensure the file was deleted
        Assert.assertFalse(tempFile.exists());
    }

    // Tests deleting a directory
    @Test
    public void testDeleteFileOrDirectoryDirectory() throws Exception {

        // create a temp directory with some files in it
        File tempDir = createTempDirWithFiles();

        // Ensure the dir exists
        Assert.assertTrue(tempDir.exists());

        Utils.deleteFileOrDirectory(tempDir);

        // Ensure the file was deleted
        Assert.assertFalse(tempDir.exists());
    }

    // Test compressing a directory
    @Test
    public void testGenerateTarGz() throws Exception {

        // create a temp directory with some files in it
        File tempDir = createTempDirWithFiles();

        // Compress
        byte[] data = Utils.generateTarGz(tempDir, "newPath", null);

        // Here, we simply ensure that it did something!
        Assert.assertNotNull(data);
        Assert.assertTrue(data.length > 0);
    }

    // Test compressing an empty directory
    @Test
    public void testGenerateTarGzEmptyDirectory() throws Exception {

        // create an empty directory
        File emptyDir = tempFolder.newFolder("subfolder");
        byte[] data = Utils.generateTarGz(emptyDir, null, null);

        // Here, we simply ensure that it did something!
        Assert.assertNotNull(data);
        Assert.assertTrue(data.length > 0);
    }

    // Test compressing a non-existent directory
    // Note that this currently throws an IllegalArgumentException, and not an IOException!
    @Test (expected = IllegalArgumentException.class)
    public void testGenerateTarGzNoDirectory() throws Exception {
        File rootDir = tempFolder.getRoot().getAbsoluteFile();
        File nonExistentDir = new File(rootDir, "temp");
        Utils.generateTarGz(nonExistentDir, null, null);
        Assert.fail("Expected an IOException as the directory does not exist");
    }

    @Test
    public void testGenerateTarGzMETAINF() throws Exception {

        ArrayList<String> expect = new ArrayList(Arrays.asList(new String[] {"META-INF/statedb/couchdb/indexes/MockFakeIndex.json", "src/github.com/example_cc/example_cc.go"
        }));
        Collections.sort(expect);

        byte[] bytes = Utils.generateTarGz(new File(SAMPLE_GO_CC + "/src/github.com/example_cc"),
                "src/github.com/example_cc", new File("src/test/fixture/meta-infs/test1/META-INF"));
        Assert.assertNotNull("generateTarGz() returned null bytes.", bytes);

        ArrayList tarBytesToEntryArrayList = TestUtils.tarBytesToEntryArrayList(bytes);
        assertArrayListEquals("Tar not what expected.", expect, tarBytesToEntryArrayList);

    }

    @Test
    public void testGenerateTarGzNOMETAINF() throws Exception {

        byte[] bytes = Utils.generateTarGz(new File(SAMPLE_GO_CC + "/src/github.com/example_cc"),
                "src/github.com/", null);
        Assert.assertNotNull("generateTarGz() returned null bytes.", bytes);

        ArrayList<String> expect = new ArrayList(Arrays.asList(new String[] {"src/github.com/example_cc.go"
        }));

        ArrayList tarBytesToEntryArrayList = TestUtils.tarBytesToEntryArrayList(bytes);
        assertArrayListEquals("Tar not what expected.", expect, tarBytesToEntryArrayList);

    }



    @Test
    public void testGenerateUUID() {
        // As this is a "unique" identifier, we call the function twice to
        // ensure it doesn't return the same value
        String uuid1 = Utils.generateUUID();
        String uuid2 = Utils.generateUUID();

        Assert.assertNotNull(uuid1);
        Assert.assertNotNull(uuid2);
        Assert.assertNotEquals("gererateUUID returned a duplicate UUID!", uuid1, uuid2);

    }

    @Test
    public void testGenerateNonce() {
        // As this is a "unique" identifier, we call the function twice to
        // ensure it doesn't return the same value
        byte[] nonce1 = Utils.generateNonce();
        byte[] nonce2 = Utils.generateNonce();

        Assert.assertNotNull(nonce1);
        Assert.assertNotNull(nonce2);
        Assert.assertNotEquals("generateNonce returned a duplicate nonce!", nonce1, nonce2);

    }

    @Test
    public void testGenerateTimestamp() {
        Assert.assertNotNull(Utils.generateTimestamp());
    }

    @Test
    public void testHash() {

        byte[] input = "TheQuickBrownFox".getBytes(UTF_8);
        String expectedHash = "feb69c5c360a15802de6af23a3f5622da9d96aff2be78c8f188cce57a3549db6";

        byte[] hash = Utils.hash(input, new SHA3Digest());
        Assert.assertEquals(expectedHash, Hex.toHexString(hash));
    }

    @Test
    public void testCombinePaths() {

        String expected = "/1/2/3/4/5";

        // Deal with OS differences
        expected = expected.replace("/", File.separator);

        // Probably not really nice to do multiple tests at once, but they are
        // almost trivial anyway..

        Assert.assertEquals(expected, Utils.combinePaths("/1/2/3", "4/5"));
        Assert.assertEquals(expected, Utils.combinePaths("/1/2", "3", "4/5"));

    }

    @Test
    public void testParseGrpcUrl() {

        String url = "grpc://hyperledger.org:1234";

        Properties purl = Utils.parseGrpcUrl(url);

        Assert.assertEquals("grpc", purl.getProperty("protocol"));
        Assert.assertEquals("hyperledger.org", purl.getProperty("host"));
        Assert.assertEquals("1234", purl.getProperty("port"));
    }

    @Test
    public void testCheckGrpcUrlValid() {

        // Test a number of valid variations
        Assert.assertNull(Utils.checkGrpcUrl("grpc://hyperledger.org:1234"));
        Assert.assertNull(Utils.checkGrpcUrl("grpcs://127.0.0.1:1234"));
    }

    @Test
    public void testCheckGrpcUrlInvalid() {

        // Test a number of invalid variations
        Assert.assertNotNull(Utils.checkGrpcUrl("http://hyperledger.org:1234"));
        Assert.assertNotNull(Utils.checkGrpcUrl("grpc://hyperledger.org"));
        Assert.assertNotNull("grpc://hyperledger.org:1234/index.html");
    }

    @Test
    public void testIsNullOrEmpty() {

        // Test a number of variations
        Assert.assertTrue(Utils.isNullOrEmpty(null));
        Assert.assertTrue(Utils.isNullOrEmpty(""));

        Assert.assertFalse(Utils.isNullOrEmpty("xyzzy"));
        Assert.assertFalse(Utils.isNullOrEmpty(" "));

    }

    @Test
    public void testLogString() {

        // Test a number of variations
        Assert.assertEquals(null, Utils.logString(null));
        Assert.assertEquals("", Utils.logString(""));
        Assert.assertEquals("ab??c", Utils.logString("ab\r\nc"));
        Assert.assertEquals("ab?c", Utils.logString("ab\tc"));

    }

    @Test
    public void testToHexString() {
        Assert.assertEquals("414243", Utils.toHexString("ABC".getBytes()));
        Assert.assertEquals("41090a", Utils.toHexString(ByteString.copyFromUtf8("A\t\n")));
    }

    @Test
    public void testToHexStringNull() {
        Assert.assertNull(Utils.toHexString((byte[]) null));
        Assert.assertNull(Utils.toHexString((ByteString) null));
    }

    // ==========================================================================================
    // Helper methods
    // ==========================================================================================

    // Helper method to allow tests of multiple code paths through generateDirectoryHash
    public void doGenerateDirectoryHash(boolean useRootDir, boolean usePreviousHash) throws Exception {

        // Use any old hash value
        final String previousHashToUse = "3c08029b52176eacf802dee93129a9f1fd115008950e1bb968465dcd51bbbb9d";

        // The hashes expected when we 1: do not pass a previousHash and 2: pass
        // the previousHash
        final String expectedHash1 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        final String expectedHash2 = "6c9f96b2dd87d7a02fd3b7cc6026a6a96d21c4c53aaf5777439151690c48c7b8";
        final String expectedHash = usePreviousHash ? expectedHash2 : expectedHash1;

        String chaincodeSubDirString = "chaincode/example/java";

        // Create the temp directories
        File rootDir = tempFolder.getRoot().getAbsoluteFile();
        File chaincodeDir = new File(rootDir, chaincodeSubDirString);
        chaincodeDir.mkdirs();

        String rootDirString = null;
        String chaincodeDirString;

        if (useRootDir) {
            // Pass both a RootDir and a chaincodeDir to the function

            rootDirString = rootDir.getAbsolutePath();
            chaincodeDirString = chaincodeSubDirString;

        } else {
            // Pass just a chaincodeDir to the function
            chaincodeDirString = chaincodeDir.getAbsolutePath();
        }

        // Create a dummy file in the chaincode directory
        File tempFile = new File(chaincodeDir, "test.txt");
        tempFile.createNewFile();

        String previousHash = usePreviousHash ? previousHashToUse : "";

        String hash = Utils.generateDirectoryHash(rootDirString, chaincodeDirString, previousHash);
        Assert.assertEquals(expectedHash, hash);
    }

    // Creates a temp directory containing a couple of files
    private File createTempDirWithFiles() throws Exception {

        // create a temp directory with some files in it
        File tempDir = tempFolder.newFolder("tempDir");

        File tempFile1 = new File(tempDir, "test1.txt");
        Path file1 = Paths.get(tempFile1.getAbsolutePath());
        Files.write(file1, "TheQuickBrownFox".getBytes());

        File tempFile2 = new File(tempDir, "test2.txt");
        Path file2 = Paths.get(tempFile2.getAbsolutePath());
        Files.write(file2, "JumpsOverTheLazyDog".getBytes());

        return tempDir;
    }

}
