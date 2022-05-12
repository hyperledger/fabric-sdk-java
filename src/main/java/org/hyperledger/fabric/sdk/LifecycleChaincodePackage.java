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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.helper.Utils;

import static java.lang.String.format;

/**
 * A wrapper for the Hyperledger Fabric Policy object
 */
public class LifecycleChaincodePackage {

    private static final Log logger = LogFactory.getLog(LifecycleChaincodePackage.class);
    // private static final boolean IS_DEBUG_LEVEL = logger.isDebugEnabled();

    private static final Config config = Config.getConfig();
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;

    private final byte[] pBytes;

    private LifecycleChaincodePackage(byte[] packageBytes) {

        pBytes = new byte[packageBytes.length];
        System.arraycopy(packageBytes, 0, pBytes, 0, packageBytes.length); //make sure we keep our own copy.

    }

    /**
     * constructs a ChaincodeEndorsementPolicy object with the actual policy gotten from the file system
     *
     * @param policyFile The file containing the policy
     * @throws IOException
     */
    public static LifecycleChaincodePackage fromFile(File policyFile) throws IOException, InvalidArgumentException {
        if (null == policyFile) {
            throw new InvalidArgumentException("The parameter policyFile may not be null.");
        }
        try (InputStream is = new FileInputStream(policyFile)) {
            byte[] packageBytes = IOUtils.toByteArray(is);
            return fromBytes(packageBytes);
        }
    }

    /**
     * Construct a LifecycleChaincodePackage from a stream.
     *
     * @param inputStream The stream containing the lifecycle chaincode package. This stream is NOT closed.
     * @throws IOException
     */

    public static LifecycleChaincodePackage fromStream(InputStream inputStream) throws IOException, InvalidArgumentException {
        if (null == inputStream) {
            throw new InvalidArgumentException("The parameter inputStream may not be null.");
        }
        byte[] packageBytes = IOUtils.toByteArray(inputStream);
        return fromBytes(packageBytes);
    }

    /**
     * Sets the LifecycleChaincodePackage from a byte array
     *
     * @param packageBytes the byte array containing the serialized policy
     */
    public static LifecycleChaincodePackage fromBytes(byte[] packageBytes) throws InvalidArgumentException {
        if (null == packageBytes) {
            throw new InvalidArgumentException("The parameter packageBytes may not be null.");
        }
        return new LifecycleChaincodePackage(packageBytes);
    }

    /**
     * Lifecycle chaincode package as bytes
     *
     * @return Lifecycle chaincode package as bytes.
     */
    public byte[] getAsBytes() {

        byte[] ret = new byte[pBytes.length];
        System.arraycopy(pBytes, 0, ret, 0, pBytes.length); //make sure we keep our own copy.
        return ret;
    }

    /**
     * Write Lifecycle chaincode package bytes to file.
     *
     * @param path    of the file to write to.
     * @param options Options on creating file.
     * @throws IOException
     */

    public void toFile(Path path, OpenOption... options) throws IOException {
        Files.write(path, pBytes, options);

    }

    /**
     * @param label                    Any name you like to identify this package.
     * @param chaincodeSource          Chaincode source directory.
     * @param chaincodeType            Chaincode type GO, JAVA.
     * @param chaincodePath            Only valid for GO LANG chaincode. Otherwise, null.
     * @param chaincodeMetaInfLocation MetaInf location. Can be null.
     * @return
     * @throws IOException
     */

    public static LifecycleChaincodePackage fromSource(String label, Path chaincodeSource, TransactionRequest.Type chaincodeType, String chaincodePath, Path chaincodeMetaInfLocation) throws IOException, InvalidArgumentException {
        if (Utils.isNullOrEmpty(label)) {
            throw new InvalidArgumentException("The parameter label may not be null or empty.");
        }
        if (null == chaincodeSource) {
            throw new InvalidArgumentException(" The parameter chaincodeSource may not be null.");
        }
        if (null == chaincodeType) {
            throw new InvalidArgumentException(" The parameter chaincodeType may not be null.");
        }

        byte[] mataDataBytes = generatePackageMataDataBytes(label, chaincodePath, chaincodeType);
        byte[] dataBytes = generatePackageDataBytes(chaincodeSource, chaincodeMetaInfLocation, chaincodeType, chaincodePath);

        ByteArrayOutputStream bos = new ByteArrayOutputStream(500000);

        // String sourcePath = sourceDirectory.getAbsolutePath();

        TarArchiveOutputStream archiveOutputStream = new TarArchiveOutputStream(new GzipCompressorOutputStream(bos));
        archiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

        TarArchiveEntry archiveEntry = new TarArchiveEntry("metadata.json");
        archiveEntry.setMode(0100644);
        archiveEntry.setSize(mataDataBytes.length);
        archiveOutputStream.putArchiveEntry(archiveEntry);
        archiveOutputStream.write(mataDataBytes);
        archiveOutputStream.closeArchiveEntry();

        archiveEntry = new TarArchiveEntry("code.tar.gz");
        archiveEntry.setMode(0100644);
        archiveEntry.setSize(dataBytes.length);
        archiveOutputStream.putArchiveEntry(archiveEntry);
        archiveOutputStream.write(dataBytes);
        archiveOutputStream.closeArchiveEntry();
        archiveOutputStream.close();

        return fromBytes(bos.toByteArray());
    }

    static byte[] generatePackageDataBytes(Path chaincodeSource, Path chaincodeMetaInfLocation, TransactionRequest.Type chaincodeLanguage, String chaincodePath) throws IOException {
        logger.debug("generatePackageDataBytes");

        if (null == chaincodeSource) {
            throw new IllegalArgumentException("Missing chaincodeSource ");
        }

        final Chaincode.ChaincodeSpec.Type ccType;
        File projectSourceDir = null;
        String targetPathPrefix = null;
        String dplang;

        File metainf = null;
        if (null != chaincodeMetaInfLocation) {

            File chaincodemetainflocation = chaincodeMetaInfLocation.toFile();

            if (!chaincodemetainflocation.exists()) {
                throw new IllegalArgumentException(format("Directory to find chaincode META-INF %s does not exist", chaincodemetainflocation.getAbsolutePath()));
            }

            if (!chaincodemetainflocation.isDirectory()) {
                throw new IllegalArgumentException(format("Directory to find chaincode META-INF %s is not a directory", chaincodemetainflocation.getAbsolutePath()));
            }
            metainf = new File(chaincodemetainflocation, "META-INF");
            logger.trace("META-INF directory is " + metainf.getAbsolutePath());
            if (!metainf.exists()) {

                throw new IllegalArgumentException(format("The META-INF directory does not exist in %s", chaincodemetainflocation.getAbsolutePath()));
            }

            if (!metainf.isDirectory()) {
                throw new IllegalArgumentException(format("The META-INF in %s is not a directory.", chaincodemetainflocation.getAbsolutePath()));
            }
            File[] files = metainf.listFiles();

            if (files == null) {
                throw new IllegalArgumentException("null for listFiles on: " + chaincodemetainflocation.getAbsolutePath());
            }

            if (files.length < 1) {

                throw new IllegalArgumentException(format("The META-INF directory %s is empty.", metainf.getAbsolutePath()));
            }

            logger.trace(format("chaincode META-INF found %s", metainf.getAbsolutePath()));

        }

        switch (chaincodeLanguage) {
            case GO_LANG:

                // chaincodePath is mandatory
                // chaincodeSource may be a File or InputStream

                //   Verify that chaincodePath is being passed
                if (Utils.isNullOrEmpty(chaincodePath)) {
                    throw new IllegalArgumentException("Missing chaincodePath in InstallRequest");
                }

                dplang = "Go";
                ccType = Chaincode.ChaincodeSpec.Type.GOLANG;

                projectSourceDir = Paths.get(chaincodeSource.toString(), "src", chaincodePath).toFile();
                targetPathPrefix = Paths.get("src", chaincodePath).toString();
                break;

            case JAVA:

                // chaincodePath is not applicable and must be null
                // chaincodeSource may be a File or InputStream

                //   Verify that chaincodePath is null
                if (!Utils.isNullOrEmpty(chaincodePath)) {
                    throw new IllegalArgumentException("chaincodePath must be null for Java chaincode");
                }

                dplang = "Java";
                ccType = Chaincode.ChaincodeSpec.Type.JAVA;

                targetPathPrefix = "src";
                projectSourceDir = Paths.get(chaincodeSource.toString()).toFile();
                break;

            case NODE:

                // chaincodePath is not applicable and must be null
                // chaincodeSource may be a File or InputStream

                //   Verify that chaincodePath is null
                if (!Utils.isNullOrEmpty(chaincodePath)) {
                    throw new IllegalArgumentException("chaincodePath must be null for Node chaincode");
                }

                dplang = "Node";
                ccType = Chaincode.ChaincodeSpec.Type.NODE;

                projectSourceDir = Paths.get(chaincodeSource.toString()).toFile();
                targetPathPrefix = "src"; //Paths.get("src", chaincodePath).toString();
                break;
            default:
                throw new IllegalArgumentException("Unexpected chaincode language: " + chaincodeLanguage);
        }

        byte[] data = null;
        //    String chaincodeID = chaincodeName + "::" + chaincodePath + "::" + chaincodeVersion;

        if (!projectSourceDir.exists()) {
            final String message = "The project source directory does not exist: " + projectSourceDir.getAbsolutePath();
            logger.error(message);
            throw new IllegalArgumentException(message);
        }
        if (!projectSourceDir.isDirectory()) {
            final String message = "The project source directory is not a directory: " + projectSourceDir.getAbsolutePath();
            logger.error(message);
            throw new IllegalArgumentException(message);
        }

        logger.debug(format("Creating chaincode package language %s chaincode from directory: '%s' with source location: '%s'. chaincodePath:'%s'",
                dplang, projectSourceDir.getAbsolutePath(), targetPathPrefix, chaincodePath));

        // generate chaincode source tar
        data = Utils.generateTarGz(projectSourceDir, targetPathPrefix, metainf);

        if (null != diagnosticFileDumper) {

            logger.trace(format("Creatating chaincode package language %s chaincode from directory: '%s' with source location: '%s'. chaincodePath:'%s' tar file dump %s",
                    dplang, projectSourceDir.getAbsolutePath(), targetPathPrefix,
                    chaincodePath, diagnosticFileDumper.createDiagnosticTarFile(data)));
        }

        return data;
    }

    static byte[] generatePackageMataDataBytes(String label, String path, TransactionRequest.Type type) {
        JsonObject metadata = Json.createObjectBuilder()
                .add("path", path != null ? path : "")
                .add("type", type.toPackageName())
                .add("label", label)
                .build();

        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream()) {
            try (JsonWriter writer = Json.createWriter(byteStream)) {
                writer.writeObject(metadata);
            }
            return byteStream.toByteArray();
        } catch (IOException e) {
            // Never happens with ByteArrayOutputStream
            throw new UncheckedIOException(e);
        }
    }

    public JsonObject getMetaInfJson() throws IOException {

        try (TarArchiveInputStream tarInput = new TarArchiveInputStream(new GzipCompressorInputStream(new ByteArrayInputStream(pBytes)))) {

            TarArchiveEntry currentEntry = tarInput.getNextTarEntry();
            while (currentEntry != null) {
                if (currentEntry.getName().equals("metadata.json")) {
                    byte[] buf = new byte[(int) currentEntry.getSize()];
                    tarInput.read(buf, 0, (int) currentEntry.getSize());

                    try (InputStream stream = new ByteArrayInputStream(buf)) {
                        try (JsonReader reader = Json.createReader(stream)) {

                            return (JsonObject) reader.read();
                        }
                    }

                }
                currentEntry = tarInput.getNextTarEntry();

            }
        }

        return null;
    }

    public byte[] getChaincodePayloadBytes() throws IOException {

        try (TarArchiveInputStream tarInput = new TarArchiveInputStream(new GzipCompressorInputStream(new ByteArrayInputStream(pBytes)))) {

            TarArchiveEntry currentEntry = tarInput.getNextTarEntry();
            while (currentEntry != null) {
                if (!currentEntry.getName().equals("metadata.json")) { // right now anything but this
                    byte[] buf = new byte[(int) currentEntry.getSize()];
                    tarInput.read(buf, 0, (int) currentEntry.getSize());

                    return buf;

                }
                currentEntry = tarInput.getNextTarEntry();
            }
        }

        return null;
    }

    public TransactionRequest.Type getType() throws IOException {
        JsonObject metaInfJson = getMetaInfJson();
        if (null != metaInfJson) {

            String type = metaInfJson.containsKey("type") ? metaInfJson.getString("type") : null;
            if (null != type) {

                return TransactionRequest.Type.fromPackageName(type);
            }
        }
        return null;
    }

    public String getLabel() throws IOException {
        JsonObject metaInfJson = getMetaInfJson();
        if (null != metaInfJson) {

            String label = metaInfJson.containsKey("label") ? metaInfJson.getString("label") : null;
            if (null != label) {

                return label;
            }
        }
        return null;
    }

    public String getPath() throws IOException {
        JsonObject metaInfJson = getMetaInfJson();
        if (null != metaInfJson) {

            return metaInfJson.containsKey("path") ? metaInfJson.getString("path") : null;
        }
        return null;
    }
}

