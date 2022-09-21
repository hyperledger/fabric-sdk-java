/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.helper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.codec.binary.Hex.encodeHexString;

public final class Utils {
    private static final Log logger = LogFactory.getLog(Utils.class);

    private static final boolean TRACE_ENABED = logger.isTraceEnabled();
    private static final Config config = Config.getConfig();
    private static final int MAX_LOG_STRING_LENGTH = config.maxLogStringLength();

    private static final Map<Class<?>, Function<String, ?>> STRING_CONVERSIONS_BY_TYPE =
            new ImmutableMap.Builder<Class<?>, Function<String, ?>>()
                    .put(Byte.class, Byte::valueOf)
                    .put(byte.class, Byte::valueOf)
                    .put(Short.class, Short::valueOf)
                    .put(short.class, Short::valueOf)
                    .put(Integer.class, Integer::valueOf)
                    .put(int.class, Integer::valueOf)
                    .put(Long.class, Long::valueOf)
                    .put(long.class, Long::valueOf)
                    .put(Float.class, Float::valueOf)
                    .put(float.class, Float::valueOf)
                    .put(Double.class, Double::valueOf)
                    .put(double.class, Double::valueOf)
                    .put(Boolean.class, Boolean::valueOf)
                    .put(boolean.class, Boolean::valueOf)
                    .put(BigInteger.class, BigInteger::new)
                    .put(BigDecimal.class, BigDecimal::new)
                    .build();

    /**
     * Generate parameter hash for the given chaincode path,func and args
     *
     * @param path Chaincode path
     * @param func Chaincode function name
     * @param args List of arguments
     * @return hash of path, func and args
     */
    public static String generateParameterHash(String path, String func, List<String> args) {
        logger.debug(format("GenerateParameterHash : path=%s, func=%s, args=%s", path, func, args));

        // Append the arguments
        StringBuilder param = new StringBuilder(path);
        param.append(func);
        args.forEach(param::append);

        // Compute the hash

        return Hex.toHexString(hash(param.toString().getBytes(UTF_8), new SHA3Digest()));
    }

    /**
     * Generate hash of a chaincode directory
     *
     * @param rootDir      Root directory
     * @param chaincodeDir Channel code directory
     * @param hash         Previous hash (if any)
     * @return hash of the directory
     * @throws IOException
     */
    public static String generateDirectoryHash(String rootDir, String chaincodeDir, String hash) throws IOException {
        // Generate the project directory
        Path projectPath;
        if (rootDir == null) {
            projectPath = Paths.get(chaincodeDir);
        } else {
            projectPath = Paths.get(rootDir, chaincodeDir);
        }

        File dir = projectPath.toFile();
        if (!dir.exists() || !dir.isDirectory()) {
            throw new IOException(format("The chaincode path \"%s\" is invalid", projectPath));
        }

        StringBuilder hashBuilder = new StringBuilder(hash);
        Files.walk(projectPath)
                .sorted(Comparator.naturalOrder())
                .filter(Files::isRegularFile)
                .map(Path::toFile)
                .forEach(file -> {
                    try {
                        byte[] buf = readFile(file);
                        byte[] toHash = Arrays.concatenate(buf, hashBuilder.toString().getBytes(UTF_8));
                        hashBuilder.setLength(0);
                        hashBuilder.append(Hex.toHexString(hash(toHash, new SHA3Digest())));
                    } catch (IOException ex) {
                        throw new RuntimeException(format("Error while reading file %s", file.getAbsolutePath()), ex);
                    }
                });

        // If original hash and final hash are the same, it indicates that no new contents were found
        if (hashBuilder.toString().equals(hash)) {
            throw new IOException(format("The chaincode directory \"%s\" has no files", projectPath));
        }
        return hashBuilder.toString();
    }

    /**
     * Compress the contents of given directory using Tar and Gzip to an in-memory byte array.
     *
     * @param sourceDirectory  the source directory.
     * @param pathPrefix       a path to be prepended to every file name in the .tar.gz output, or {@code null} if no prefix is required.
     * @param chaincodeMetaInf
     * @return the compressed directory contents.
     * @throws IOException
     */
    public static byte[] generateTarGz(File sourceDirectory, String pathPrefix, File chaincodeMetaInf) throws IOException {
        logger.trace(format("generateTarGz: sourceDirectory: %s, pathPrefix: %s, chaincodeMetaInf: %s",
                sourceDirectory == null ? "null" : sourceDirectory.getAbsolutePath(), pathPrefix,
                chaincodeMetaInf == null ? "null" : chaincodeMetaInf.getAbsolutePath()));

        ByteArrayOutputStream bos = new ByteArrayOutputStream(500000);

        String sourcePath = sourceDirectory.getAbsolutePath();

        try (TarArchiveOutputStream archiveOutputStream = new TarArchiveOutputStream(new GzipCompressorOutputStream(bos))) {
            archiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

            Collection<File> childrenFiles = org.apache.commons.io.FileUtils.listFiles(sourceDirectory, null, true);

            ArchiveEntry archiveEntry;
            for (File childFile : childrenFiles) {
                String childPath = childFile.getAbsolutePath();
                String relativePath = childPath.substring((sourcePath.length() + 1));

                if (pathPrefix != null) {
                    relativePath = Utils.combinePaths(pathPrefix, relativePath);
                }

                relativePath = FilenameUtils.separatorsToUnix(relativePath);

                if (TRACE_ENABED) {
                    logger.trace(format("generateTarGz: Adding '%s' entry from source '%s' to archive.", relativePath, childFile.getAbsolutePath()));
                }

                archiveEntry = new TarArchiveEntry(childFile, relativePath);
                archiveOutputStream.putArchiveEntry(archiveEntry);

                try (FileInputStream fileInputStream = new FileInputStream(childFile)) {
                    IOUtils.copy(fileInputStream, archiveOutputStream);
                } finally {
                    archiveOutputStream.closeArchiveEntry();
                }

            }

            if (null != chaincodeMetaInf) {
                childrenFiles = org.apache.commons.io.FileUtils.listFiles(chaincodeMetaInf, null, true);

                final URI metabase = chaincodeMetaInf.toURI();

                for (File childFile : childrenFiles) {

                    final String relativePath = Paths.get("META-INF", metabase.relativize(childFile.toURI()).getPath()).toString();

                    if (TRACE_ENABED) {
                        logger.trace(format("generateTarGz: Adding '%s' entry from source '%s' to archive.", relativePath, childFile.getAbsolutePath()));
                    }

                    archiveEntry = new TarArchiveEntry(childFile, relativePath);
                    archiveOutputStream.putArchiveEntry(archiveEntry);

                    try (FileInputStream fileInputStream = new FileInputStream(childFile)) {
                        IOUtils.copy(fileInputStream, archiveOutputStream);
                    } finally {
                        archiveOutputStream.closeArchiveEntry();
                    }

                }

            }
        }

        return bos.toByteArray();
    }

    /**
     * Read the contents a file.
     *
     * @param input source file to read.
     * @return contents of the file.
     * @throws IOException
     */
    public static byte[] readFile(File input) throws IOException {
        return Files.readAllBytes(Paths.get(input.getAbsolutePath()));
    }

    /**
     * Generate a v4 UUID
     *
     * @return String representation of {@link UUID}
     */
    public static String generateUUID() {
        return UUID.randomUUID().toString();
    }

    /**
     * Create a new {@link Timestamp} instance based on the current time
     *
     * @return timestamp
     */
    public static Timestamp generateTimestamp() {
        Instant time = Instant.now();
        return Timestamp.newBuilder().setSeconds(time.getEpochSecond())
                .setNanos(time.getNano()).build();
    }

    /**
     * Delete a file or directory
     *
     * @param file {@link File} representing file or directory
     * @throws IOException
     */
    public static void deleteFileOrDirectory(File file) throws IOException {
        if (file.exists()) {
            if (file.isDirectory()) {
                Path rootPath = Paths.get(file.getAbsolutePath());

                Files.walk(rootPath, FileVisitOption.FOLLOW_LINKS)
                        .sorted(Comparator.reverseOrder())
                        .map(Path::toFile)
                        .forEach(File::delete);
            } else {
                file.delete();
            }
        } else {
            throw new RuntimeException("File or directory does not exist");
        }
    }

    /**
     * Generate hash of the given input using the given Digest.
     *
     * @param input  input data.
     * @param digest the digest to use for hashing
     * @return hashed data.
     */
    public static byte[] hash(byte[] input, Digest digest) {
        byte[] retValue = new byte[digest.getDigestSize()];
        digest.update(input, 0, input.length);
        digest.doFinal(retValue, 0);
        return retValue;
    }

    /**
     * Combine two or more paths
     *
     * @param first parent directory path
     * @param other children
     * @return combined path
     */
    public static String combinePaths(String first, String... other) {
        return Paths.get(first, other).toString();
    }

    /**
     * Read a file from classpath
     *
     * @param fileName
     * @return byte[] data
     * @throws IOException
     */
    public static byte[] readFileFromClasspath(String fileName) throws IOException {
        try (InputStream is = Utils.class.getClassLoader().getResourceAsStream(fileName)) {
            return IOUtils.toByteArray(is);
        }
    }

    public static Properties parseGrpcUrl(String url) {
        if (isNullOrEmpty(url)) {
            throw new RuntimeException("URL cannot be null or empty");
        }

        Properties props = new Properties();
        Pattern p = Pattern.compile("([^:]+)[:]//([^:]+)[:]([0-9]+)", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(url);
        if (m.matches()) {
            props.setProperty("protocol", m.group(1));
            props.setProperty("host", m.group(2));
            props.setProperty("port", m.group(3));

            String protocol = props.getProperty("protocol");
            if (!"grpc".equals(protocol) && !"grpcs".equals(protocol)) {
                throw new RuntimeException(format("Invalid protocol expected grpc or grpcs and found %s.", protocol));
            }
        } else {
            throw new RuntimeException("URL must be of the format protocol://host:port. Found: '" + url + "'");
        }

        // TODO: allow all possible formats of the URL
        return props;
    }

    /**
     * Check if the strings Grpc url is valid
     *
     * @param url
     * @return Return the exception that indicates the error or null if ok.
     */
    public static Exception checkGrpcUrl(String url) {
        try {

            parseGrpcUrl(url);
            return null;

        } catch (Exception e) {
            return e;
        }
    }

    /**
     * Check if a string is null or empty.
     *
     * @param url the string to test.
     * @return {@code true} if the string is null or empty; otherwise {@code false}.
     */
    public static boolean isNullOrEmpty(String url) {
        return url == null || url.isEmpty();
    }

    /**
     * Makes logging strings which can be long or with unprintable characters be logged and trimmed.
     *
     * @param string Unsafe string too long
     * @return returns a string which does not have unprintable characters and trimmed in length.
     */
    public static String logString(final String string) {
        if (string == null || string.length() == 0) {
            return string;
        }

        String ret = string.replaceAll("[^\\p{Print}]", "?");

        ret = ret.substring(0, Math.min(ret.length(), MAX_LOG_STRING_LENGTH)) + (ret.length() > MAX_LOG_STRING_LENGTH ? "..." : "");

        return ret;

    }

    private static final int NONONCE_LENGTH = 24;

    private static final SecureRandom RANDOM = new SecureRandom();

    public static byte[] generateNonce() {

        byte[] values = new byte[NONONCE_LENGTH];
        RANDOM.nextBytes(values);

        return values;
    }

    public static String toHexString(ByteString byteString) {
        if (byteString == null) {
            return null;
        }

        return encodeHexString(byteString.toByteArray());

    }

    public static String toHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        return encodeHexString(bytes);

    }

    public static String toHexString(String bytes) {
        if (bytes == null) {
            return null;
        }

        return encodeHexString(bytes.getBytes(UTF_8));

    }

    /**
     * Lookup method by name and params
     * If there are no strict matches - trying to convert args to appropriate type
     * Useful for building network configs from yaml files
     * */
    public static Object invokeMethod(final Object target, final String methodName, final Class<?>[] parameterTypes, final Object[] args) throws InvocationTargetException,
            IllegalAccessException, NoSuchMethodException {
        if (parameterTypes.length != args.length) {
            throw new IllegalArgumentException("Parameters types " + java.util.Arrays.toString(parameterTypes) +
                    " do not match arguments " + java.util.Arrays.toString(args));
        }

        Method method = lookupMethod(target.getClass(), methodName, parameterTypes);

        //convert args to founded method param's types
        Object[] coercedArgs = new Object[args.length];
        Class<?>[] methodParameterTypes = method.getParameterTypes();
        for (int i = 0; i < args.length; i++) {
            coercedArgs[i] = convertArgumentToType(args[i], methodParameterTypes[i]);
        }

        return method.invoke(target, coercedArgs);
    }

    private static Method lookupMethod(final Class<?> cls, final String name, final Class<?>[] parameterTypes) throws NoSuchMethodException {
        try {
            return cls.getMethod(name, parameterTypes);
        } catch (NoSuchMethodException originalException) {
            //trying to find method with same name and parameters count
            List<Method> candidates = java.util.Arrays.stream(cls.getMethods())
                    .filter(it -> it.getName().equals(name))
                    .filter(it -> it.getParameterCount() == parameterTypes.length)
                    .collect(Collectors.toList());

            if (candidates.isEmpty()) {
                throw originalException;
            }

            //if there is only one candidate - return it
            if (candidates.size() == 1) {
                return candidates.get(0);
            }

            //else, it could be same method declared in hierarchy (override). They must be with equal parameter types
            for (int i = 0; i < candidates.size() - 1; i++) {
                Class<?>[] types1 = candidates.get(i).getParameterTypes();
                Class<?>[] types2 = candidates.get(i + 1).getParameterTypes();
                //otherwise - we found methods with different params and can't choose one
                if (!java.util.Arrays.equals(types1, types2)) {
                    throw originalException;
                }
            }

            return candidates.get(0);
        }
    }

    private static Object convertArgumentToType(final Object arg, final Class<?> type) {
        if (arg.getClass().equals(type) || !(arg instanceof String)) {
            return arg;
        }

        Function<String, ?> convert = STRING_CONVERSIONS_BY_TYPE.get(type);
        if (null == convert) {
            throw new IllegalArgumentException("Unable to convert \"" + arg + "\" to " + type.getTypeName());
        }

        return convert.apply((String) arg);
    }

    /**
     * Private constructor to prevent instantiation.
     */
    private Utils() {
    }

}
