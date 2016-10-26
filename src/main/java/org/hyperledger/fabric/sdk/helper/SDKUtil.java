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

package org.hyperledger.fabric.sdk.helper;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

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

import com.google.protobuf.Timestamp;

public class SDKUtil {
	private static final Log logger = LogFactory.getLog(SDKUtil.class);

	/**
	 * Generate parameter hash for the given chain code path,func and args 
	 * @param path Chain code path
	 * @param func Chain code function name
	 * @param args List of arguments
	 * @return hash of path, func and args
	 */
	public static String generateParameterHash(String path, String func, List<String> args) {
		logger.debug(String.format("GenerateParameterHash : path=%s, func=%s, args=%s", path, func, args));

		// Append the arguments
		String argStr = "";
		for (String arg : args) {
			argStr += arg;
		}

		// Append the path + function + arguments
		String str = path + func + argStr;
		logger.debug("str: " + str);

		// Compute the hash
		String strHash = Hex.toHexString(hash(str.getBytes(), new SHA3Digest()));
		logger.debug("strHash: " + strHash);

		return strHash;
	}

	/**
	 * Generate hash of a chain code directory
	 * @param rootDir Root directory
	 * @param chaincodeDir Chain code directory
	 * @param hash Previous hash (if any)
	 * @return hash of the directory
	 * @throws IOException
	 */
	public static String generateDirectoryHash(String rootDir, String chaincodeDir, String hash) throws IOException {
		// Generate the project directory
		String projectDir = rootDir + "/" + chaincodeDir;

		// Read in the contents of the current directory
		File dir = new File(projectDir);
		File[] dirContents = dir.listFiles();

		// Go through all entries in the projet directory
		for (File file : dirContents) {
			// Check whether the entry is a file or a directory
			if (file.isDirectory()) {
				// If the entry is a directory, call the function recursively.

				hash = generateDirectoryHash(rootDir, chaincodeDir + "/" + file.getName(), hash);
			} else {
				// If the entry is a file, read it in and add the contents to
				// the hash string

				// Read in the file as buffer
				byte[] buf = readFile(file);
				// Update the value to be hashed with the file content
				byte[] toHash = Arrays.concatenate(buf, hash.getBytes());
				// Update the value of the hash
				hash = Hex.toHexString(hash(toHash, new SHA3Digest()));
			}
		}

		return hash;
	}
	
	/**
	 * Compress the given directory <src> to <target> tar.gz file
	 * @param src The source directory
	 * @param target The target tar.gz file
	 * @throws IOException
	 */
	public static void generateTarGz(String src, String target) throws IOException {
		File sourceDirectory = new File(src);
		File destinationArchive = new File(target);
		
		String sourcePath = sourceDirectory.getAbsolutePath();
        FileOutputStream destinationOutputStream = new FileOutputStream(destinationArchive);
        
        TarArchiveOutputStream archiveOutputStream = new TarArchiveOutputStream(new GzipCompressorOutputStream(new BufferedOutputStream(destinationOutputStream)));
        archiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

        try {
            Collection<File> childrenFiles = org.apache.commons.io.FileUtils.listFiles(sourceDirectory, null, true);
            childrenFiles.remove(destinationArchive);

            ArchiveEntry archiveEntry;
            FileInputStream fileInputStream;
            for (File childFile : childrenFiles) {
                String childPath = childFile.getAbsolutePath();
                String relativePath = childPath.substring((sourcePath.length() + 1), childPath.length());

                relativePath = FilenameUtils.separatorsToUnix(relativePath);
                archiveEntry = new TarArchiveEntry(childFile, relativePath);
                fileInputStream = new FileInputStream(childFile);
                archiveOutputStream.putArchiveEntry(archiveEntry);

                try {
                    IOUtils.copy(fileInputStream, archiveOutputStream);
                } finally {
                    IOUtils.closeQuietly(fileInputStream);
                    archiveOutputStream.closeArchiveEntry();
                }
            }
        } finally {
            IOUtils.closeQuietly(archiveOutputStream);
        }
	}
	
	/**
	 * Read a file and return its contents
	 * @param input source file to read
	 * @return {@link byte[]} contents of the file
	 * @throws IOException
	 */
	public static byte[] readFile(File input) throws IOException {
		return Files.readAllBytes(Paths.get(input.getAbsolutePath()));
	}
	
	/**
	 * Generate a v4 UUID
	 * @return String representation of {@link UUID}
	 */
	public static String generateUUID() {
		return UUID.randomUUID().toString();
	}
	
	/**
	 * Create a new {@link Timestamp} instance based on the current time
	 * @return timestamp
	 */
	public static Timestamp generateTimestamp() {
		Instant time = Instant.now();
		Timestamp timestamp = Timestamp.newBuilder().setSeconds(time.getEpochSecond())
		    .setNanos(time.getNano()).build();
		return timestamp;
	}
	
	/**
	 * Delete a file or directory
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
	 * Generate hash of the given input using the given Digest
	 * @param input byte[] input
	 * @param digest The {@link Digest} to use for hashing
	 * @return
	 */
	public static byte[] hash(byte[] input, Digest digest) {
		byte[] retValue = new byte[digest.getDigestSize()];
		digest.update(input, 0, input.length);
		digest.doFinal(retValue, 0);
		return retValue;
	}

}
