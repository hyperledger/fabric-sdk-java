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

package org.hyperledger.fabric.sdkintegration;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.hyperledger.fabric.sdk.helper.Utils;

import static java.lang.String.format;

class Util {

    /**
     * Private constructor to prevent instantiation.
     */
    private Util() {
    }

    /**
     * Generate a targz inputstream from source folder.
     *
     * @param src        Source location
     * @param pathPrefix prefix to add to the all files found.
     * @return return inputstream.
     * @throws IOException
     */
    public static InputStream generateTarGzInputStream(File src, String pathPrefix) throws IOException {
        File sourceDirectory = src;

        ByteArrayOutputStream bos = new ByteArrayOutputStream(500000);

        String sourcePath = sourceDirectory.getAbsolutePath();

        TarArchiveOutputStream archiveOutputStream = new TarArchiveOutputStream(new GzipCompressorOutputStream(new BufferedOutputStream(bos)));
        archiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

        try {
            Collection<File> childrenFiles = org.apache.commons.io.FileUtils.listFiles(sourceDirectory, null, true);

            ArchiveEntry archiveEntry;
            FileInputStream fileInputStream;
            for (File childFile : childrenFiles) {
                String childPath = childFile.getAbsolutePath();
                String relativePath = childPath.substring((sourcePath.length() + 1), childPath.length());

                if (pathPrefix != null) {
                    relativePath = Utils.combinePaths(pathPrefix, relativePath);
                }

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

        return new ByteArrayInputStream(bos.toByteArray());
    }

    public static File findFileSk(File directory) {

        File[] matches = directory.listFiles((dir, name) -> name.endsWith("_sk"));

        if (null == matches) {
            throw new RuntimeException(format("Matches returned null does %s directory exist?", directory.getAbsoluteFile().getName()));
        }

        if (matches.length != 1) {
            throw new RuntimeException(format("Expected in %s only 1 sk file but found %d", directory.getAbsoluteFile().getName(), matches.length));
        }

        return matches[0];

    }
}
