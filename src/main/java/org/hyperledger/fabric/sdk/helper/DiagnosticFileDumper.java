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

package org.hyperledger.fabric.sdk.helper;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.CompletionHandler;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.TimeZone;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dumps files for diagnostic purposes
 *
 */

public class DiagnosticFileDumper implements Runnable {

    private final File directory;
    private final String dirAbsolutePath;
    private final String pid;
    //  private static final Log logger = LogFactory.getLog(DiagnosticFileDumper.class);
    private static Thread thread;
    private final BlockingQueue<QueEntry> queEntries = new LinkedBlockingQueue<>();

    private static DiagnosticFileDumper singleInstance = null;
    private static final AtomicInteger counter = new AtomicInteger(0);

    private DiagnosticFileDumper(File directory) {

        this.directory = directory;
        this.dirAbsolutePath = directory == null ? null : directory.getAbsolutePath();
        this.pid = getPID() + "";

    }

    static DiagnosticFileDumper configInstance(File directory) {

        if (singleInstance == null) {
            singleInstance = new DiagnosticFileDumper(directory);
            thread = new Thread(singleInstance);
            thread.setName("DiagnosticFileDumper");
            thread.setDaemon(true);
            thread.start();

        }

        return singleInstance;

    }

    public String createDiagnosticProtobufFile(byte[] byteString) {

        return createDiagnosticFile(byteString, "protobuf_", "proto");

    }

    private boolean cantWrite() {
        return null == directory || !directory.exists() || !directory.isDirectory() || !directory.canWrite();
    }

    public String createDiagnosticFile(byte[] bytes) {

        return createDiagnosticFile(bytes, null, null);

    }

    public String createDiagnosticFile(byte[] bytes, String prefix, String ext) {
        String fileName = "";
        if (cantWrite()) {
            return "Missing dump directory or can not write: " + (dirAbsolutePath);
        }
        if (null != bytes) {
            if (null == prefix) {
                prefix = "diagnostic_";
            }
            if (null == ext) {
                ext = "bin";
            }

            SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss_SSS");
            dateFormatGmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            fileName = prefix + dateFormatGmt.format(new Date()) + "P" + pid + "_" + Thread.currentThread().getId()
                    + "_" + counter.addAndGet(1) + "." + ext;
            fileName = fileName.replaceAll("\\:", "-"); // colon is bad for windows.

            new QueEntry(fileName, bytes); //Add to Que let process by async thread.

        }
        return fileName;

    }

    @Override
    public void run() {

        while (true) {

            try {
                final LinkedList<QueEntry> entries = new LinkedList<>();

                entries.add(this.queEntries.take()); // wait on one.
                this.queEntries.drainTo(entries); //got one, see if there are more.

                if (cantWrite()) {
                    return;  //IF the directory is missing just assume user does not want diagnostic files created anymore.
                }

                entries.forEach(queEntry -> {

                    try {
                        final AsynchronousFileChannel channel = AsynchronousFileChannel.open(Paths.get(dirAbsolutePath, queEntry.fileName),
                                StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                        channel.write(ByteBuffer.wrap(queEntry.dataBytes), 0, null, new CompletionHandler<Integer, Object>() {
                            @Override
                            public void completed(Integer result, Object attachment) {
                                try {
                                    channel.close();
                                } catch (IOException e) {
                                    //best effort
                                }
                            }

                            @Override
                            public void failed(Throwable exc, Object attachment) {

                                try {
                                    channel.close();
                                } catch (IOException e) {
                                    //best effort.
                                }

                            }
                        });

                    } catch (IOException e) {
                        //best effort.
                    }

                });
            } catch (InterruptedException e) {
                // best effort
            }

        }

    }

    class QueEntry {
        final String fileName;
        final byte[] dataBytes;

        QueEntry(String fileName, byte[] dataBytes) {
            this.fileName = fileName;
            this.dataBytes = dataBytes;

            queEntries.add(this);

        }

    }

    private static long getPID() {
        String processName =
                java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
        return Long.parseLong(processName.split("@")[0]);
    }

}
