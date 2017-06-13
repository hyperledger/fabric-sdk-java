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

package org.hyperledger.fabric.sdk;

import java.io.File;

import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdkintegration.SampleStore;
import org.hyperledger.fabric.sdkintegration.SampleUser;

import static java.lang.String.format;

public class TestHFClient {

    final File tempFile;
    final HFClient hfClient;

    public TestHFClient(File tempFile, HFClient hfClient) {
        this.tempFile = tempFile;
        this.hfClient = hfClient;
    }

    public static HFClient newInstance() throws Exception {


        File tempFile = File.createTempFile("teststore", "properties");
        tempFile.deleteOnExit();

        File sampleStoreFile = new File(System.getProperty("user.home") + "/test.properties");
        if (sampleStoreFile.exists()) { //For testing start fresh
            sampleStoreFile.delete();
        }
        final SampleStore sampleStore = new SampleStore(sampleStoreFile);

        //src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/

        //SampleUser someTestUSER = sampleStore.getMember("someTestUSER", "someTestORG");
        SampleUser someTestUSER = sampleStore.getMember("someTestUSER", "someTestORG", "mspid",
                findFileSk("src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore"),
                new File("src/test/fixture/sdkintegration/e2e-2Orgs/channel/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem"));
        someTestUSER.setMspId("testMSPID?");

        HFClient hfclient = HFClient.createNewInstance();
        hfclient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

//        someTestUSER.setEnrollment(new Enrollment() {
//            @Override
//            public PrivateKey getKey() {
//                return new PrivateKey() {
//                    private static final long serialVersionUID = -7506317638561401152L;
//
//                    @Override
//                    public String getAlgorithm() {
//                        return "algorithm?";
//                    }
//
//                    @Override
//                    public String getFormat() {
//                        return "format?";
//                    }
//
//                    @Override
//                    public byte[] getEncoded() {
//                        return new byte[0];
//                    }
//                };
//            }
//
//            @Override
//            public String getCert() {
//                return "fakecert?";
//            }
//
//        });
        hfclient.setUserContext(someTestUSER);


        new TestHFClient(tempFile, hfclient);

        return hfclient;

    }

    static File findFileSk(String directorys) {

        File directory = new File(directorys);

        File[] matches = directory.listFiles((dir, name) -> name.endsWith("_sk"));

        if (null == matches) {
            throw new RuntimeException(format("Matches returned null does %s directory exist?", directory.getAbsoluteFile().getName()));
        }

        if (matches.length != 1) {
            throw new RuntimeException(format("Expected in %s only 1 sk file but found %d", directory.getAbsoluteFile().getName(), matches.length));
        }

        return matches[0];

    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (tempFile != null) {
            try {
                tempFile.delete();
            } catch (Exception e) {
               // // now harm done.
            }
        }
    }
}
