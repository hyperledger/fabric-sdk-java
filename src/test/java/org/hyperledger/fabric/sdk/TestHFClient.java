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
        HFClient hfclient = HFClient.createNewInstance();
        User user = new User("admin");
        user.enrollment = new Enrollment();
        hfclient.setUserContext(user);
        tempFile = File.createTempFile("teststore", "properties");
        hfclient.setKeyValStore(new FileKeyValStore(tempFile));
        hfclient.setMemberServices(new MemberServicesFabricCAImpl("http://Nowhere.com", null));

        new TestHFClient(tempFile, hfclient);

        return hfclient;

    }

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
