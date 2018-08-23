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

import java.io.IOException;

import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.junit.Test;


/*
    This runs a version of end2end but with Java chaincode.
    It requires that End2endIT has been run already to do all enrollment and setting up of orgs,
    creation of the channels. None of that is specific to chaincode deployment language.
 */

public class End2endJavaIT extends End2endIT {

    {
        testName = "End2endJavaIT";  //Just print out what test is really running.

        // This is what changes are needed to deploy and run Node code.

        // this is relative to src/test/fixture and is where the Node chaincode source is.
        CHAIN_CODE_FILEPATH = "sdkintegration/javacc/sample1"; //override path to Node code
        CHAIN_CODE_PATH = null; //This is used only for GO.
        CHAIN_CODE_NAME = "example_cc_java"; // chaincode name.
        CHAIN_CODE_LANG = Type.JAVA; //language is Java.
    }

    @Override
    void blockWalker(HFClient client, Channel channel) throws InvalidArgumentException, ProposalException, IOException {
        // block walker depends on the state of the chain after go's end2end. Nothing here is language specific so
        // there is no loss in coverage for not doing this.
    }

    @Override
    @Test
    public void setup() throws Exception {
        sampleStore = new SampleStore(sampleStoreFile);
        enrollUsersSetup(sampleStore);
        runFabricTest(sampleStore); // just run fabric tests.
    }

    @Override
    Channel constructChannel(String name, HFClient client, SampleOrg sampleOrg) throws Exception {
        // override this method since we don't want to construct the channel that's been done.
        // Just get it out of the samplestore!

        client.setUserContext(sampleOrg.getPeerAdmin());

        return sampleStore.getChannel(client, name).initialize();

    }
}
