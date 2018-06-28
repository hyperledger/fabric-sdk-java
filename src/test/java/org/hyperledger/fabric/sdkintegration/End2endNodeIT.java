package org.hyperledger.fabric.sdkintegration;

import java.io.IOException;
import java.nio.file.Paths;

import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.junit.Test;

import static java.lang.String.format;


/*
    This runs a version of end2end but with Node chaincode.
    It requires that End2endIT has been run already to do all enrollment and setting up of orgs,
    creation of the channels. None of that is specific to chaincode deployment language.
 */

public class End2endNodeIT extends End2endIT {

    {

        testName = "End2endNodeIT";  //Just print out what test is really running.

        // This is what changes are needed to deploy and run Node code.

        // this is relative to src/test/fixture and is where the Node chaincode source is.
        CHAIN_CODE_FILEPATH = "sdkintegration/nodecc/sample1"; //override path to Node code
        CHAIN_CODE_PATH = null; //This is used only for GO.
        CHAIN_CODE_NAME = "example_cc_node"; // chaincode name.
        CHAIN_CODE_LANG = Type.NODE; //language is Node.
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
