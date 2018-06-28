package org.hyperledger.fabric.sdkintegration;


import org.hyperledger.fabric.sdk.ChaincodeID;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.junit.Test;


//    This runs a version of end2endAndBackAgainIT but with Node chaincode.s
public class End2endAndBackAgainNodeIT extends End2endAndBackAgainIT {

    {

        // This is what changes are needed to deploy and run Node code.
        testName = "End2endAndBackAgainNodeIT";

        // this is relative to src/test/fixture and is where the Node chaincode source is.
        CHAIN_CODE_FILEPATH = "sdkintegration/nodecc/sample_11"; //override path to Node code
        CHAIN_CODE_PATH = null; //This is used only for GO.
        CHAIN_CODE_NAME = "example_cc_node"; // chaincode namFCAAffiliationTest.javae.
        CHAIN_CODE_LANG = Type.NODE; //language is Node.
        chaincodeID = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
                .setVersion(CHAIN_CODE_VERSION).build();
        chaincodeID_11 = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
                .setVersion(CHAIN_CODE_VERSION_11).build();
    }

    @Override
    @Test
    public void setup() throws Exception {

        sampleStore = new SampleStore(sampleStoreFile);

        setupUsers(sampleStore);
        runFabricTest(sampleStore);
    }
}
