package org.hyperledger.fabric.sdk;


import org.hyperledger.fabric.protos.peer.Chaincode;

/**
 * Wrapper to not expose Fabric's ChainCoodeId

 */
public class ChainCodeID {

     Chaincode.ChaincodeID getFabricChainCodeID() {
        return fabricChainCodeID;
    }

    private  final Chaincode.ChaincodeID fabricChainCodeID;

     ChainCodeID(Chaincode.ChaincodeID chaincodeID) {
        this.fabricChainCodeID = chaincodeID;
    }

    public String getName(){
        return fabricChainCodeID.getName();
    }

    public String getPath(){
        return  fabricChainCodeID.getPath();

    }

    public String getVersion(){
        return  fabricChainCodeID.getVersion();

    }

}
