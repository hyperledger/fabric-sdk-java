package org.hyperledger.fabric.sdk.transaction;


import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.ChainHeader;

import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeHeaderExtension;

/**
 * Created by rineholt on 1/12/17.
 */
public class ProtoUtils {

    /**
     *   createChainHeader create chainHeader
     * @param type
     * @param txID
     * @param chainID
     * @param epoch
     * @param chaincodeHeaderExtension
     * @return
     */
    public final static ChainHeader createChainHeader(HeaderType type, String txID, String chainID, long epoch, ChaincodeHeaderExtension chaincodeHeaderExtension) {

        ChainHeader.Builder ret = ChainHeader.newBuilder()
                .setType(type.getNumber())
                .setVersion(0)
                .setTxID(txID)
                .setChainID(chainID)
                .setEpoch(epoch)

                ;
        if(null != chaincodeHeaderExtension){
            ret.setExtension(chaincodeHeaderExtension.toByteString());
        }

        return ret.build();

    }
}
