/**
 * 
 */
package org.hyperledger.fabric.sdk.transaction;

import org.hyperledger.protos.Chaincode;
import org.hyperledger.protos.Fabric;

import io.netty.util.internal.StringUtil;

public class QueryTransactionBuilder extends TransactionBuilder {

	protected QueryTransactionBuilder() {}
	
	public static QueryTransactionBuilder newBuilder() {
		return new QueryTransactionBuilder();
	}

	@Override
	public Transaction build() {
		return build(Fabric.Transaction.Type.CHAINCODE_QUERY);
	}
	
	protected Transaction build(Fabric.Transaction.Type ccType) {
		if (chain == null || request == null) {
			throw new IllegalArgumentException("Must provide request and chain before attempting to call build()");
		}
		
		// Verify that chaincodeID is being passed
        if (StringUtil.isNullOrEmpty(request.getChaincodeID())) {
          throw new RuntimeException("missing chaincodeID in InvokeOrQueryRequest");
        }
        
     // create transaction
		Fabric.Transaction tx = createTransactionBuilder(Chaincode.ChaincodeSpec.Type.GOLANG,
				ccType,
				request.getChaincodeID(), request.getArgs(), null, request.getChaincodeName(),
				null).build();
	
	     return new Transaction(tx, request.getChaincodeID());
	}

}
