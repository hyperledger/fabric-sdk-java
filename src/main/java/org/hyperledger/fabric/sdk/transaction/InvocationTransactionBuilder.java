/**
 * 
 */
package org.hyperledger.fabric.sdk.transaction;

import org.hyperledger.protos.Fabric;

public class InvocationTransactionBuilder extends QueryTransactionBuilder {

	private InvocationTransactionBuilder() {
	}
	
	public static InvocationTransactionBuilder newBuilder() {
		return new InvocationTransactionBuilder();
	}

	@Override
	public Transaction build() {
		return build(Fabric.Transaction.Type.CHAINCODE_INVOKE);
	}	
}
