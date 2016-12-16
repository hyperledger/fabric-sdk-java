/**
 * 
 */
package org.hyperledger.fabric.sdk.transaction;

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvokeException;
import org.hyperledger.protos.Fabric;

import java.io.IOException;

public class InvocationTransactionBuilder extends QueryTransactionBuilder {

    private InvocationTransactionBuilder() {
    }

    public static InvocationTransactionBuilder newBuilder() {
        return new InvocationTransactionBuilder();
    }

    @Override
    public Transaction build() {
        try {
            return build(Fabric.Transaction.Type.CHAINCODE_INVOKE);
        } catch (CryptoException | IOException e) {
            throw new InvokeException("Error while creating invoke transaction", e);
        }
    }
}
