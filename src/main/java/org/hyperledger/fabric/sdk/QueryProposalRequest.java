package org.hyperledger.fabric.sdk;

/**
 * Created by rineholt on 11/11/16.
 */
public class QueryProposalRequest extends TransactionRequest {
    private QueryProposalRequest(){}
    public static QueryProposalRequest newInstance() {
        return new QueryProposalRequest();
    }
}
