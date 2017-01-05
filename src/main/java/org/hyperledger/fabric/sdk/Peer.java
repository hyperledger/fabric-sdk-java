/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.events.TransactionListener;
import org.hyperledger.fabric.sdk.exception.ExecuteException;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.hyperledger.fabric.sdk.transaction.Transaction;
import org.hyperledger.protos.Fabric;
import org.hyperledger.protos.Fabric.Response;

/**
 * The Peer class represents a peer to which SDK sends deploy, invoke, or query requests.
 */
public class Peer {
	private static final Log logger = LogFactory.getLog(Peer.class);

    private String url;
    private Chain chain;
    private PeerClient peerClient;

    /**
     * Constructor for a peer given the endpoint config for the peer.
     * @param {string} url The URL of
     * @param {Chain} The chain of which this peer is a member.
     * @returns {Peer} The new peer.
     */
    public Peer(String url, String pem, Chain chain) {
        this.url = url;
        this.chain = chain;
        Endpoint ep = new Endpoint(url, pem);
        this.peerClient = new PeerClient(ep.getChannelBuilder());
    }

    /**
     * Get the chain of which this peer is a member.
     * @returns {Chain} The chain of which this peer is a member.
     */
    public Chain getChain() {
        return this.chain;
    }

    /**
     * Get the URL of the peer.
     * @returns {string} Get the URL associated with the peer.
     */
    public String getUrl() {
        return this.url;
    }

    /**
     * Send a transaction to this peer.
     * @param transaction A transaction
     * @throws PeerException 
     */
    public Response sendTransaction(Transaction transaction) throws PeerException {

        logger.debug("peer.sendTransaction");

        // Send the transaction to the peer node via grpc
        // The rpc specification on the peer side is:
        //     rpc ProcessTransaction(Transaction) returns (Response) {}
        Response response = peerClient.processTransaction(transaction.getTxBuilder().build());

        if (response.getStatus() != Response.StatusCode.SUCCESS) {
            return response;
        }

        logger.debug(String.format("peer.sendTransaction: received %s", response.getMsg().toStringUtf8()));

        // Check transaction type here, as invoke is an asynchronous call,
        // whereas a deploy and a query are synchonous calls. As such,
        // invoke will emit 'submitted' and 'error', while a deploy/query
        // will emit 'complete' and 'error'.

        Fabric.Transaction.Type txType = transaction.getTxBuilder().getType();
        switch (txType) {
            case CHAINCODE_DEPLOY: // async
                String txid = response.getMsg().toStringUtf8();
                // Deploy transaction has been completed
                if (txid == null || txid.isEmpty()) {
                    throw new ExecuteException("the deploy response is missing the transaction UUID");
                } else if (!this.waitForDeployComplete(txid)) {
                    throw new ExecuteException("the deploy request is submitted, but is not completed");
                } else {
                    return response;
                }
            case CHAINCODE_INVOKE: // async
                txid = response.getMsg().toStringUtf8();
                // Invoke transaction has been submitted
                if (txid == null || txid.isEmpty()) {
                    throw new ExecuteException("the invoke response is missing the transaction UUID");
                } else if(!this.waitForInvokeComplete(txid)) {
                    throw new ExecuteException("the invoke request is submitted, but is not completed");
                } else {
                    return response;
                }
            case CHAINCODE_QUERY: // sync
                return response;
            default: // not implemented
                throw new ExecuteException("processTransaction for this transaction type is not yet implemented!");
        }
    }

    private boolean waitForDeployComplete(final String txid) {
        int waitTime = this.chain.getDeployWaitTime();
        logger.debug(String.format("waiting %d seconds before emitting deploy complete event", waitTime));

        final boolean[] deployCompleted = {false};
        final Object lock = new Object();
        this.chain.getEventHub().registerTxEvent(txid, new TransactionListener() {
            @Override
            public void process(Fabric.Transaction transaction) {
                chain.getEventHub().unregisterTxEvent(txid);
                deployCompleted[0] = true;
                synchronized (lock) {
                    lock.notify();
                }
            }
        });

        try {
            synchronized (lock) {
                lock.wait(waitTime * 1000);
            }
        } catch (InterruptedException e) {
            // ignore
        }
        return deployCompleted[0];
    }

    private boolean waitForInvokeComplete(final String txid) {
        int waitTime = this.chain.getInvokeWaitTime();
        logger.debug(String.format("waiting %d seconds before emitting invoke complete event", waitTime));

        final boolean[] invokeCompleted = {false};
        final Object lock = new Object();
        this.chain.getEventHub().registerTxEvent(txid, new TransactionListener() {
            @Override
            public void process(Fabric.Transaction transaction) {
                chain.getEventHub().unregisterTxEvent(txid);
                invokeCompleted[0] = true;
                synchronized (lock) {
                    lock.notify();
                }
            }
        });
        try {
            synchronized (lock) {
                lock.wait(waitTime * 1000);
            }
        } catch (InterruptedException e) {
            // ignore
        }
        return invokeCompleted[0];
    }

    /**
     * Remove the peer from the chain.
     */
    public void remove() {
        throw new RuntimeException("TODO: implement"); //TODO implement remove
    }

} // end Peer
