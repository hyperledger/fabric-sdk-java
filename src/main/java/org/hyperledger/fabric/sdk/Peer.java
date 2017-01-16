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
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.PeerException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;

/**
 * The Peer class represents a peer to which SDK sends deploy, or query requests.
 */
public class Peer {
    private static final Log logger = LogFactory.getLog(Peer.class);
    private final EndorserClient endorserClent;
    private String name = null;
    private String url;

    public String getName() {
        return name;
    }

    /**
     * Set peer's name
     *
     * @param name
     */
    public void setName(String name) throws InvalidArgumentException {
        if (name == null) {
            throw new InvalidArgumentException("Peer name set to null");
        }
        if (name.length() == 0) {
            throw new InvalidArgumentException("Peer name can not be empty string.");
        }
        this.name = name;
    }



    /**
     * Set the chain the peer is on.
     *
     * @param chain
     */

    void setChain(Chain chain) throws InvalidArgumentException {
        if (chain == null) {
            throw new InvalidArgumentException("Chain can not be null");
        }

        this.chain = chain;
    }

    private Chain chain;

    /**
     * Constructor for a peer given the endpoint config for the peer.
     *
     * @param {string} url The URL of
     * @param {Chain}  The chain of which this peer is a member.
     * @returns {Peer} The new peer.
     */
    public Peer(String url, String pem) throws InvalidArgumentException {


        Exception e = SDKUtil.checkGrpcUrl(url);
        if(e != null){
            throw new InvalidArgumentException("Bad peer url.", e);

        }
        this.url = url;



        this.endorserClent = new EndorserClient(new Endpoint(url, pem).getChannelBuilder());
    }

    /**
     * Get the chain of which this peer is a member.
     *
     * @returns {Chain} The chain of which this peer is a member.
     */
    public Chain getChain() {
        return this.chain;
    }

    /**
     * Get the URL of the peer.
     *
     * @returns {string} Get the URL associated with the peer.
     */
    public String getUrl() {

        return this.url;
    }


    public FabricProposalResponse.ProposalResponse sendProposal(FabricProposal.SignedProposal proposal) throws PeerException, InvalidArgumentException {
        if(proposal == null){
            throw new PeerException("Proposal is null");
        }
        if(chain == null){
            throw new PeerException("Chain is null");
        }
        Exception e = SDKUtil.checkGrpcUrl(url);
        if(e != null){
            throw new InvalidArgumentException("Bad peer url.", e);

        }

        logger.debug("peer.sendProposal");

        return endorserClent.sendProposal(proposal);

    }


    /**
     * TODO: Temporary hack to wait until the deploy event has hopefully completed.
     * This does not detect if an error occurs in the peer or chaincode when deploying.
     * When peer event listening is added to the SDK, this will be implemented correctly.
     */

    /*TODO check waitForDeployComplete
    private void waitForDeployComplete(events.EventEmitter eventEmitter, EventDeploySubmitted submitted) {
        let waitTime = this.chain.getDeployWaitTime();
        logger.debug("waiting %d seconds before emitting deploy complete event",waitTime);
        setTimeout(
           function() {
              let event = new EventDeployComplete(
                  submitted.uuid,
                  submitted.chaincodeID,
                  "TODO: get actual results; waited "+waitTime+" seconds and assumed deploy was successful"
              );
              eventEmitter.emit("complete",event);
           },
           waitTime * 1000
        );
    }
    */

    /**
     * TODO: Temporary hack to wait until the deploy event has hopefully completed.
     * This does not detect if an error occurs in the peer or chaincode when deploying.
     * When peer event listening is added to the SDK, this will be implemented correctly.
     */

    /*TODO check waitForInvokeComplete
    private void waitForInvokeComplete(events.EventEmitter eventEmitter) {
        let waitTime = this.chain.getInvokeWaitTime();
        logger.debug("waiting %d seconds before emitting invoke complete event",waitTime);
        setTimeout(
           function() {
              eventEmitter.emit("complete",new EventInvokeComplete("waited "+waitTime+" seconds and assumed invoke was successful"));
           },
           waitTime * 1000
        );
    }
    */

    /**
     * Remove the peer from the chain.
     */
    public void remove() {
        throw new RuntimeException("TODO: implement"); //TODO implement remove
    }

    public static Peer createNewInstance(String name, String pem) throws InvalidArgumentException {
        return new Peer(name, pem);
    }


} // end Peer
