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
import org.hyperledger.fabric.sdk.events.EventHub;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HFClient {

    static {

        if (null == System.getProperty("org.hyperledger.fabric.sdk.logGRPC")) {
            // Turn this off by default!
            Logger.getLogger("io.netty").setLevel(Level.OFF);
            Logger.getLogger("io.grpc").setLevel(Level.OFF);

        }
    }

    private static final Log logger = LogFactory.getLog(HFClient.class);

    private  final  Map<String, Chain> chains = new HashMap<>();

    public User getUserContext() {
        return userContext;
    }

    private User userContext;

    private HFClient() {

    }

    public static HFClient createNewInstance() {
        return new HFClient();
    }

    public Chain newChain(String name) throws InvalidArgumentException {
        logger.trace("Creating chain :" + name);
        Chain newChain = Chain.createNewInstance(name, this);
        chains.put(name, newChain);
        return newChain;
    }

    public Peer newPeer(String name) throws InvalidArgumentException {
        return Peer.createNewInstance(name, null);
    }

    public Peer newPeer(String url, String pem) throws InvalidArgumentException {
        return Peer.createNewInstance(url, pem);
    }

    public Orderer newOrderer(String url) throws InvalidArgumentException {
        return Orderer.createNewInstance(url, null);
    }

    public Chain getChain(String name) {
        return chains.get(name);
    }

    public DeploymentProposalRequest newDeploymentProposalRequest() {
        return new DeploymentProposalRequest();
    }

    public InvokeProposalRequest newInvokeProposalRequest() {
        return InvokeProposalRequest.newInstance();
    }

    public QueryProposalRequest newQueryProposalRequest() {
        return QueryProposalRequest.newInstance();
    }

    public void setUserContext(User userContext) {
        this.userContext = userContext;
    }

    public EventHub newEventHub(String eventHub) {
        return EventHub.createNewInstance(eventHub, null);
    }
}
