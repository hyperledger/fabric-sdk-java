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
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.orderer.Ab;

/**
 * The Orderer class represents a orderer to which SDK sends deploy, invoke, or query requests.
 */
public class Orderer {
    private static final Log logger = LogFactory.getLog(Orderer.class);

    /**
     * getUrl - the Grpc url of the Orderer
     * @return the Grpc url of the Orderer
     */
    public String getUrl() {
        return url;
    }

    private final String url;
    private final String pem;
//    private final EndorserClient endorserClent;

    public void setChain(Chain chain) throws InvalidArgumentException {
        if (chain == null) {
            throw new InvalidArgumentException("Chain can not be null");
        }

        this.chain = chain;
    }

    private Chain chain;
//    private OrdererClient ordererClient;

    /**
     * Constructor for a orderer given the endpoint config for the orderer.
     *
     * @param {string} url The URL of
     * @param {Chain}  The chain of which this orderer is a member.
     * @returns {Orderer} The new orderer.
     */
    public Orderer(String url, String pem, Chain chain) throws InvalidArgumentException {


        Exception e = SDKUtil.checkGrpcUrl(url);
        if(e != null){
            throw new InvalidArgumentException("Bad Orderer url.", e);

        }
        //  super(url, pem);
        this.url = url;
        this.pem = pem;


        this.chain = chain;
        // Endpoint ep = new Endpoint(url, pem);
        // Ab.BroadcastMessageOrBuilder bb = Ab.BroadcastMessage.newBuilder();

    }

    /**
     * Get the chain of which this orderer is a member.
     *
     * @returns {Chain} The chain of which this orderer is a member.
     */
    public Chain getChain() {
        return this.chain;
    }


    /**
     * Send transaction to Order
     *
     * @param transaction transaction to be sent
     */

    public Ab.BroadcastResponse sendTransaction(Common.Envelope transaction) {

        OrdererClient orderClient = new OrdererClient(new Endpoint(url, pem).getChannelBuilder());
        return orderClient.sendTransaction(transaction);

    }


    public static Orderer createNewInstance(String url, String pem) throws InvalidArgumentException {
        return new Orderer(url, pem, null);

    }


   } // end Orderer
