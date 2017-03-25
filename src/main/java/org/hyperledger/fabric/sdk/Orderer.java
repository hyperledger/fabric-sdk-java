/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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


import java.util.Properties;

import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.TransactionException;

import static org.hyperledger.fabric.sdk.helper.SDKUtil.checkGrpcUrl;

/**
 * The Orderer class represents a orderer to which SDK sends deploy, invoke, or query requests.
 */
public class Orderer {
    private static final Log logger = LogFactory.getLog(Orderer.class);
    private final Properties properties;


    /**
     * Get Orderer properties.
     *
     * @return
     */

    public Properties getProperties() {

        return properties == null ? null : (Properties) properties.clone();
    }

    /**
     * Return Orderer's name
     *
     * @return orderer's name.
     */
    public String getName() {
        return name;
    }

    private final String name;
    private final String url;

    Orderer(String name, String url, Properties properties) throws InvalidArgumentException {

        if (StringUtil.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for orderer");
        }
        Exception e = checkGrpcUrl(url);
        if (e != null) {
            throw new InvalidArgumentException(e);
        }

        this.name = name;
        this.url = url;
        this.properties = properties == null ? null : (Properties) properties.clone(); //keep our own copy.

    }

    /**
     * getUrl - the Grpc url of the Orderer
     *
     * @return the Grpc url of the Orderer
     */
    public String getUrl() {
        return url;
    }


    void setChain(Chain chain) throws InvalidArgumentException {
        if (chain == null) {
            throw new InvalidArgumentException("Chain can not be null");
        }

        this.chain = chain;
    }

    private Chain chain;

    /**
     * Get the chain of which this orderer is a member.
     *
     * @return {Chain} The chain of which this orderer is a member.
     */
    Chain getChain() {
        return this.chain;
    }


    /**
     * Send transaction to Order
     *
     * @param transaction transaction to be sent
     */

    Ab.BroadcastResponse sendTransaction(Common.Envelope transaction) throws Exception {

        logger.debug(String.format("Order.sendTransaction name: %s, url: %s", name, url));

        OrdererClient orderClient = new OrdererClient(new Endpoint(url, properties).getChannelBuilder());
        return orderClient.sendTransaction(transaction);

    }


    static Orderer createNewInstance(String name, String url, Properties properties) throws InvalidArgumentException {
        return new Orderer(name, url, properties);

    }

    DeliverResponse[] sendDeliver(Common.Envelope transaction) throws TransactionException {

        logger.debug(String.format("Order.sendDeliver name: %s, url: %s", name, url));

        OrdererClient orderClient = new OrdererClient(new Endpoint(url, properties).getChannelBuilder());
        return orderClient.sendDeliver(transaction);

    }


} // end Orderer
