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

import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.orderer.Ab;

public class Orderer {
	private Chain chain;
	private OrdererClient ordererClient;

	/**
     * Constructor for the orderer given the endpoint config for the orderer.
     * @param {string} url The URL of the orderer
     * @param {Chain} The chain of which this orderer is a member.
     * @returns {Orderer} The new orderer.
     */
	
	public Orderer(String url, String pem, Chain chain) {
        this.chain = chain;
        Endpoint ep = new Endpoint(url, pem);
        this.ordererClient = new OrdererClient(ep.getChannelBuilder());
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

	public Ab.BroadcastResponse sendTransaction(Envelope transaction) {
		return ordererClient.sendTransaction(transaction);
	}

}
