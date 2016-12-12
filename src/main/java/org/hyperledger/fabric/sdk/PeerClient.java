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

import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.EndorserGrpc;
import org.hyperledger.fabric.protos.peer.EndorserGrpc.EndorserBlockingStub;
import org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse;
import org.hyperledger.fabric.sdk.exception.PeerException;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

/**
 * Sample client code that makes gRPC calls to the server.
 */
public class PeerClient {
	private static final Log logger = LogFactory.getLog(PeerClient.class);

	private final ManagedChannel channel;
	private final EndorserBlockingStub blockingStub;

	/**
	 * Construct client for accessing Peer server using the existing channel.
	 */
	public PeerClient(ManagedChannelBuilder<?> channelBuilder) {
		channel = channelBuilder.build();
		blockingStub = EndorserGrpc.newBlockingStub(channel);
	}

	public void shutdown() throws InterruptedException {
		channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
	}
	
	public ProposalResponse processProposal(SignedProposal request) throws PeerException {
		try {
			return blockingStub.processProposal(request);
		} catch(Exception exp) {
			throw new PeerException("Failed to send proposal to peer", exp);
		}
	}

	@Override
	public void finalize() {
		try {
			shutdown();
		} catch (InterruptedException e) {
			logger.debug("Failed to shutdown the PeerClient");
		}
	}
}
