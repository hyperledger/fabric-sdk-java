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

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.protos.Chaincode;
import org.hyperledger.protos.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.protos.Chaincode.ChaincodeInvocationSpec;
import org.hyperledger.protos.Chaincode.ChaincodeSpec;
import org.hyperledger.protos.DevopsGrpc;
import org.hyperledger.protos.DevopsGrpc.DevopsBlockingStub;
import org.hyperledger.protos.DevopsGrpc.DevopsStub;
import org.hyperledger.protos.Fabric.Response;

import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

/**
 * Sample client code that makes gRPC calls to the server.
 */
public class DevopsClient {
	private static final Log logger = LogFactory.getLog(DevopsClient.class);

	private final ManagedChannel channel;
	private final DevopsBlockingStub blockingStub;
	private final DevopsStub asyncStub;
	private String chaincodeName = "";

	/**
	 * Construct client for accessing Peer server using the existing channel.
	 */
	public DevopsClient(ManagedChannelBuilder<?> channelBuilder) {
		channel = channelBuilder.build();
		blockingStub = DevopsGrpc.newBlockingStub(channel);
		asyncStub = DevopsGrpc.newStub(channel);
	}

	public void shutdown() throws InterruptedException {
		channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
	}

	public void query(QueryRequest request) {
		logger.info("query");

		Chaincode.ChaincodeInvocationSpec ispec = getInvocationSpec(request);

		Response response;
		try {
			response = blockingStub.query(ispec);
		} catch (StatusRuntimeException e) {
			logger.warn(String.format("RPC failed: %s", e.getStatus()));
			return;
		}
		logger.info(String.format("Status: \"%s\" at %s, %s", response.getStatusValue(), response.getStatus().name(),
				String.valueOf(response.getMsg().toStringUtf8())));

	}

	private ChaincodeSpec getChaincodeSpec(TransactionRequest request) {

		Chaincode.ChaincodeID cid = Chaincode.ChaincodeID.newBuilder().setName(chaincodeName)
				.setPath(request.getChaincodePath()).build();

		ArrayList<ByteString> args = new ArrayList<>(request.getArgs().size());
		for (String arg : request.getArgs()) {
			args.add(ByteString.copyFrom(arg.getBytes()));
		}

		Chaincode.ChaincodeInput input = Chaincode.ChaincodeInput.newBuilder()
				// .setFunction()
				.addAllArgs(args).build();

		Chaincode.ChaincodeSpec spec = Chaincode.ChaincodeSpec.newBuilder()
				.setType(Chaincode.ChaincodeSpec.Type.GOLANG).setChaincodeID(cid).setCtorMsg(input).build();

		return spec;
	}

	private ChaincodeInvocationSpec getInvocationSpec(TransactionRequest request) {

		return Chaincode.ChaincodeInvocationSpec.newBuilder().setChaincodeSpec(getChaincodeSpec(request))
				.build();
	}

	public void invoke(InvokeRequest request) {
		logger.info("invoke");

		Chaincode.ChaincodeInvocationSpec ispec = getInvocationSpec(request);

		Response response;
		try {
			response = blockingStub.invoke(ispec);
		} catch (StatusRuntimeException e) {
			logger.warn(String.format("RPC failed: %s", e.getStatus()));
			return;
		}
		logger.info(String.format("Status: \"%s\" at %s, %s", response.getStatusValue(), response.getStatus().name(),
				String.valueOf(response.getMsg().toStringUtf8())));

	}

	/**
	 * Blocking unary call example. Calls getFeature and prints the response.
	 */
	public void deploy(DeployRequest request) {
		logger.info("deploy	");

		ChaincodeSpec spec = getChaincodeSpec(request);
		ChaincodeDeploymentSpec response;
		try {
			response = blockingStub.deploy(spec);
		} catch (StatusRuntimeException e) {
			logger.warn(String.format("RPC failed: %s", e.getStatus()));
			return;
		}
		chaincodeName = response.getChaincodeSpec().getChaincodeID().getName();
		logger.info(String.format("Status: \"%s\" at %s, %s", response.getChaincodeSpec().getChaincodeID().getName(),
				response.getExecEnv().toString(), response.getExecEnv().toString()));
	}

	@Override
	public void finalize() {
		try {
			shutdown();
		} catch (InterruptedException e) {
			logger.debug("Failed to shutdown the DevopsClient");
		}
	}

}
