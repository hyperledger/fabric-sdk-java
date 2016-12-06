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

package org.hyperledger.fabric.sdk.transaction;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.protos.Chaincode;
import org.hyperledger.protos.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.protos.Chaincode.ChaincodeSpec;
import org.hyperledger.protos.Chaincode.ConfidentialityLevel;

import com.google.protobuf.ByteString;
import org.hyperledger.protos.Fabric;

public abstract class TransactionBuilder {
	private static final Log logger = LogFactory.getLog(TransactionBuilder.class);

	protected TransactionRequest request = null;
	protected TransactionContext context = null;

	public TransactionBuilder request(TransactionRequest request) {
		this.request = request;
		return this;
	}
	
	public TransactionBuilder context(TransactionContext context) {
		this.context = context;
		return this;
	}
	
	public abstract Transaction build();

	/**
	 * Create a transaction
	 * @param ccType Chaincode type (GOLANG, JAVA etc)
	 * @param transactionType The type of transaction (Deploy/Query/Invoke etc)
	 * @param name name of the chaincode
	 * @param args argument list for the transaction
	 * @param codePackage chaincode contents - only used for NetMode deploy transaction
	 * @param txId transaction ID
	 * @param chaincodePath Chain code path - only used for DevMode deploy transaction
	 * @return {@link Fabric.Transaction.Builder}
	 */
	protected Fabric.Transaction.Builder createTransactionBuilder(
			Chaincode.ChaincodeSpec.Type ccType, 
			Fabric.Transaction.Type transactionType,
			String name, 
			List<String> args,
			byte[] codePackage,
			String txId,
			String chaincodePath) throws CryptoException, IOException {
		// build chaincodeId
		Chaincode.ChaincodeID.Builder chaincodeIDBuilder = Chaincode.ChaincodeID.newBuilder().setName(name);
		if (chaincodePath != null) {
			chaincodeIDBuilder = chaincodeIDBuilder.setPath(chaincodePath);
		}
		Chaincode.ChaincodeID chaincodeID = chaincodeIDBuilder.build(); 
		
		// build chaincodeInput
		List<ByteString> argList = new ArrayList<>(args.size());		
		for (String arg : args) {
			argList.add(ByteString.copyFrom(arg.getBytes()));
		}
		Chaincode.ChaincodeInput chaincodeInput = Chaincode.ChaincodeInput.newBuilder().addAllArgs(argList).build();

		// Construct the ChaincodeSpec
		ChaincodeSpec chaincodeSpec = Chaincode.ChaincodeSpec.newBuilder().setType(ccType).setChaincodeID(chaincodeID)
				.setCtorMsg(chaincodeInput).build();
		
		// create payload
		ByteString payload = null;

		switch (transactionType.getNumber()) {
		case Fabric.Transaction.Type.CHAINCODE_DEPLOY_VALUE:
			// Construct the ChaincodeDeploymentSpec (i.e. the payload)
			ChaincodeDeploymentSpec.Builder chaincodeDeploymentSpecBuilder = Chaincode.ChaincodeDeploymentSpec
					.newBuilder().setChaincodeSpec(chaincodeSpec);

			if (codePackage != null && codePackage.length > 0) {
				chaincodeDeploymentSpecBuilder = chaincodeDeploymentSpecBuilder
						.setCodePackage(ByteString.copyFrom(codePackage));
			}
			payload = chaincodeDeploymentSpecBuilder.build().toByteString();
			break;
		case Fabric.Transaction.Type.CHAINCODE_QUERY_VALUE:
		case Fabric.Transaction.Type.CHAINCODE_INVOKE_VALUE:
			// Construct the ChaincodeDeploymentSpec (i.e. the payload)
			payload = Chaincode.ChaincodeInvocationSpec.newBuilder().setChaincodeSpec(chaincodeSpec).build()
					.toByteString();
			break;
		}
		
		// public or confidential?
		ConfidentialityLevel confidentialityLevel = request.isConfidential()
				? Chaincode.ConfidentialityLevel.CONFIDENTIAL : Chaincode.ConfidentialityLevel.PUBLIC;
		
		// Initialize a transaction structure
		Fabric.Transaction.Builder txBuilder = Fabric.Transaction.newBuilder()
				.setType(transactionType).setChaincodeID(chaincodeID.toByteString())
				.setTxid(txId)
				.setTimestamp(SDKUtil.generateTimestamp()).setConfidentialityLevel(confidentialityLevel);
		
		if (payload != null) {
			txBuilder = txBuilder.setPayload(payload);
		}

		if (request.getMetadata() != null && request.getMetadata().length > 0) {
			txBuilder.setMetadata(ByteString.copyFrom(request.getMetadata()));
		}

        if (request.getUserCert() != null) {
            byte[] certRaw = context.getTCert().getCert();
            logger.debug("========== Invoker Cert: " + Hex.toHexString(certRaw));
            byte[] nonceRaw = context.getNonce();
            byte[] bindingMsg = Arrays.concatenate(certRaw, nonceRaw);
            logger.debug("========== Binding Msg [%s]" + Hex.toHexString(bindingMsg));
            byte[] binding = context.getChain().getCryptoPrimitives().hash(bindingMsg);
            logger.debug("========== Binding: " + Hex.toHexString(binding));
            byte[] ctor = chaincodeSpec.getCtorMsg().toByteArray();
            logger.debug("========== Ctor: " + Hex.toHexString(ctor));
            byte[] txmsg = Arrays.concatenate(ctor, binding);
            logger.debug("========== Payload||binding: " + Hex.toHexString(txmsg));
            BigInteger[] mdsig = context.getChain().getCryptoPrimitives().ecdsaSign(request.getUserCert().getPrivateKey(), txmsg);
            byte[] sigma = context.getChain().getCryptoPrimitives().toDER(new byte[][]{mdsig[0].toByteArray(), mdsig[1].toByteArray()});
            logger.debug("========== Sigma: " + Hex.toHexString(sigma));
            txBuilder.setMetadata(ByteString.copyFrom(sigma));
        }

        return txBuilder;
	}
}
