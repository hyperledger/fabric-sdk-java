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

import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.TransactionRequest;

public abstract class TransactionBuilder {
	
	protected TransactionRequest request = null;
	protected Chain chain = null;
	
	public TransactionBuilder request(TransactionRequest request) {
		this.request = request;
		return this;
	}
	
	public TransactionBuilder chain(Chain chain) {
		this.chain = chain;
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
//	protected Fabric.Transaction.Builder createTransactionBuilder(
//			Chaincode.ChaincodeSpec.Type ccType, 
//			Fabric.Transaction.Type transactionType,
//			String name, 
//			List<String> args,
//			byte[] codePackage,
//			String txId,
//			String chaincodePath) {
//		// build chaincodeId
//		Chaincode.ChaincodeID.Builder chaincodeIDBuilder = Chaincode.ChaincodeID.newBuilder().setName(name);
//		if (chaincodePath != null) {
//			chaincodeIDBuilder = chaincodeIDBuilder.setPath(chaincodePath);
//		}
//		Chaincode.ChaincodeID chaincodeID = chaincodeIDBuilder.build(); 
//		
//		// build chaincodeInput
//		List<ByteString> argList = new ArrayList<>(args.size());		
//		for (String arg : args) {
//			argList.add(ByteString.copyFrom(arg.getBytes()));
//		}
//		Chaincode.ChaincodeInput chaincodeInput = Chaincode.ChaincodeInput.newBuilder().addAllArgs(argList).build();
//
//		// Construct the ChaincodeSpec
//		ChaincodeSpec chaincodeSpec = Chaincode.ChaincodeSpec.newBuilder().setType(ccType).setChaincodeID(chaincodeID)
//				.setCtorMsg(chaincodeInput).build();
//		
//		// create payload
//		ByteString payload = null;
//
//		switch (transactionType.getNumber()) {
//		case Fabric.Transaction.Type.CHAINCODE_DEPLOY_VALUE:
//			// Construct the ChaincodeDeploymentSpec (i.e. the payload)
//			ChaincodeDeploymentSpec.Builder chaincodeDeploymentSpecBuilder = Chaincode.ChaincodeDeploymentSpec
//					.newBuilder().setChaincodeSpec(chaincodeSpec);
//
//			if (codePackage != null && codePackage.length > 0) {
//				chaincodeDeploymentSpecBuilder = chaincodeDeploymentSpecBuilder
//						.setCodePackage(ByteString.copyFrom(codePackage));
//			}
//			payload = chaincodeDeploymentSpecBuilder.build().toByteString();
//			break;
//		case Fabric.Transaction.Type.CHAINCODE_QUERY_VALUE:
//		case Fabric.Transaction.Type.CHAINCODE_INVOKE_VALUE:
//			// Construct the ChaincodeDeploymentSpec (i.e. the payload)
//			payload = Chaincode.ChaincodeInvocationSpec.newBuilder().setChaincodeSpec(chaincodeSpec).build()
//					.toByteString();
//			break;
//		}
//		
//		// public or confidential?
//		ConfidentialityLevel confidentialityLevel = request.isConfidential()
//				? Chaincode.ConfidentialityLevel.CONFIDENTIAL : Chaincode.ConfidentialityLevel.PUBLIC;
//		
//		// Initialize a transaction structure
//		Fabric.Transaction.Builder txBuilder = Fabric.Transaction.newBuilder()
//				.setType(transactionType).setChaincodeID(chaincodeID.toByteString())
//				.setTxid(txId)
//				.setTimestamp(SDKUtil.generateTimestamp()).setConfidentialityLevel(confidentialityLevel);
//		
//		if (payload != null) {
//			txBuilder = txBuilder.setPayload(payload);
//		}
//
//		if (request.getMetadata() != null && request.getMetadata().length > 0) {
//			txBuilder.setMetadata(ByteString.copyFrom(request.getMetadata()));
//		}
//		
//		 /*if (request.userCert) {
//			 // cert based
//			 let certRaw = new Buffer(self.tcert.publicKey);
//			 // logger.debug('========== Invoker Cert [%s]',certRaw.toString("hex"));
//			 let nonceRaw = new Buffer(self.nonce);
//			 let bindingMsg = Buffer.concat([certRaw, nonceRaw]);
//			 // logger.debug('========== Binding Msg [%s]', bindingMsg.toString("hex"));
//			 self.binding = new Buffer(self.chain.cryptoPrimitives.hash(bindingMsg), "hex");
//			 // logger.debug('========== Binding [%s]', self.binding.toString("hex"));
//			 let ctor = chaincodeSpec.getCtorMsg().toBuffer();
//			 // logger.debug('========== Ctor [%s]', ctor.toString("hex"));
//			 let txmsg = Buffer.concat([ctor, self.binding]);
//			 // logger.debug('========== Payload||binding [%s]',
//			 txmsg.toString("hex"));
//			 let mdsig = self.chain.cryptoPrimitives.ecdsaSign(request.userCert.privateKey.getPrivate("hex"), txmsg);
//			 let sigma = new Buffer(mdsig.toDER());
//			 // logger.debug('========== Sigma [%s]', sigma.toString("hex"));
//			 return sigma
//		}*/
//		
//		return txBuilder;
//	}
}
