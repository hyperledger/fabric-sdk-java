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

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.peer.ChaincodeProposal;
import org.hyperledger.fabric.protos.peer.ChaincodeTransaction.ChaincodeActionPayload;
import org.hyperledger.fabric.protos.peer.ChaincodeTransaction.ChaincodeEndorsedAction;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.protos.peer.FabricTransaction.Transaction;
import org.hyperledger.fabric.protos.peer.FabricTransaction.TransactionAction;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

public class TransactionBuilder {

	private Log logger = LogFactory.getLog(TransactionBuilder.class);
	private FabricProposal.Proposal chaincodeProposal;
	private Collection<FabricProposalResponse.Endorsement> endorsements;
	private ByteString proposalResponcePayload;
	private String chainId;
	private TransactionContext context;
	private CryptoPrimitives cryptoPrimitives;

	public static TransactionBuilder newBuilder() {
		return new TransactionBuilder();
	}

	public TransactionBuilder context(TransactionContext context) {
		this.context = context;
		return this;
	}

	public TransactionBuilder cryptoPrimitives(CryptoPrimitives cryptoPrimitives) {
		this.cryptoPrimitives = cryptoPrimitives;
		return this;
	}

	public TransactionBuilder chainID(String chainId) {
		this.chainId = chainId;
		return this;
	}

	public TransactionBuilder chaincodeProposal(FabricProposal.Proposal chaincodeProposal) {
		this.chaincodeProposal = chaincodeProposal;
		return this;
	}

	public TransactionBuilder endorsements(Collection<FabricProposalResponse.Endorsement> endorsements) {
		this.endorsements = endorsements;
		return this;
	}

	public TransactionBuilder proposalResponcePayload(ByteString proposalResponcePayload) {
		this.proposalResponcePayload = proposalResponcePayload;
		return this;
	}

	public Envelope build() throws CryptoException, InvalidProtocolBufferException {
		return createTransactionEnvelope(chaincodeProposal, proposalResponcePayload, endorsements);
	}

	private Common.Envelope createTransactionEnvelope(FabricProposal.Proposal chaincodeProposal,
	        ByteString proposalResponcePayload, Collection<FabricProposalResponse.Endorsement> endorsements)
	        throws CryptoException, InvalidProtocolBufferException {

		ChaincodeEndorsedAction ccea = ChaincodeEndorsedAction.newBuilder()
		        .setProposalResponsePayload(proposalResponcePayload).addAllEndorsements(endorsements).build();

		//We need to remove any transient fields - they are not part of what the peer uses to calculate hash.
		ChaincodeProposal.ChaincodeProposalPayload chaincodeProposalPayloadNoTrans = ChaincodeProposal.ChaincodeProposalPayload.newBuilder()
				.mergeFrom(chaincodeProposal.getPayload())
				.clearTransient().build();
		byte[] bhash = cryptoPrimitives.hash(chaincodeProposalPayloadNoTrans.toByteArray());

		ChaincodeActionPayload ccap = ChaincodeActionPayload.newBuilder().setAction(ccea)
		        .setChaincodeProposalPayload(ByteString.copyFrom(bhash)).build();

		Common.Header header = Common.Header.parseFrom(chaincodeProposal.getHeader());

		TransactionAction ta = TransactionAction.newBuilder().setHeader(header.getSignatureHeader().toByteString())
		        .setPayload(ccap.toByteString()).build();

		Transaction transaction = Transaction.newBuilder().addActions(ta).build();

		Payload payload = Payload.newBuilder().setHeader(header).setData(transaction.toByteString()).build();

		byte[] ecdsaSignature = cryptoPrimitives.ecdsaSign(context.getMember().getEnrollment().getPrivateKey(), payload.toByteArray());

		Envelope ce = Envelope.newBuilder().setPayload(payload.toByteString())
		        .setSignature(ByteString.copyFrom(ecdsaSignature))
				.build();

		logger.debug("Done creating transaction ready for orderer");

		return ce;

	}
}
