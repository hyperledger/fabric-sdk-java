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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

import com.google.protobuf.ByteString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.ChainCodeResponse;
import org.hyperledger.fabric.sdk.ChainCodeResponse.Status;
import org.hyperledger.fabric.sdk.DeployRequest;
import org.hyperledger.fabric.sdk.InvokeRequest;
import org.hyperledger.fabric.sdk.Member;
import org.hyperledger.fabric.sdk.MemberServices;
import org.hyperledger.fabric.sdk.QueryRequest;
import org.hyperledger.fabric.sdk.TCert;
import org.hyperledger.fabric.sdk.exception.ChainCodeException;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.NoAvailableTCertException;
import org.hyperledger.protos.Chaincode;
import org.hyperledger.protos.Fabric;
import org.hyperledger.protos.Fabric.Response.StatusCode;

/**
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 */
public class TransactionContext  {
	private static final Log logger = LogFactory.getLog(TransactionContext.class);

    private static final byte[] CONFIDENTIALITY_1_2_STATE_KD_C6 = new byte[] {6};

    private Member member;
    private Chain chain;
    private MemberServices memberServices;
    private byte[] nonce;
//    private binding: any;
    private TCert tcert;
    private List<String> attrs;

    public TransactionContext (Member member) {
    	this(member, null);
    }

    public TransactionContext (Member member, TCert tcert) {
        super();
        this.member = member;
        this.chain = member.getChain();
        this.memberServices = this.chain.getMemberServices();
        this.tcert = tcert;
        this.nonce = this.chain.getCryptoPrimitives().generateNonce();
    }

    /**
     * Get the member with which this transaction context is associated.
     * @return The member
     */
    public Member getMember() {
        return this.member;
    }

    /**
     * Get the chain with which this transaction context is associated.
     * @return The chain
     */
    public Chain getChain() {
        return this.chain;
    }

    /**
     * Get the member services, or undefined if security is not enabled.
     * @return The member services
     */
    public MemberServices getMemberServices() {
        return this.memberServices;
    }

    /**
     * Get the transaction certificate.
     * @return The transaction certificate
     */
    public TCert getTCert() {
        return this.tcert;
    }

    /**
     * Get the nonce.
     * @return The nonce
     */
    public byte[] getNonce() {
        return this.nonce;
    }

    /**
     * Emit a specific event provided an event listener is already registered.
     */
    public void emitMyEvent(String name, Object event) {
    	/*
       setTimeout(function() {
         // Check if an event listener has been registered for the event
         let listeners = self.listeners(name);

         // If an event listener has been registered, emit the event
         if (listeners && listeners.length > 0) {
            self.emit(name, event);
         }
       }, 0);
*/
    }

    /**
     * Issue a deploy transaction
     * @param deployRequest {@link DeployRequest} A deploy request
     * @return {@link ChainCodeResponse} response of deploy transaction
     */
    public ChainCodeResponse deploy(DeployRequest deployRequest) throws ChainCodeException, NoAvailableTCertException, CryptoException, IOException {
        logger.debug(String.format("Received deploy request: %s", deployRequest));

        if (null == getMyTCert() && getChain().isSecurityEnabled()) {
            logger.debug("Failed getting a new TCert");
            throw new NoAvailableTCertException("Failed getting a new TCert");
        }

        logger.debug("Got a TCert successfully, continue...");

        Transaction transaction = DeployTransactionBuilder.newBuilder().context(this).request(deployRequest).build();
        Fabric.Response response = execute(transaction);

        if (response.getStatus() == StatusCode.FAILURE) {
            throw new ChainCodeException(response.getMsg().toStringUtf8(), null);
        }

        return new ChainCodeResponse(
                transaction.getTxBuilder().getTxid(),
                transaction.getChaincodeID(),
                Status.UNDEFINED, response.getMsg().toStringUtf8());
    }

    /**
     * Issue an invoke on chaincode
     * @param invokeRequest {@link InvokeRequest} An invoke request
     * @throws ChainCodeException 
     */
    public ChainCodeResponse invoke(InvokeRequest invokeRequest) throws ChainCodeException, NoAvailableTCertException, CryptoException, IOException {
        logger.debug(String.format("Received invoke request: %s", invokeRequest));

        // Get a TCert to use in the invoke transaction
        setAttrs(invokeRequest.getAttributes());

        if (null == getMyTCert() && getChain().isSecurityEnabled()) {
            logger.debug("Failed getting a new TCert");
            throw new NoAvailableTCertException("Failed getting a new TCert");
        }

        logger.debug("Got a TCert successfully, continue...");

        Transaction transaction = InvocationTransactionBuilder.newBuilder().context(this).request(invokeRequest).build();
        Fabric.Response response = execute(transaction);

        if (response.getStatus() == StatusCode.FAILURE) {
            throw new ChainCodeException(response.getMsg().toStringUtf8(), null);
        }

        return new ChainCodeResponse(
                transaction.getTxBuilder().getTxid(),
                transaction.getChaincodeID(),
                Status.SUCCESS,
                response.getMsg().toStringUtf8());
    }

    /**
     * Issue a query transaction
     * @param queryRequest {@link QueryRequest}
     * @throws ChainCodeException
     */
    public ChainCodeResponse query(QueryRequest queryRequest) throws ChainCodeException, NoAvailableTCertException, CryptoException, IOException {
        logger.debug(String.format("Received query request: %s", queryRequest));

        // Get a TCert to use in the query transaction
        setAttrs(queryRequest.getAttributes());

        if (null == getMyTCert() && getChain().isSecurityEnabled()) {
            logger.debug("Failed getting a new TCert");
            throw new NoAvailableTCertException("Failed getting a new TCert");
        }
        logger.debug("Got a TCert successfully, continue...");

        Transaction transaction = QueryTransactionBuilder.newBuilder().context(this).request(queryRequest).build();
        Fabric.Response response = execute(transaction);

        if (response.getStatus() == StatusCode.FAILURE) {
            throw new ChainCodeException(response.getMsg().toStringUtf8(), null);
        }

        return new ChainCodeResponse(
                transaction.getTxBuilder().getTxid(),
                transaction.getChaincodeID(),
                Status.SUCCESS,
                response.getMsg().toStringUtf8());
    }

   /**
    * Get the attribute names associated
    */
   public List<String> getAttrs() {
       return this.attrs;
   }

   /**
    * Set the attributes for this transaction context.
    */
   public void setAttrs(List<String> attrs) {
       this.attrs = attrs;
   }

    /**
     * Execute a transaction
     * @param tx {Transaction} The transaction.
     */
    private Fabric.Response execute(Transaction tx) throws CryptoException, IOException {
        logger.debug(String.format("Executing transaction [%s]", tx));

        // Set nonce
        tx.getTxBuilder().setNonce(ByteString.copyFrom(this.nonce));

        // Process confidentiality
        logger.debug("Process Confidentiality...");

        this.processConfidentiality(tx);

        logger.debug("Sign transaction...");

        if (getChain().isSecurityEnabled()) {
            // Add the tcert
            tx.getTxBuilder().setCert(ByteString.copyFrom(tcert.getCert()));
            // sign the transaction bytes
            byte[] txBytes = tx.getTxBuilder().buildPartial().toByteArray();
            BigInteger[] signature = this.chain.getCryptoPrimitives().ecdsaSign(tcert.getPrivateKey(), txBytes);
            byte[] derSignature = this.chain.getCryptoPrimitives().toDER(
                    new byte[][]{signature[0].toByteArray(), signature[1].toByteArray()});

            tx.getTxBuilder().setSignature(ByteString.copyFrom(derSignature));
        }

        logger.debug("Send transaction...");
        logger.debug("Confidentiality: " + tx.getTxBuilder().getConfidentialityLevel());

        if (tx.getTxBuilder().getConfidentialityLevel() == Chaincode.ConfidentialityLevel.CONFIDENTIAL &&
                tx.getTxBuilder().getType() == Fabric.Transaction.Type.CHAINCODE_QUERY) {
            Fabric.Response response = this.getChain().sendTransaction(tx);
            if (response.getStatus() == StatusCode.SUCCESS) {
                byte[] message = decryptResult(response.getMsg().toByteArray());
                return Fabric.Response.newBuilder()
                        .setStatus(StatusCode.SUCCESS)
                        .setMsg(ByteString.copyFrom(message))
                        .build();
            } else {
                return response;
            }
        } else {
            return this.getChain().sendTransaction(tx);
        }
    }

    private void processConfidentiality(Transaction transaction) throws CryptoException, IOException {
        // is confidentiality required?
        if (transaction.getTxBuilder().getConfidentialityLevel() != Chaincode.ConfidentialityLevel.CONFIDENTIAL) {
            // No confidentiality is required
            return;
        }

        logger.debug("Process Confidentiality ...");

        // Set confidentiality level and protocol version
        transaction.getTxBuilder().setConfidentialityProtocolVersion("1.2");

        // Generate transaction key. Common to all type of transactions
        KeyPair txKey = this.chain.getCryptoPrimitives().eciesKeyGen();

        ASN1Encodable privBytes = this.chain.getCryptoPrimitives().ecdsaPrivateKeyToASN1(txKey.getPrivate());

        // Generate stateKey. Transaction type dependent step.
        byte[] stateKey;
        if (transaction.getTxBuilder().getType() == Fabric.Transaction.Type.CHAINCODE_DEPLOY) {
            // The request is for a deploy
            stateKey = this.chain.getCryptoPrimitives().aesKeyGen();
        } else if (transaction.getTxBuilder().getType() == Fabric.Transaction.Type.CHAINCODE_INVOKE ) {
            // The request is for an execute
            // Empty state key
            stateKey = new byte[0];
        } else {
            // The request is for a query
            logger.debug("Generate state key...");
            stateKey = this.chain.getCryptoPrimitives().hmacAESTruncated(
                    Hex.decode(this.member.getEnrollment().getQueryStateKey()),
                    Arrays.concatenate(CONFIDENTIALITY_1_2_STATE_KD_C6, this.nonce));
        }

        // Prepare ciphertexts

        // Encrypts message to validators using self.enrollChainKey
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            DERSequenceGenerator seq = new DERSequenceGenerator(byteArrayOutputStream);
            seq.addObject(new DEROctetString(privBytes));
            seq.addObject(new DEROctetString(stateKey));
            seq.close();
        } catch (IOException e) {
            // ignore
        }

        logger.debug("Using chain key: " + this.member.getEnrollment().getChainKey());
        PublicKey ecdsaChainKey = this.chain.getCryptoPrimitives().ecdsaPEMToPublicKey(
                this.member.getEnrollment().getChainKey()
        );

        byte[] encMsgToValidators = this.chain.getCryptoPrimitives().eciesEncryptECDSA(
            ecdsaChainKey,
            byteArrayOutputStream.toByteArray()
        );
        transaction.getTxBuilder().setToValidators(ByteString.copyFrom(encMsgToValidators));

        // Encrypts chaincodeID using txKey
        // logger.debug('CHAINCODE ID %s', transaction.chaincodeID);

        byte[] encryptedChaincodeID = this.chain.getCryptoPrimitives().eciesEncrypt(
            txKey.getPublic(),
            transaction.getTxBuilder().getChaincodeID().toByteArray()
        );
        transaction.getTxBuilder().setChaincodeID(ByteString.copyFrom(encryptedChaincodeID));

        // Encrypts payload using txKey
        byte[] encryptedPayload = this.chain.getCryptoPrimitives().eciesEncrypt(
            txKey.getPublic(),
            transaction.getTxBuilder().getPayload().toByteArray()
        );
        transaction.getTxBuilder().setPayload(ByteString.copyFrom(encryptedPayload));

        // Encrypt metadata using txKey
        if (transaction.getTxBuilder().getMetadata() != null && transaction.getTxBuilder().getMetadata().toByteArray() != null) {
            byte[] encryptedMetadata = this.chain.getCryptoPrimitives().eciesEncrypt(
                txKey.getPublic(),
                transaction.getTxBuilder().getMetadata().toByteArray()
            );
            transaction.getTxBuilder().setMetadata(ByteString.copyFrom(encryptedMetadata));
        }
    }

    private byte[] decryptResult(byte[] ct) throws CryptoException {
        byte[] key = this.chain.getCryptoPrimitives().hmacAESTruncated(
                Hex.decode(this.member.getEnrollment().getQueryStateKey()),
                Arrays.concatenate(CONFIDENTIALITY_1_2_STATE_KD_C6, this.nonce));

        return this.chain.getCryptoPrimitives().aes256GCMDecrypt(key, ct);
    }

    private TCert getMyTCert() {        
        if (!getChain().isSecurityEnabled() || this.tcert != null) {
            logger.debug("TCert already cached.");
            return this.tcert;
        }
        logger.debug("No TCert cached. Retrieving one.");
        this.tcert = this.member.getNextTCert(this.attrs);
        return this.tcert;
    }

}  // end TransactionContext
