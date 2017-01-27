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

import java.nio.Buffer;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.MemberServices;
import org.hyperledger.fabric.sdk.TCert;
import org.hyperledger.fabric.sdk.helper.SDKUtil;;

/**
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 */
public class TransactionContext  {
	private static final Log logger = LogFactory.getLog(TransactionContext.class);
    private User user;
    private Chain chain;
    private MemberServices memberServices;
    private String nonce;
    private TCert tcert;
    private List<String> attrs;
    private String ecert;


    public TransactionContext (Chain chain, User user) {
        super();
        if (user == null || !user.isEnrolled()) {
			throw new IllegalArgumentException("Member must be enrolled before creating a transaction context");
        }
        this.user = user;
        this.chain = chain;
        this.memberServices = this.chain.getMemberServices();
        this.ecert = user.getEnrollment().getCert();
        this.nonce = SDKUtil.generateUUID();
    }

    public String getEcert() {
		return this.ecert;
    }

    public void setEcert(String ecert) {
		this.ecert = ecert;
    }

    /**
     * Get the member with which this transaction context is associated.
     * @returns The member
     */
    public User getMember() {
        return this.user;
    }

    /**
     * Get the chain with which this transaction context is associated.
     * @returns The chain
     */
    public Chain getChain() {
        return this.chain;
    }

    /**
     * Get the member services, or undefined if security is not enabled.
     * @returns The member services
     */
    public MemberServices getMemberServices() {
        return this.memberServices;
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


    //private void processConfidentiality(Transaction transaction) {
        /* TODO implement processConfidentiality function
    	// is confidentiality required?
        if (transaction.pb.getConfidentialityLevel() != _fabricProto.ConfidentialityLevel.CONFIDENTIAL) {
            // No confidentiality is required
            return
        }

        logger.debug("Process Confidentiality ...");
        var self = this;

        // Set confidentiality level and protocol version
        transaction.pb.setConfidentialityProtocolVersion("1.2");

        // Generate transaction key. Common to all type of transactions
        var txKey = self.chain.cryptoPrimitives.eciesKeyGen();

        logger.debug("txkey [%s]", txKey.pubKeyObj.pubKeyHex);
        logger.debug("txKey.prvKeyObj %s", txKey.prvKeyObj.toString());

        var privBytes = self.chain.cryptoPrimitives.ecdsaPrivateKeyToASN1(txKey.prvKeyObj.prvKeyHex);
        logger.debug("privBytes %s", privBytes.toString());

        // Generate stateKey. Transaction type dependent step.
        var stateKey;
        if (transaction.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_DEPLOY) {
            // The request is for a deploy
            stateKey = new Buffer(self.chain.cryptoPrimitives.aesKeyGen());
        } else if (transaction.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_INVOKE ) {
            // The request is for an execute
            // Empty state key
            stateKey = new Buffer([]);
        } else {
            // The request is for a query
            logger.debug("Generate state key...");
            stateKey = new Buffer(self.chain.cryptoPrimitives.hmacAESTruncated(
                self.member.getEnrollment().queryStateKey,
                [CONFIDENTIALITY_1_2_STATE_KD_C6].concat(self.nonce)
            ));
        }

        // Prepare ciphertexts

        // Encrypts message to validators using self.enrollChainKey
        var chainCodeValidatorMessage1_2 = new asn1Builder.Ber.Writer();
        chainCodeValidatorMessage1_2.startSequence();
        chainCodeValidatorMessage1_2.writeBuffer(privBytes, 4);
        if (stateKey.length != 0) {
            logger.debug("STATE KEY %s", stateKey);
            chainCodeValidatorMessage1_2.writeBuffer(stateKey, 4);
        } else {
            chainCodeValidatorMessage1_2.writeByte(4);
            chainCodeValidatorMessage1_2.writeLength(0);
        }
        chainCodeValidatorMessage1_2.endSequence();
        logger.debug(chainCodeValidatorMessage1_2.buffer);

        logger.debug("Using chain key [%s]", self.member.getEnrollment().chainKey);
        var ecdsaChainKey = self.chain.cryptoPrimitives.ecdsaPEMToPublicKey(
            self.member.getEnrollment().chainKey
        );

        let encMsgToValidators = self.chain.cryptoPrimitives.eciesEncryptECDSA(
            ecdsaChainKey,
            chainCodeValidatorMessage1_2.buffer
        );
        transaction.pb.setToValidators(encMsgToValidators);

        // Encrypts chaincodeID using txKey
        // logger.debug('CHAINCODE ID %s', transaction.chaincodeID);

        let encryptedChaincodeID = self.chain.cryptoPrimitives.eciesEncrypt(
            txKey.pubKeyObj,
            transaction.pb.getChaincodeID().buffer
        );
        transaction.pb.setChaincodeID(encryptedChaincodeID);

        // Encrypts payload using txKey
        // logger.debug('PAYLOAD ID %s', transaction.payload);
        let encryptedPayload = self.chain.cryptoPrimitives.eciesEncrypt(
            txKey.pubKeyObj,
            transaction.pb.getPayload().buffer
        );
        transaction.pb.setPayload(encryptedPayload);

        // Encrypt metadata using txKey
        if (transaction.pb.getMetadata() != null && transaction.pb.getMetadata().buffer != null) {
            logger.debug("Metadata [%s]", transaction.pb.getMetadata().buffer);
            let encryptedMetadata = self.chain.cryptoPrimitives.eciesEncrypt(
                txKey.pubKeyObj,
                transaction.pb.getMetadata().buffer
            );
            transaction.pb.setMetadata(encryptedMetadata);
        }

        */
    //}

    private void decryptResult(Buffer ct) {
        /* TODO implement decryptResult function
        let key = new Buffer(
            this.chain.cryptoPrimitives.hmacAESTruncated(
                this.member.getEnrollment().queryStateKey,
                [CONFIDENTIALITY_1_2_STATE_KD_C6].concat(this.nonce))
        );

        logger.debug("Decrypt Result [%s]", ct.toString("hex"));
        return this.chain.cryptoPrimitives.aes256GCMDecrypt(key, ct);
        */
    }

    private TCert getMyTCert() {
        if (!getChain().isSecurityEnabled() || this.tcert != null) {
            logger.debug("TCert already cached.");
            return this.tcert;
        }
        logger.debug("No TCert cached. Retrieving one.");
        return this.user.getNextTCert(this.attrs);
    }


}  // end TransactionContext
