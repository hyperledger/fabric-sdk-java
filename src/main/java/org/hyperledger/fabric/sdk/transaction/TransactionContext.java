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
import org.hyperledger.fabric.sdk.ChainCodeResponse;
import org.hyperledger.fabric.sdk.ChainCodeResponse.Status;
import org.hyperledger.fabric.sdk.DeployRequest;
import org.hyperledger.fabric.sdk.InvokeRequest;
import org.hyperledger.fabric.sdk.Member;
import org.hyperledger.fabric.sdk.MemberServices;
import org.hyperledger.fabric.sdk.QueryRequest;
import org.hyperledger.fabric.sdk.TCert;
import org.hyperledger.fabric.sdk.exception.ChainCodeException;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.protos.Fabric;
import org.hyperledger.protos.Fabric.Response.StatusCode;

/**
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 */
public class TransactionContext  {
	private static final Log logger = LogFactory.getLog(TransactionContext.class);
    private Member member;
    private Chain chain;
    private MemberServices memberServices;
//    private nonce: any;
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
  //      this.nonce = this.chain.cryptoPrimitives.generateNonce();
    }

    /**
     * Get the member with which this transaction context is associated.
     * @returns The member
     */
    public Member getMember() {
        return this.member;
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
     * Issue a deploy transaction
     * @param deployRequest {@link DeployRequest} A deploy request
     * @return {@link ChainCodeResponse} response of deploy transaction
     */
    public ChainCodeResponse deploy(DeployRequest deployRequest) throws DeploymentException {
        logger.debug(String.format("Received deploy request: %s", deployRequest));
        
       /* this.tcert = getMyTCert();
        if (null == tcert) {
//           logger.debug("Failed getting a new TCert [%s]", err);
//           self.emitMyEvent("error", new EventTransactionError(err));
        	throw new RuntimeException("Failed getting a new TCert");
//           return self;
         }

         logger.debug("Got a TCert successfully, continue...");
         */

			Transaction transaction = DeployTransactionBuilder.newBuilder().chain(chain).request(deployRequest).build();
	        execute(transaction);
	        return new ChainCodeResponse(
	        		transaction.getTransaction().getTxid(),
	        		transaction.getChaincodeID(),
	        		Status.UNDEFINED, null);
    }

    /**
     * Issue an invoke on chaincode
     * @param invokeRequest {@link InvokeRequest} An invoke request
     * @throws ChainCodeException 
     */
    public ChainCodeResponse invoke(InvokeRequest invokeRequest) throws ChainCodeException {        
        logger.debug(String.format("Received invoke request: %s", invokeRequest));

        // Get a TCert to use in the invoke transaction
        setAttrs(invokeRequest.getAttributes());

        /*TODO add error check
        self.getMyTCert(function (err, tcert) {
            if (err) {
                logger.debug('Failed getting a new TCert [%s]', err);
                self.emitMyEvent('error', new EventTransactionError(err));

                return self;
            }

            logger.debug("Got a TCert successfully, continue...");
		*/
        Transaction transaction = InvocationTransactionBuilder.newBuilder().chain(chain).request(invokeRequest).build();

        /*TODO add error check
              if (err) {
                logger.debug("Error in newInvokeOrQueryTransaction [%s]", err);
                self.emitMyEvent('error', new EventTransactionError(err));

                return self;
              }

              logger.debug("Calling TransactionContext.execute");

              return self.execute(invokeTx);
            });
        });
        return self;
        */
        Fabric.Response response = execute(transaction);
        if (response.getStatus() == StatusCode.FAILURE) {
        	throw new ChainCodeException(response.getMsg().toStringUtf8(), null);
        }
        
        return new ChainCodeResponse(
        		transaction.getTransaction().getTxid(),
        		transaction.getChaincodeID(),
        		Status.SUCCESS, 
        		response.getMsg().toStringUtf8());
    }

    /**
     * Issue a query transaction
     * @param queryRequest {@link QueryRequest}
     * @throws ChainCodeException
     */
    public ChainCodeResponse query(QueryRequest queryRequest) throws ChainCodeException {      
      logger.debug(String.format("Received query request: %s", queryRequest));


      // Get a TCert to use in the query transaction
      setAttrs(queryRequest.getAttributes());

      /*TODO obtain certificates
      self.getMyTCert(function (err, tcert) {
          if (err) {
              logger.debug('Failed getting a new TCert [%s]', err);
              self.emitMyEvent('error', new EventTransactionError(err));

              return self;
          }

          logger.debug("Got a TCert successfully, continue...");

          self.newInvokeOrQueryTransaction(queryRequest, false, function(err, queryTx) {
            if (err) {
              logger.debug("Error in newInvokeOrQueryTransaction [%s]", err);
              self.emitMyEvent('error', new EventTransactionError(err));

              return self;
            }

            logger.debug("Calling TransactionContext.execute");

            return self.execute(queryTx);
          });
        });
      return self;
      */

      Transaction transaction = QueryTransactionBuilder.newBuilder().chain(chain).request(queryRequest).build();
      Fabric.Response response = execute(transaction);
      
      if (response.getStatus() == StatusCode.FAILURE) {
      	throw new ChainCodeException(response.getMsg().toStringUtf8(), null);
      }
      
      return new ChainCodeResponse(
      		transaction.getTransaction().getTxid(),
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
    private Fabric.Response execute(Transaction tx) {
        logger.debug(String.format("Executing transaction [%s]", tx));

        return getChain().sendTransaction(tx);
        /*TODO implement security
        // Get the TCert
        self.getMyTCert();
        if (err) {
             logger.debug("Failed getting a new TCert [%s]", err);
             return self.emit("error", new EventTransactionError(err));
        }

        if (!tcert) {
                logger.debug("Missing TCert...");
                return self.emit("error", new EventTransactionError("Missing TCert."));
	}

        // Set nonce
        tx.pb.setNonce(self.nonce);

        // Process confidentiality
        logger.debug("Process Confidentiality...");

        self.processConfidentiality(tx);

        logger.debug("Sign transaction...");

        // Add the tcert
        tx.pb.setCert(tcert.publicKey);
        // sign the transaction bytes
        let txBytes = tx.pb.toBuffer();
        let derSignature = self.chain.cryptoPrimitives.ecdsaSign(tcert.privateKey.getPrivate("hex"), txBytes).toDER();
        // logger.debug('signature: ', derSignature);
        tx.pb.setSignature(new Buffer(derSignature));

        logger.debug("Send transaction...");
        logger.debug("Confidentiality: ", tx.pb.getConfidentialityLevel());

        if (tx.pb.getConfidentialityLevel() == _fabricProto.ConfidentialityLevel.CONFIDENTIAL &&
               tx.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_QUERY) {
               // Need to send a different event emitter so we can catch the response
               // and perform decryption before sending the real complete response
               // to the caller
               var emitter = new events.EventEmitter();
               emitter.on("complete", function (event:EventQueryComplete) {
               logger.debug("Encrypted: [%s]", event);
               event.result = self.decryptResult(event.result);
               logger.debug("Decrypted: [%s]", event);
               self.emit("complete", event);
       });
                    emitter.on("error", function (event:EventTransactionError) {
                        self.emit("error", event);
                    });
                    self.getChain().sendTransaction(tx, emitter);
                } else {
                    self.getChain().sendTransaction(tx, self);
                }
            } else {
            }

        });
        return self;
    }

    TCert getMyTCert(cb:GetTCertCallback) {
    	TransactionContext self = this;
        if (!self.getChain().isSecurityEnabled() || self.tcert) {
            logger.debug("[TransactionContext] TCert already cached.");
            return cb(null, self.tcert);
        }
        logger.debug("[TransactionContext] No TCert cached. Retrieving one.");
        this.member.getNextTCert(self.attrs, function (err, tcert) {
            if (err) return cb(err);
            self.tcert = tcert;
            return cb(null, tcert);
        });
        */
    }

    private void processConfidentiality(Transaction transaction) {
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
    }

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
        return this.member.getNextTCert(this.attrs);
    }


}  // end TransactionContext
