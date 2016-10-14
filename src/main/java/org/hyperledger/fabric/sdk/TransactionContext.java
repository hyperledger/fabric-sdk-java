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
import com.google.protobuf.Timestamp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.protos.Chaincode;
import org.hyperledger.protos.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.protos.Chaincode.ChaincodeDeploymentSpec.ExecutionEnvironment;
import org.hyperledger.protos.Chaincode.ChaincodeInput;
import org.hyperledger.protos.Chaincode.ChaincodeSpec;
import org.hyperledger.protos.Chaincode.ConfidentialityLevel;
import org.hyperledger.protos.Fabric;

import java.nio.Buffer;
import java.util.ArrayList;

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
    private ArrayList<String> attrs;

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
       TransactionContext self = this;
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
     * Issue a deploy transaction.
     * @param deployRequest {Object} A deploy request of the form: { chaincodeID, payload, metadata, uuid, timestamp, confidentiality: { level, version, nonce }
   */
    public TransactionContext deploy(DeployRequest deployRequest) {
        logger.debug(String.format("Received deploy request: %s", deployRequest));

        // Get a TCert to use in the deployment transaction
        /*TODO implement security
        this.tcert = getMyTCert();
        if (null == tcert) {
           logger.debug("Failed getting a new TCert [%s]", err);
           self.emitMyEvent("error", new EventTransactionError(err));

           return self;
         }

         logger.debug("Got a TCert successfully, continue...");
         */

         Transaction transaction = createTransaction(deployRequest, Fabric.Transaction.Type.CHAINCODE_DEPLOY);

         /*TODO implement error checks
         if (err) {
                logger.debug("Error in newBuildOrDeployTransaction [%s]", err);
                self.emitMyEvent("error", new EventTransactionError(err));

                return self;
          }

          logger.debug("Calling TransactionContext.execute");
		*/

        execute(transaction);
        return this;
    }

    /**
     * Issue an invoke transaction.
     * @param invokeRequest {Object} An invoke request of the form: XXX
     */
    public TransactionContext invoke(InvokeRequest invokeRequest) {        
        logger.debug(String.format("Received invoke request: %s", invokeRequest));

        // Get a TCert to use in the invoke transaction
        setAttrs(invokeRequest.attrs);

        /*TODO add error check
        self.getMyTCert(function (err, tcert) {
            if (err) {
                logger.debug('Failed getting a new TCert [%s]', err);
                self.emitMyEvent('error', new EventTransactionError(err));

                return self;
            }

            logger.debug("Got a TCert successfully, continue...");
		*/
        Transaction transaction = invokeTransaction(invokeRequest);

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
        return execute(transaction);
    }

    /**
     * Issue an query transaction.
     * @param queryRequest {Object} A query request of the form: XXX
     */
    public TransactionContext query(QueryRequest queryRequest) {      
      logger.debug(String.format("Received query request: %s", queryRequest));


      // Get a TCert to use in the query transaction
      setAttrs(queryRequest.attrs);

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

      Transaction transaction = queryTransaction(queryRequest);
      return execute(transaction);
    }

   /**
    * Get the attribute names associated
    */
   public ArrayList<String> getAttrs() {
       return this.attrs;
   }

   /**
    * Set the attributes for this transaction context.
    */
   public void setAttrs(ArrayList<String> attrs) {
       this.attrs = attrs;
   }

    /**
     * Execute a transaction
     * @param tx {Transaction} The transaction.
     */
    private TransactionContext execute(Transaction tx) {
        logger.debug(String.format("Executing transaction [%s]", tx));

        getChain().sendTransaction(tx);
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
        return null; //TODO return the correct certificate
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

    /**
     * Create a deploy transaction.
     * @param request {Object} A BuildRequest or DeployRequest
     */
    private void newBuildOrDeployTransaction(DeployRequest request, boolean isBuildRequest) {
      	logger.debug("newBuildOrDeployTransaction");

        // Determine if deployment is for dev mode or net mode
        if (chain.isDevMode()) {
            // Deployment in developent mode. Build a dev mode transaction.
            newDevModeTransaction(request, isBuildRequest);

            /*TODO add logic implemented in callback function
             function(err, tx) {
                if(err) {
                    return cb(err);
                } else {
                    return cb(null, tx);
                }
            });
            */
        } else {
            // Deployment in network mode. Build a net mode transaction.
//            newNetModeTransaction(request, isBuildRequest);

            /*TODO add logic implemented in callback function
            function(err, tx) {
                if(err) {
                    return cb(err);
                } else {
                    return cb(null, tx);
                }
            });
            */
        }
    } // end newBuildOrDeployTransaction



    private Transaction createTransaction(TransactionRequest request, Fabric.Transaction.Type transactionType) {

    	//Construct the chaincodeID
        Chaincode.ChaincodeID chaincodeID =  Chaincode.ChaincodeID.newBuilder()
        		.setPath(request.chaincodePath)
        		.build();
//        logger.debug("newDevModeTransaction: chaincodeID: " + JSON.stringify(chaincodeID));


        //convert all args to ByteString
        ArrayList<ByteString> args = new ArrayList<>(request.args.size());
        for(String arg : request.args) {
        	args.add(ByteString.copyFrom(arg.getBytes()));
        }

        // Set ctorMsg
        ChaincodeInput chaincodeInput = Chaincode.ChaincodeInput.newBuilder()
        		.addAllArgs(args)
        		.build();

        // Construct the ChaincodeSpec
        ChaincodeSpec chaincodeSpec = Chaincode.ChaincodeSpec.newBuilder()
                .setType(Chaincode.ChaincodeSpec.Type.GOLANG)
                .setChaincodeID(chaincodeID)
                .setCtorMsg(chaincodeInput)
                .build();


        // Construct the ChaincodeDeploymentSpec (i.e. the payload)

        ChaincodeDeploymentSpec chaincodeDeploymentSpec = Chaincode.ChaincodeDeploymentSpec.newBuilder()
        		.setChaincodeSpec(chaincodeSpec)
        		.setExecEnv(ExecutionEnvironment.DOCKER)
        		.build();

        ConfidentialityLevel confidentialityLevel = request.confidential ? Chaincode.ConfidentialityLevel.CONFIDENTIAL : Chaincode.ConfidentialityLevel.PUBLIC;

        Fabric.Transaction tx = Fabric.Transaction.newBuilder()
        		.setType(transactionType)
        		.setChaincodeID(chaincodeID.toByteString())
        		.setPayload(chaincodeDeploymentSpec.toByteString())
        		.setTxid("aaa")
        		.setTimestamp(Timestamp.getDefaultInstance())
//TODO        		.setMetadata(request.metadata)
        		.build();


                /*TODO Set the user certificate data
                if (request.userCert) {
                	/*TODO implement user certificates
                    // cert based
                    let certRaw = new Buffer(self.tcert.publicKey);
                    // logger.debug('========== Invoker Cert [%s]', certRaw.toString("hex"));
                    let nonceRaw = new Buffer(self.nonce);
                    let bindingMsg = Buffer.concat([certRaw, nonceRaw]);
                    // logger.debug('========== Binding Msg [%s]', bindingMsg.toString("hex"));
                    this.binding = new Buffer(self.chain.cryptoPrimitives.hash(bindingMsg), "hex");
                    // logger.debug('========== Binding [%s]', this.binding.toString("hex"));
                    let ctor = chaincodeSpec.getCtorMsg().toBuffer();
                    // logger.debug('========== Ctor [%s]', ctor.toString("hex"));
                    let txmsg = Buffer.concat([ctor, this.binding]);
                    // logger.debug('========== Payload||binding [%s]', txmsg.toString("hex"));
                    let mdsig = self.chain.cryptoPrimitives.ecdsaSign(request.userCert.privateKey.getPrivate("hex"), txmsg);
                    let sigma = new Buffer(mdsig.toDER());
                    // logger.debug('========== Sigma [%s]', sigma.toString("hex"));
                    tx.setMetadata(sigma);
                }
                    */

        return new Transaction(tx, request.chaincodeName);

    }

    /**
     * Create a development mode deploy transaction.
     * @param request {Object} A development mode BuildRequest or DeployRequest
     */
    private Transaction newDevModeTransaction(DeployRequest request, boolean isBuildRequest) {
        logger.debug("newDevModeTransaction");

        // Verify that chaincodeName is being passed
        if (null == request.chaincodeName || request.chaincodeName.equals("")) {
          throw new RuntimeException("missing chaincodeName in DeployRequest");
        }

        return createTransaction(request, Fabric.Transaction.Type.CHAINCODE_DEPLOY);
    }

    /**
     * Create a network mode deploy transaction.
     * @param request {Object} A network mode BuildRequest or DeployRequest
     */

    /*TODO revisit newNetModeTransaction
    private void newNetModeTransaction(DeployRequest request, boolean isBuildRequest, cb:DeployTransactionCallback) {
        logger.debug("newNetModeTransaction");

        let self = this;

        // Verify that chaincodePath is being passed
        if (!request.chaincodePath || request.chaincodePath === "") {
          return cb(Error("missing chaincodePath in DeployRequest"));
        }

        // Determine the user's $GOPATH
        let goPath =  process.env["GOPATH"];
        logger.debug("$GOPATH: " + goPath);

        // Compose the path to the chaincode project directory
        let projDir = goPath + "/src/" + request.chaincodePath;
        logger.debug("projDir: " + projDir);

        // Compute the hash of the chaincode deployment parameters
        let hash = sdk_util.GenerateParameterHash(request.chaincodePath, request.fcn, request.args);

        // Compute the hash of the project directory contents
        hash = sdk_util.GenerateDirectoryHash(goPath + "/src/", request.chaincodePath, hash);
        logger.debug("hash: " + hash);

        // Compose the Dockerfile commands
     	  let dockerFileContents =
        "from hyperledger/fabric-baseimage" + "\n" +
     	  "COPY . $GOPATH/src/build-chaincode/" + "\n" +
     	  "WORKDIR $GOPATH" + "\n\n" +
     	  "RUN go install build-chaincode && cp src/build-chaincode/vendor/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && mv $GOPATH/bin/build-chaincode $GOPATH/bin/%s";

     	  // Substitute the hashStrHash for the image name
     	  dockerFileContents = util.format(dockerFileContents, hash);

     	  // Create a Docker file with dockerFileContents
     	  let dockerFilePath = projDir + "/Dockerfile";
     	  fs.writeFile(dockerFilePath, dockerFileContents, function(err) {
            if (err) {
                logger.debug(util.format("Error writing file [%s]: %s", dockerFilePath, err));
                return cb(Error(util.format("Error writing file [%s]: %s", dockerFilePath, err)));
            }

            logger.debug("Created Dockerfile at [%s]", dockerFilePath);

            // Create the .tar.gz file of the chaincode package
            let targzFilePath = "/tmp/deployment-package.tar.gz";
            // Create the compressed archive
            sdk_util.GenerateTarGz(projDir, targzFilePath, function(err) {
                if(err) {
                    logger.debug(util.format("Error creating deployment archive [%s]: %s", targzFilePath, err));
                    return cb(Error(util.format("Error creating deployment archive [%s]: %s", targzFilePath, err)));
                }

                logger.debug(util.format("Created deployment archive at [%s]", targzFilePath));

                //
                // Initialize a transaction structure
                //

                let tx = new _fabricProto.Transaction();

                //
                // Set the transaction type
                //

                if (isBuildRequest) {
                    tx.setType(_fabricProto.Transaction.Type.CHAINCODE_BUILD);
                } else {
                    tx.setType(_fabricProto.Transaction.Type.CHAINCODE_DEPLOY);
                }

                //
                // Set the chaincodeID
                //

                let chaincodeID = new _chaincodeProto.ChaincodeID();
                chaincodeID.setName(hash);
                logger.debug("chaincodeID: " + JSON.stringify(chaincodeID));
                tx.setChaincodeID(chaincodeID.toBuffer());

                //
                // Set the payload
                //

                // Construct the ChaincodeSpec
                let chaincodeSpec = new _chaincodeProto.ChaincodeSpec();

                // Set Type -- GOLANG is the only chaincode language supported at this time
                chaincodeSpec.setType(_chaincodeProto.ChaincodeSpec.Type.GOLANG);
                // Set chaincodeID
                chaincodeSpec.setChaincodeID(chaincodeID);
                // Set ctorMsg
                let chaincodeInput = new _chaincodeProto.ChaincodeInput();
                chaincodeInput.setFunction(request.fcn);
                chaincodeInput.setArgs(request.args);
                chaincodeSpec.setCtorMsg(chaincodeInput);
                logger.debug("chaincodeSpec: " + JSON.stringify(chaincodeSpec));

                // Construct the ChaincodeDeploymentSpec and set it as the Transaction payload
                let chaincodeDeploymentSpec = new _chaincodeProto.ChaincodeDeploymentSpec();
                chaincodeDeploymentSpec.setChaincodeSpec(chaincodeSpec);

                // Read in the .tar.zg and set it as the CodePackage in ChaincodeDeploymentSpec
                fs.readFile(targzFilePath, function(err, data) {
                    if(err) {
                        logger.debug(util.format("Error reading deployment archive [%s]: %s", targzFilePath, err));
                        return cb(Error(util.format("Error reading deployment archive [%s]: %s", targzFilePath, err)));
                    }

                    logger.debug(util.format("Read in deployment archive from [%s]", targzFilePath));

                    chaincodeDeploymentSpec.setCodePackage(data);
                    tx.setPayload(chaincodeDeploymentSpec.toBuffer());

                    //
                    // Set the transaction UUID
                    //

                    tx.setUuid(sdk_util.GenerateUUID());

                    //
                    // Set the transaction timestamp
                    //

                    tx.setTimestamp(sdk_util.GenerateTimestamp());

                    //
                    // Set confidentiality level
                    //

                    if (request.confidential) {
                        logger.debug("Set confidentiality level to CONFIDENTIAL");
                        tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.CONFIDENTIAL);
                    } else {
                        logger.debug("Set confidentiality level to PUBLIC");
                        tx.setConfidentialityLevel(_fabricProto.ConfidentialityLevel.PUBLIC);
                    }

                    //
                    // Set request metadata
                    //

                    if (request.metadata) {
                        tx.setMetadata(request.metadata);
                    }

                    //
                    // Set the user certificate data
                    //

                    if (request.userCert) {
                        // cert based
                        let certRaw = new Buffer(self.tcert.publicKey);
                        // logger.debug('========== Invoker Cert [%s]', certRaw.toString("hex"));
                        let nonceRaw = new Buffer(self.nonce);
                        let bindingMsg = Buffer.concat([certRaw, nonceRaw]);
                        // logger.debug('========== Binding Msg [%s]', bindingMsg.toString("hex"));
                        self.binding = new Buffer(self.chain.cryptoPrimitives.hash(bindingMsg), "hex");
                        // logger.debug('========== Binding [%s]', self.binding.toString("hex"));
                        let ctor = chaincodeSpec.getCtorMsg().toBuffer();
                        // logger.debug('========== Ctor [%s]', ctor.toString("hex"));
                        let txmsg = Buffer.concat([ctor, self.binding]);
                        // logger.debug('========== Payload||binding [%s]', txmsg.toString("hex"));
                        let mdsig = self.chain.cryptoPrimitives.ecdsaSign(request.userCert.privateKey.getPrivate("hex"), txmsg);
                        let sigma = new Buffer(mdsig.toDER());
                        // logger.debug('========== Sigma [%s]', sigma.toString("hex"));
                        tx.setMetadata(sigma);
                    }

                    //
                    // Clean up temporary files
                    //

                    // Remove the temporary .tar.gz with the deployment contents and the Dockerfile
                    fs.unlink(targzFilePath, function(err) {
                        if(err) {
                            logger.debug(util.format("Error deleting temporary archive [%s]: %s", targzFilePath, err));
                            return cb(Error(util.format("Error deleting temporary archive [%s]: %s", targzFilePath, err)));
                        }

                        logger.debug("Temporary archive deleted successfully ---> " + targzFilePath);

                        fs.unlink(dockerFilePath, function(err) {
                            if(err) {
                                logger.debug(util.format("Error deleting temporary file [%s]: %s", dockerFilePath, err));
                                return cb(Error(util.format("Error deleting temporary file [%s]: %s", dockerFilePath, err)));
                            }

                            logger.debug("File deleted successfully ---> " + dockerFilePath);

                            //
                            // Return the deploy transaction structure
                            //

                            tx = new Transaction(tx, hash);

                            return cb(null, tx);
                        }); // end delete Dockerfile
                    }); // end delete .tar.gz
              }); // end reading .tar.zg and composing transaction
	         }); // end writing .tar.gz
	      }); // end writing Dockerfile
    }

    */


    private Transaction invokeTransaction(InvokeOrQueryRequest request) {
    	return createTransaction(request, Fabric.Transaction.Type.CHAINCODE_INVOKE);
    }

    private Transaction queryTransaction(InvokeOrQueryRequest request) {
    	return createTransaction(request, Fabric.Transaction.Type.CHAINCODE_QUERY);
    }

}  // end TransactionContext
