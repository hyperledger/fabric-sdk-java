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

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.MemberServices;
import org.hyperledger.fabric.sdk.TCert;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.Buffer;
import java.time.Instant;
import java.util.List;


/**
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 */
public class TransactionContext {
    private static final Log logger = LogFactory.getLog(TransactionContext.class);

    public CryptoPrimitives getCryptoPrimitives() {
        return cryptoPrimitives;
    }

    private final CryptoPrimitives cryptoPrimitives;
    private User user;
    private Chain chain;

    private MemberServices memberServices;
    private String txID = null;
    private TCert tcert;
    private List<String> attrs;

    public TransactionContext(Chain chain, User user, CryptoPrimitives cryptoPrimitives) {

        this(SDKUtil.generateUUID(), chain, user, cryptoPrimitives);

    }

    public TransactionContext(String transactionID, Chain chain, User user, CryptoPrimitives cryptoPrimitives) {

        this.user = user;
        this.chain = chain;
        this.memberServices = this.chain.getMemberServices();
        this.tcert = tcert;
        this.txID = transactionID;
        this.cryptoPrimitives = cryptoPrimitives;

        //      this.nonce = this.chain.cryptoPrimitives.generateNonce();
    }

    /**
     * Get the user with which this transaction context is associated.
     *
     * @returns The user
     */
    public User getUser() {
        return this.user;
    }

    /**
     * Get the chain with which this transaction context is associated.
     *
     * @returns The chain
     */
    public Chain getChain() {
        return this.chain;
    }

    /**
     * Get the user services, or undefined if security is not enabled.
     *
     * @returns The user services
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

//    /**
//     * Execute a transaction
//     * @param tx {Transaction} The transaction.
//     */
//    private Fabric.Response execute(Transaction tx) {
//        logger.debug(String.format("Executing transaction [%s]", tx));
//
//        return getChain().sendTransaction(tx);
//        /*TODO implement security
//        // Get the TCert
//        self.getMyTCert();
//        if (err) {
//             logger.debug("Failed getting a new TCert [%s]", err);
//             return self.emit("error", new EventTransactionError(err));
//        }
//
//        if (!tcert) {
//                logger.debug("Missing TCert...");
//                return self.emit("error", new EventTransactionError("Missing TCert."));
//	}
//
//        // Set nonce
//        tx.pb.setNonce(self.nonce);
//
//        // Process confidentiality
//        logger.debug("Process Confidentiality...");
//
//        self.processConfidentiality(tx);
//
//        logger.debug("Sign transaction...");
//
//        // Add the tcert
//        tx.pb.setCert(tcert.publicKey);
//        // sign the transaction bytes
//        let txBytes = tx.pb.toBuffer();
//        let derSignature = self.chain.cryptoPrimitives.ecdsaSign(tcert.privateKey.getPrivate("hex"), txBytes).toDER();
//        // logger.debug('signature: ', derSignature);
//        tx.pb.setSignature(new Buffer(derSignature));
//
//        logger.debug("Send transaction...");
//        logger.debug("Confidentiality: ", tx.pb.getConfidentialityLevel());
//
//        if (tx.pb.getConfidentialityLevel() == _fabricProto.ConfidentialityLevel.CONFIDENTIAL &&
//               tx.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_QUERY) {
//               // Need to send a different event emitter so we can catch the response
//               // and perform decryption before sending the real complete response
//               // to the caller
//               var emitter = new events.EventEmitter();
//               emitter.on("complete", function (event:EventQueryComplete) {
//               logger.debug("Encrypted: [%s]", event);
//               event.result = self.decryptResult(event.result);
//               logger.debug("Decrypted: [%s]", event);
//               self.emit("complete", event);
//       });
//                    emitter.on("error", function (event:EventTransactionError) {
//                        self.emit("error", event);
//                    });
//                    self.getChain().sendTransaction(tx, emitter);
//                } else {
//                    self.getChain().sendTransaction(tx, self);
//                }
//            } else {
//            }
//
//        });
//        return self;
//    }
//
//    TCert getMyTCert(cb:GetTCertCallback) {
//    	TransactionContext self = this;
//        if (!self.getChain().isSecurityEnabled() || self.tcert) {
//            logger.debug("[TransactionContext] TCert already cached.");
//            return cb(null, self.tcert);
//        }
//        logger.debug("[TransactionContext] No TCert cached. Retrieving one.");
//        this.user.getNextTCert(self.attrs, function (err, tcert) {
//            if (err) return cb(err);
//            self.tcert = tcert;
//            return cb(null, tcert);
//        });
//        */
//    }
//
//    private void processConfidentiality(Transaction transaction) {
//        /* TODO implement processConfidentiality function
//    	// is confidentiality required?
//        if (transaction.pb.getConfidentialityLevel() != _fabricProto.ConfidentialityLevel.CONFIDENTIAL) {
//            // No confidentiality is required
//            return
//        }
//
//        logger.debug("Process Confidentiality ...");
//        var self = this;
//
//        // Set confidentiality level and protocol version
//        transaction.pb.setConfidentialityProtocolVersion("1.2");
//
//        // Generate transaction key. Common to all type of transactions
//        var txKey = self.chain.cryptoPrimitives.eciesKeyGen();
//
//        logger.debug("txkey [%s]", txKey.pubKeyObj.pubKeyHex);
//        logger.debug("txKey.prvKeyObj %s", txKey.prvKeyObj.toString());
//
//        var privBytes = self.chain.cryptoPrimitives.ecdsaPrivateKeyToASN1(txKey.prvKeyObj.prvKeyHex);
//        logger.debug("privBytes %s", privBytes.toString());
//
//        // Generate stateKey. Transaction type dependent step.
//        var stateKey;
//        if (transaction.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_DEPLOY) {
//            // The request is for a deploy
//            stateKey = new Buffer(self.chain.cryptoPrimitives.aesKeyGen());
//        } else if (transaction.pb.getType() == _fabricProto.Transaction.Type.CHAINCODE_INVOKE ) {
//            // The request is for an execute
//            // Empty state key
//            stateKey = new Buffer([]);
//        } else {
//            // The request is for a query
//            logger.debug("Generate state key...");
//            stateKey = new Buffer(self.chain.cryptoPrimitives.hmacAESTruncated(
//                self.user.getEnrollment().queryStateKey,
//                [CONFIDENTIALITY_1_2_STATE_KD_C6].concat(self.nonce)
//            ));
//        }
//
//        // Prepare ciphertexts
//
//        // Encrypts message to validators using self.enrollChainKey
//        var chainCodeValidatorMessage1_2 = new asn1Builder.Ber.Writer();
//        chainCodeValidatorMessage1_2.startSequence();
//        chainCodeValidatorMessage1_2.writeBuffer(privBytes, 4);
//        if (stateKey.length != 0) {
//            logger.debug("STATE KEY %s", stateKey);
//            chainCodeValidatorMessage1_2.writeBuffer(stateKey, 4);
//        } else {
//            chainCodeValidatorMessage1_2.writeByte(4);
//            chainCodeValidatorMessage1_2.writeLength(0);
//        }
//        chainCodeValidatorMessage1_2.endSequence();
//        logger.debug(chainCodeValidatorMessage1_2.buffer);
//
//        logger.debug("Using chain key [%s]", self.user.getEnrollment().chainKey);
//        var ecdsaChainKey = self.chain.cryptoPrimitives.ecdsaPEMToPublicKey(
//            self.user.getEnrollment().chainKey
//        );
//
//        let encMsgToValidators = self.chain.cryptoPrimitives.eciesEncryptECDSA(
//            ecdsaChainKey,
//            chainCodeValidatorMessage1_2.buffer
//        );
//        transaction.pb.setToValidators(encMsgToValidators);
//
//        // Encrypts chaincodeID using txKey
//        // logger.debug('CHAINCODE ID %s', transaction.chaincodeID);
//
//        let encryptedChaincodeID = self.chain.cryptoPrimitives.eciesEncrypt(
//            txKey.pubKeyObj,
//            transaction.pb.getChaincodeID().buffer
//        );
//        transaction.pb.setChaincodeID(encryptedChaincodeID);
//
//        // Encrypts payload using txKey
//        // logger.debug('PAYLOAD ID %s', transaction.payload);
//        let encryptedPayload = self.chain.cryptoPrimitives.eciesEncrypt(
//            txKey.pubKeyObj,
//            transaction.pb.getPayload().buffer
//        );
//        transaction.pb.setPayload(encryptedPayload);
//
//        // Encrypt metadata using txKey
//        if (transaction.pb.getMetadata() != null && transaction.pb.getMetadata().buffer != null) {
//            logger.debug("Metadata [%s]", transaction.pb.getMetadata().buffer);
//            let encryptedMetadata = self.chain.cryptoPrimitives.eciesEncrypt(
//                txKey.pubKeyObj,
//                transaction.pb.getMetadata().buffer
//            );
//            transaction.pb.setMetadata(encryptedMetadata);
//        }
//
//        */
//    }

    private void decryptResult(Buffer ct) {
        /* TODO implement decryptResult function
        let key = new Buffer(
            this.chain.cryptoPrimitives.hmacAESTruncated(
                this.user.getEnrollment().queryStateKey,
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

    Timestamp currentTimeStamp = null;


    public Timestamp getFabricTimestamp() {
        if (currentTimeStamp == null) {


            Timestamp.Builder ts = Timestamp.newBuilder();
            ts.setSeconds(Instant.now().toEpochMilli());
            currentTimeStamp = ts.build();
        }
        return currentTimeStamp;
    }


    public ByteString getNonce() {
        //TODO right now the server does not care need to figure out
        return ByteString.copyFromUtf8(SDKUtil.generateUUID());

    }

    private static class SerializedIdentity {
        String Mspid;
        byte[] IdBytes;

    }

    /* Implementation of an example ASN .1 structure. * < pre > *MyStructure:: = SEQUENCE
        { *version INTEGER DEFAULT 0, *created GeneralizedTime, *baseData OCTET STRING, *extraData[0]
            UTF8String OPTIONAL, *commentData[1] UTF8String OPTIONAL
        } * <pre > * */
    public static  class MyStructure implements ASN1Encodable {

        public DERUTF8String Mspid = null;
        private DEROctetString IdBytes = null;

        MyStructure(String mspid, byte[] idbytes){
                Mspid = new DERUTF8String( mspid);
                IdBytes = new DEROctetString(idbytes);

        }




        @Override
        public ASN1Primitive toASN1Primitive() {

            ASN1EncodableVector  asn1EncodableVector =new ASN1EncodableVector();
            asn1EncodableVector.add(Mspid);
            asn1EncodableVector.add(IdBytes);

          //  ASN1Sequence asn1Sequence = ASN1Sequence.getInstance();
            return  new DERSequence(asn1EncodableVector);
        }
    };

    public  String getMSPID(){
        return chain.getEnrollment().getMSPID();
    }

    public String getCreator() {
        //TODO right now the server does not care need to figure out needs to tcert or ecert of user

        /**
         * Type SerializedIdentity struct {
         Mspid string
         IdBytes []byte
         }
         */

        return chain.getEnrollment().getCert();


//        ByteArrayOutputStream bos = new ByteArrayOutputStream();
//        ASN1OutputStream encoder = new ASN1OutputStream(bos);
//
//        try {
//
//            MyStructure encoding = new MyStructure("DEFAULT", chain.getEnrollment().getCert().getBytes());
//            encoder.writeObject(encoding);
//
//
//
//
//            encoder.close();
//            return bos.toByteArray();
//
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            throw new RuntimeException(e);
//
//        } finally {
//            try {
//                if (null != encoder)
//                    encoder.close();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
    }




    public boolean isDevMode() {
        return chain.isDevMode();
    }

    public String getChainID() {
        return getChain().getName();
    }


    public String getTxID() {
        return txID;
    }
}  // end TransactionContext
