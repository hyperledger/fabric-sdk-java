/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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
import java.time.Instant;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.sdk.Chain;
import org.hyperledger.fabric.sdk.MemberServices;
import org.hyperledger.fabric.sdk.TCert;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;


/**
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 */
public class TransactionContext {
    private static final Config config = Config.getConfig();
    private static final Log logger = LogFactory.getLog(TransactionContext.class);
    //TODO right now the server does not care need to figure out
    private final ByteString nonce = ByteString.copyFromUtf8(SDKUtil.generateUUID());



    private boolean verify = true;

    public CryptoPrimitives getCryptoPrimitives() {
        return cryptoPrimitives;
    }

    private final CryptoPrimitives cryptoPrimitives;
    private final User user;
    private final Chain chain;

    private final MemberServices memberServices;
    private final String txID ;
    private TCert tcert;
    private List<String> attrs;
    private long proposalWaitTime = config.getProposalWaitTime();
    private final  Identities.SerializedIdentity  identity;

    public TransactionContext(Chain chain, User user, CryptoPrimitives cryptoPrimitives) {


        this.user = user;
        this.chain = chain;
        this.memberServices = this.chain.getMemberServices();
        this.tcert = tcert;
        //  this.txID = transactionID;
        this.cryptoPrimitives = cryptoPrimitives;


         identity = Identities.SerializedIdentity.newBuilder()
        .setIdBytes(ByteString.copyFromUtf8(getCreator()))
        .setMspid(getMSPID()).build();
        

        ByteString no = getNonce();
        ByteString comp = no.concat(identity.toByteString());
        byte[] txh = cryptoPrimitives.hash(comp.toByteArray());
    //    txID = Hex.encodeHexString(txh);
        txID = new String( Hex.encodeHex(txh));



    }

    public Identities.SerializedIdentity getIdentity(){

        return identity;

    }


    public long getEpoch(){
        return 0;
    }


    /**
     * Get the user with which this transaction context is associated.
     *
     * @return The user
     */
    public User getUser() {
        return this.user;
    }

    /**
     * Get the chain with which this transaction context is associated.
     *
     * @return The chain
     */
    public Chain getChain() {
        return this.chain;
    }

    /**
     * Get the user services, or undefined if security is not enabled.
     *
     * @return The user services
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

    /**
     * Gets the timeout for a single proposal request to endorser in milliseconds.
     *
     * @return the timeout for a single proposal request to endorser in milliseconds
     */
    public long getProposalWaitTime() {
        return proposalWaitTime;
    }

    /**
     * Sets the timeout for a single proposal request to endorser in milliseconds.
     *
     * @param proposalWaitTime the timeout for a single proposal request to endorser in milliseconds
     */
    public void setProposalWaitTime(long proposalWaitTime) {
        this.proposalWaitTime = proposalWaitTime;
    }


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

//    private TCert getMyTCert() {
//        if ( this.tcert != null) {
//            logger.debug("TCert already cached.");
//            return this.tcert;
//        }
//        logger.debug("No TCert cached. Retrieving one.");
//        return this.user.getNextTCert(this.attrs);
//    }

    Timestamp currentTimeStamp = null;


    public Timestamp getFabricTimestamp() {
        if (currentTimeStamp == null) {


            Timestamp.Builder ts = Timestamp.newBuilder();
            ts.setSeconds(Instant.now().toEpochMilli());
            currentTimeStamp = ts.build();
        }
        return currentTimeStamp;
    }

    ByteString getNonce() {

        return nonce;

    }

    public void verify(boolean verify) {
        this.verify = verify;
    }

    public boolean getVerify() {
        return verify;
    }

    private static class SerializedIdentity {
        String Mspid;
        byte[] IdBytes;

    }

    /* Implementation of an example ASN .1 structure. * < pre > *MyStructure:: = SEQUENCE
        { *version INTEGER DEFAULT 0, *created GeneralizedTime, *baseData OCTET STRING, *extraData[0]
            UTF8String OPTIONAL, *commentData[1] UTF8String OPTIONAL
        } * <pre > * */
    public static class MyStructure implements ASN1Encodable {

        public DERUTF8String Mspid = null;
        private DEROctetString IdBytes = null;

        MyStructure(String mspid, byte[] idbytes) {
            Mspid = new DERUTF8String(mspid);
            IdBytes = new DEROctetString(idbytes);

        }


        @Override
        public ASN1Primitive toASN1Primitive() {

            ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
            asn1EncodableVector.add(Mspid);
            asn1EncodableVector.add(IdBytes);

            //  ASN1Sequence asn1Sequence = ASN1Sequence.getInstance();
            return new DERSequence(asn1EncodableVector);
        }
    }


    String getMSPID() {
        return chain.getEnrollment().getMSPID();
    }

    String getCreator() {
        return chain.getEnrollment().getCert();

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
