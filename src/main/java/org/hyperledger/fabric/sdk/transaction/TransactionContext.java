/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.transaction;


import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

/**
 * A transaction context emits events 'submitted', 'complete', and 'error'.
 * Each transaction context uses exactly one tcert.
 */
public class TransactionContext {
    private static final Config config = Config.getConfig();
    //    private static final Log logger = LogFactory.getLog(TransactionContext.class);
    //TODO right now the server does not care need to figure out
    private final ByteString nonce = ByteString.copyFrom(Utils.generateNonce());

    private boolean verify = true;

    public CryptoSuite getCryptoPrimitives() {
        return cryptoPrimitives;
    }

    private final CryptoSuite cryptoPrimitives;
    private final User user;
    private final Channel channel;

    private final String txID;

    //private List<String> attrs;
    private long proposalWaitTime = config.getProposalWaitTime();
    private final Identities.SerializedIdentity identity;

    public TransactionContext(Channel channel, User user, CryptoSuite cryptoPrimitives) {

        this.user = user;
        this.channel = channel;
        //TODO clean up when public classes are interfaces.
        this.verify = !"".equals(channel.getName());  //if name is not blank not system channel and need verify.

        //  this.txID = transactionID;
        this.cryptoPrimitives = cryptoPrimitives;

        identity = ProtoUtils.createSerializedIdentity(getUser());

        ByteString no = getNonce();

        ByteString comp = no.concat(identity.toByteString());

        byte[] txh = cryptoPrimitives.hash(comp.toByteArray());

        //    txID = Hex.encodeHexString(txh);
        txID = new String(Utils.toHexString(txh));

    }

    public Identities.SerializedIdentity getIdentity() {

        return identity;

    }

    public long getEpoch() {
        return 0;
    }

    /**
     * Get the user with which this transaction context is associated.
     *
     * @return The user
     */
    public User getUser() {
        return user;
    }

    /**
     * Get the channel with which this transaction context is associated.
     *
     * @return The channel
     */
    public Channel getChannel() {
        return this.channel;
    }

    /**
     * Get the attribute names associated with this transaction context.
     *
     * @return the attributes.
     */
    //public List<String> getAttrs() {
    //    return this.attrs;
    //}

    /**
     * Set the attributes for this transaction context.
     *
     * @param attrs the attributes.
     */
    //public void setAttrs(List<String> attrs) {
    //    this.attrs = attrs;
    //}

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

    Timestamp currentTimeStamp = null;

    public Timestamp getFabricTimestamp() {
        if (currentTimeStamp == null) {

            currentTimeStamp = ProtoUtils.getCurrentFabricTimestamp();
        }
        return currentTimeStamp;
    }

    public ByteString getNonce() {

        return nonce;

    }

    public void verify(boolean verify) {
        this.verify = verify;
    }

    public boolean getVerify() {
        return verify;
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

    public String getChannelID() {
        return getChannel().getName();
    }

    public String getTxID() {
        return txID;
    }

    byte[] sign(byte[] b) throws CryptoException {
        return cryptoPrimitives.sign(getUser().getEnrollment().getKey(), b);
    }

    public ByteString signByteString(byte[] b) throws CryptoException {
        return ByteString.copyFrom(sign(b));
    }

    public ByteString signByteStrings(ByteString... bs) throws CryptoException {
        if (bs == null) {
            return null;
        }
        if (bs.length == 0) {
            return null;
        }
        if (bs.length == 1 && bs[0] == null) {
            return null;
        }

        ByteString f = bs[0];
        for (int i = 1; i < bs.length; ++i) {
            f = f.concat(bs[i]);

        }
        return ByteString.copyFrom(sign(f.toByteArray()));
    }

    public ByteString[] signByteStrings(User[] users, ByteString... bs) throws CryptoException {
        if (bs == null) {
            return null;
        }
        if (bs.length == 0) {
            return null;
        }
        if (bs.length == 1 && bs[0] == null) {
            return null;
        }

        ByteString f = bs[0];
        for (int i = 1; i < bs.length; ++i) {
            f = f.concat(bs[i]);
        }

        final byte[] signbytes = f.toByteArray();

        ByteString[] ret = new ByteString[users.length];

        int i = -1;
        for (User user : users) {
            ret[++i] = ByteString.copyFrom(cryptoPrimitives.sign(user.getEnrollment().getKey(), signbytes));
        }
        return ret;
    }

}  // end TransactionContext
