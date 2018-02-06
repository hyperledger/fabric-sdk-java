/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.hyperledger.fabric.sdk.transaction;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.ChannelHeader;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.common.Common.SignatureHeader;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.orderer.Ab.SeekInfo;
import org.hyperledger.fabric.protos.orderer.Ab.SeekInfo.SeekBehavior;
import org.hyperledger.fabric.protos.orderer.Ab.SeekPosition;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInput;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec.Type;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeHeaderExtension;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.helper.Utils.logString;
import static org.hyperledger.fabric.sdk.helper.Utils.toHexString;

/**
 * Internal use only, not a public API.
 */
public final class ProtoUtils {

    private static final Log logger = LogFactory.getLog(ProtoUtils.class);
    private static final boolean isDebugLevel = logger.isDebugEnabled();
    public static CryptoSuite suite;

    /**
     * Private constructor to prevent instantiation.
     */
    private ProtoUtils() {
    }

    // static CryptoSuite suite = null;

    /*
     * createChannelHeader create chainHeader
     *
     * @param type                     header type. See {@link ChannelHeader.Builder#setType}.
     * @param txID                     transaction ID. See {@link ChannelHeader.Builder#setTxId}.
     * @param channelID                channel ID. See {@link ChannelHeader.Builder#setChannelId}.
     * @param epoch                    the epoch in which this header was generated. See {@link ChannelHeader.Builder#setEpoch}.
     * @param timeStamp                local time when the message was created. See {@link ChannelHeader.Builder#setTimestamp}.
     * @param chaincodeHeaderExtension extension to attach dependent on the header type. See {@link ChannelHeader.Builder#setExtension}.
     * @param tlsCertHash
     * @return a new chain header.
     */
    public static ChannelHeader createChannelHeader(HeaderType type, String txID, String channelID, long epoch,
                                                    Timestamp timeStamp, ChaincodeHeaderExtension chaincodeHeaderExtension,
                                                    byte[] tlsCertHash) {

        if (isDebugLevel) {
            String tlschs = "";
            if (tlsCertHash != null) {
                tlschs = DatatypeConverter.printHexBinary(tlsCertHash);

            }
            logger.debug(format("ChannelHeader: type: %s, version: 1, Txid: %s, channelId: %s, epoch %d, clientTLSCertificate digest: %s",
                    type.name(), txID, channelID, epoch, tlschs));

        }

        ChannelHeader.Builder ret = ChannelHeader.newBuilder()
                .setType(type.getNumber())
                .setVersion(1)
                .setTxId(txID)
                .setChannelId(channelID)
                .setTimestamp(timeStamp)
                .setEpoch(epoch);
        if (null != chaincodeHeaderExtension) {
            ret.setExtension(chaincodeHeaderExtension.toByteString());
        }

        if (tlsCertHash != null) {
            ret.setTlsCertHash(ByteString.copyFrom(tlsCertHash));
        }

        return ret.build();

    }

    public static ChaincodeDeploymentSpec createDeploymentSpec(Type ccType, String name, String chaincodePath,
                                                               String chaincodeVersion, List<String> args,
                                                               byte[] codePackage) {

        ChaincodeID.Builder chaincodeIDBuilder = ChaincodeID.newBuilder().setName(name).setVersion(chaincodeVersion);
        if (chaincodePath != null) {
            chaincodeIDBuilder = chaincodeIDBuilder.setPath(chaincodePath);
        }

        ChaincodeID chaincodeID = chaincodeIDBuilder.build();

        // build chaincodeInput
        List<ByteString> argList = new ArrayList<>(args == null ? 0 : args.size());
        if (args != null && args.size() != 0) {

            for (String arg : args) {
                argList.add(ByteString.copyFrom(arg.getBytes(UTF_8)));
            }

        }

        ChaincodeInput chaincodeInput = ChaincodeInput.newBuilder().addAllArgs(argList).build();

        // Construct the ChaincodeSpec
        ChaincodeSpec chaincodeSpec = ChaincodeSpec.newBuilder().setType(ccType).setChaincodeId(chaincodeID)
                .setInput(chaincodeInput)
                .build();

        if (isDebugLevel) {
            StringBuilder sb = new StringBuilder(1000);
            sb.append("ChaincodeDeploymentSpec chaincode cctype: ")
                    .append(ccType.name())
                    .append(", name:")
                    .append(chaincodeID.getName())
                    .append(", path: ")
                    .append(chaincodeID.getPath())
                    .append(", version: ")
                    .append(chaincodeID.getVersion());

            String sep = "";
            sb.append(" args(");

            for (ByteString x : argList) {
                sb.append(sep).append("\"").append(logString(new String(x.toByteArray(), UTF_8))).append("\"");
                sep = ", ";

            }
            sb.append(")");

            logger.debug(sb.toString());

        }

        ChaincodeDeploymentSpec.Builder chaincodeDeploymentSpecBuilder = ChaincodeDeploymentSpec
                .newBuilder().setChaincodeSpec(chaincodeSpec) //.setEffectiveDate(context.getFabricTimestamp())
                .setExecEnv(ChaincodeDeploymentSpec.ExecutionEnvironment.DOCKER);

        if (codePackage != null) {
            chaincodeDeploymentSpecBuilder.setCodePackage(ByteString.copyFrom(codePackage));

        }

        return chaincodeDeploymentSpecBuilder.build();

    }

    public static ByteString getSignatureHeaderAsByteString(TransactionContext transactionContext) {

        return getSignatureHeaderAsByteString(transactionContext.getUser(), transactionContext);
    }

    public static ByteString getSignatureHeaderAsByteString(User user, TransactionContext transactionContext) {

        final Identities.SerializedIdentity identity = ProtoUtils.createSerializedIdentity(user);

        if (isDebugLevel) {

            String cert = user.getEnrollment().getCert();
            // logger.debug(format(" User: %s Certificate:\n%s", user.getName(), cert));

            if (null == suite) {

                try {
                    suite = CryptoSuite.Factory.getCryptoSuite();
                } catch (Exception e) {
                    //best try.
                }

            }
            if (null != suite && suite instanceof CryptoPrimitives) {

                CryptoPrimitives cp = (CryptoPrimitives) suite;
                byte[] der = cp.certificateToDER(cert);
                if (null != der && der.length > 0) {

                    cert = toHexString(suite.hash(der));

                }

            }

            logger.debug(format("SignatureHeader: nonce: %s, User:%s, MSPID: %s, idBytes: %s",
                    toHexString(transactionContext.getNonce()),
                    user.getName(),
                    identity.getMspid(),
                    cert
            ));

        }
        return SignatureHeader.newBuilder()
                .setCreator(identity.toByteString())
                .setNonce(transactionContext.getNonce())
                .build().toByteString();
    }

    public static Identities.SerializedIdentity createSerializedIdentity(User user) {

        return Identities.SerializedIdentity.newBuilder()
                .setIdBytes(ByteString.copyFromUtf8(user.getEnrollment().getCert()))
                .setMspid(user.getMspId()).build();
    }

    public static Timestamp getCurrentFabricTimestamp() {
        Instant time = Instant.now();
        return Timestamp.newBuilder().setSeconds(time.getEpochSecond())
                .setNanos(time.getNano()).build();
    }

    public static Date getDateFromTimestamp(Timestamp timestamp) {
        return new Date(Timestamps.toMillis(timestamp));
    }

    static Timestamp getTimestampFromDate(Date date) {

        long millis = date.getTime();
        return Timestamp.newBuilder().setSeconds(millis / 1000)
                .setNanos((int) ((millis % 1000) * 1000000)).build();
    }

    public static Envelope createSeekInfoEnvelope(TransactionContext transactionContext, SeekInfo seekInfo, byte[] tlsCertHash) throws CryptoException {

        ChannelHeader seekInfoHeader = createChannelHeader(Common.HeaderType.DELIVER_SEEK_INFO,
                transactionContext.getTxID(), transactionContext.getChannelID(), transactionContext.getEpoch(),
                transactionContext.getFabricTimestamp(), null, tlsCertHash);

        SignatureHeader signatureHeader = SignatureHeader.newBuilder()
                .setCreator(transactionContext.getIdentity().toByteString())
                .setNonce(transactionContext.getNonce())
                .build();

        Common.Header seekHeader = Common.Header.newBuilder()
                .setSignatureHeader(signatureHeader.toByteString())
                .setChannelHeader(seekInfoHeader.toByteString())
                .build();

        Payload seekPayload = Payload.newBuilder()
                .setHeader(seekHeader)
                .setData(seekInfo.toByteString())
                .build();

        return Envelope.newBuilder().setSignature(transactionContext.signByteString(seekPayload.toByteArray()))
                .setPayload(seekPayload.toByteString())
                .build();

    }

    public static Envelope createSeekInfoEnvelope(TransactionContext transactionContext, SeekPosition startPosition,
                                                  SeekPosition stopPosition,
                                                  SeekBehavior seekBehavior, byte[] tlsCertHash) throws CryptoException {

        return createSeekInfoEnvelope(transactionContext, SeekInfo.newBuilder()
                .setStart(startPosition)
                .setStop(stopPosition)
                .setBehavior(seekBehavior)
                .build(), tlsCertHash);

    }
}
