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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common.ChannelHeader;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.common.Common.SignatureHeader;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInput;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec.Type;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeHeaderExtension;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.helper.Utils.logString;
import static org.hyperledger.fabric.sdk.helper.Utils.toHexString;

public final class ProtoUtils {

    private static final Log logger = LogFactory.getLog(ProtoUtils.class);
    private static final boolean isDebugLevel = logger.isDebugEnabled();

    /**
     * createChannelHeader create chainHeader
     *
     * @param type                     header type. See {@link ChannelHeader.Builder#setType}.
     * @param txID                     transaction ID. See {@link ChannelHeader.Builder#setTxId}.
     * @param channelID                channel ID. See {@link ChannelHeader.Builder#setChannelId}.
     * @param epoch                    the epoch in which this header was generated. See {@link ChannelHeader.Builder#setEpoch}.
     * @param timeStamp                local time when the message was created. See {@link ChannelHeader.Builder#setTimestamp}.
     * @param chaincodeHeaderExtension extension to attach dependent on the header type. See {@link ChannelHeader.Builder#setExtension}.
     * @return a new chain header.
     */
    public static ChannelHeader createChannelHeader(HeaderType type, String txID, String channelID, long epoch, Timestamp timeStamp, ChaincodeHeaderExtension chaincodeHeaderExtension) {

        if (isDebugLevel) {
            logger.debug(format("ChannelHeader: type: %s, version: 1, Txid: %s, channelId: %s, epoch %d",
                    type.name(), txID, channelID, epoch));

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


    // static CryptoSuite suite = null;

    public static ByteString getSignatureHeaderAsByteString(TransactionContext transactionContext) {

        return getSignatureHeaderAsByteString(transactionContext.getUser(), transactionContext);
    }

    public static CryptoSuite suite;

    public static ByteString getSignatureHeaderAsByteString(User user, TransactionContext transactionContext) {

        final Identities.SerializedIdentity identity = ProtoUtils.createSerializedIdentity(user);

        if (isDebugLevel) {

            String cert = user.getEnrollment().getCert();
            // logger.debug(format(" User: %s Certificate:\n%s", user.getName(), cert));

            if (null == suite) {

                try {
                    suite = CryptoSuite.Factory.getCryptoSuite();
                    suite.init();
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

        final long millis = System.currentTimeMillis();

        return Timestamp.newBuilder().setSeconds(millis / 1000)
                .setNanos((int) ((millis % 1000) * 1000000)).build();

    }

    public static Date getDateFromTimestamp(Timestamp timestamp) {

        return new Date(Timestamps.toMillis(timestamp));

    }

    /**
     * Private constructor to prevent instantiation.
     */
    private ProtoUtils() {
    }

}
