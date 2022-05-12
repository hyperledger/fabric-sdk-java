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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.ChannelHeader;
import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.common.Common.Payload;
import org.hyperledger.fabric.protos.common.Common.SignatureHeader;
import org.hyperledger.fabric.protos.common.Configtx;
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
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
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

        final Identities.SerializedIdentity identity = transactionContext.getSerializedIdentity();

        if (isDebugLevel) {

            Enrollment enrollment = user.getEnrollment();
            String cert = enrollment.getCert();
            logger.debug(format(" User: %s Certificate: %s", user.getName(), cert == null ? "null" : toHexString(cert.getBytes(UTF_8))));

            if (enrollment instanceof X509Enrollment) {
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
        return Date.from(Instant.ofEpochSecond(timestamp.getSeconds(), timestamp.getNanos()));
    }

    static Timestamp getTimestampFromDate(Date date) {
<<<<<<< HEAD

        long millis = date.getTime();
        return Timestamp.newBuilder().setSeconds(millis / 1000)
                .setNanos((int) ((millis % 1000) * 1000000)).build();
=======
        Instant instant = date.toInstant();
        return Timestamp.newBuilder()
                .setSeconds(instant.getEpochSecond())
                .setNanos(instant.getNano())
                .build();
>>>>>>> 37169e3 (Address security vulnerability CVE-2022-25647 (#199))
    }

    public static Envelope createSeekInfoEnvelope(TransactionContext transactionContext, SeekInfo seekInfo, byte[] tlsCertHash) throws CryptoException, InvalidArgumentException {

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
                                                  SeekBehavior seekBehavior, byte[] tlsCertHash) throws CryptoException, InvalidArgumentException {

        return createSeekInfoEnvelope(transactionContext, SeekInfo.newBuilder()
                .setStart(startPosition)
                .setStop(stopPosition)
                .setBehavior(seekBehavior)
                .build(), tlsCertHash);

    }

    // not an api

    public static boolean computeUpdate(String channelId, Configtx.Config original, Configtx.Config update, Configtx.ConfigUpdate.Builder configUpdateBuilder) {

        Configtx.ConfigGroup.Builder readSetBuilder = Configtx.ConfigGroup.newBuilder();
        Configtx.ConfigGroup.Builder writeSetBuilder = Configtx.ConfigGroup.newBuilder();

        if (computeGroupUpdate(original.getChannelGroup(), update.getChannelGroup(), readSetBuilder, writeSetBuilder)) {
            configUpdateBuilder.setReadSet(readSetBuilder.build())
                    .setWriteSet(writeSetBuilder.build())
                    .setChannelId(channelId);

            return true;
        }

        return false;

    }

    private static boolean computeGroupUpdate(Configtx.ConfigGroup original, Configtx.ConfigGroup updated,
                                              Configtx.ConfigGroup.Builder readSetBuilder, Configtx.ConfigGroup.Builder writeSetBuilder) {

        Map<String, Configtx.ConfigPolicy> readSetPolicies = new HashMap<>();
        Map<String, Configtx.ConfigPolicy> writeSetPolicies = new HashMap<>();
        Map<String, Configtx.ConfigPolicy> sameSetPolicies = new HashMap<>();

        boolean policiesMembersUpdated = computePoliciesMapUpdate(original.getPoliciesMap(), updated.getPoliciesMap(),
                writeSetPolicies, sameSetPolicies);

        Map<String, Configtx.ConfigValue> readSetValues = new HashMap<>();
        Map<String, Configtx.ConfigValue> writeSetValues = new HashMap<>();
        Map<String, Configtx.ConfigValue> sameSetValues = new HashMap<>();

        boolean valuesMembersUpdated = computeValuesMapUpdate(original.getValuesMap(), updated.getValuesMap(),
                writeSetValues, sameSetValues);

        Map<String, Configtx.ConfigGroup> readSetGroups = new HashMap<>();
        Map<String, Configtx.ConfigGroup> writeSetGroups = new HashMap<>();
        Map<String, Configtx.ConfigGroup> sameSetGroups = new HashMap<>();

        boolean groupsMembersUpdated = computeGroupsMapUpdate(original.getGroupsMap(), updated.getGroupsMap(),
                readSetGroups, writeSetGroups, sameSetGroups);

        if (!policiesMembersUpdated && !valuesMembersUpdated && !groupsMembersUpdated && original.getModPolicy().equals(updated.getModPolicy())) {
            // nothing changed.

            if (writeSetValues.isEmpty() && writeSetPolicies.isEmpty() && writeSetGroups.isEmpty() && readSetGroups.isEmpty()) {

                readSetBuilder.setVersion(original.getVersion());
                writeSetBuilder.setVersion(original.getVersion());

                return false;
            } else {

                readSetBuilder.setVersion(original.getVersion())
                        .putAllGroups(readSetGroups);
                writeSetBuilder.setVersion(original.getVersion())
                        .putAllPolicies(writeSetPolicies)
                        .putAllValues(writeSetValues)
                        .putAllGroups(writeSetGroups);
                return true;

            }

        }

        for (Map.Entry<String, Configtx.ConfigPolicy> i : sameSetPolicies.entrySet()) {
            final String name = i.getKey();
            final Configtx.ConfigPolicy value = i.getValue();
            readSetPolicies.put(name, value);
            writeSetPolicies.put(name, value);

        }

        for (Map.Entry<String, Configtx.ConfigValue> i : sameSetValues.entrySet()) {
            final String name = i.getKey();
            final Configtx.ConfigValue value = i.getValue();
            readSetValues.put(name, value);
            writeSetValues.put(name, value);

        }

        for (Map.Entry<String, Configtx.ConfigGroup> i : sameSetGroups.entrySet()) {
            final String name = i.getKey();
            final Configtx.ConfigGroup value = i.getValue();
            readSetGroups.put(name, value);
            writeSetGroups.put(name, value);

        }

        readSetBuilder.setVersion(original.getVersion())
                .putAllPolicies(readSetPolicies)
                .putAllValues(readSetValues)
                .putAllGroups(readSetGroups);
        writeSetBuilder.setVersion(original.getVersion() + 1)
                .putAllPolicies(writeSetPolicies)
                .putAllValues(writeSetValues)
                .setModPolicy(updated.getModPolicy())
                .putAllGroups(writeSetGroups);

        return true;
    }

    public static boolean computeGroupsMapUpdate(Map<String, Configtx.ConfigGroup> original, Map<String, Configtx.ConfigGroup>
            updated, Map<String, Configtx.ConfigGroup> readSet, Map<String, Configtx.ConfigGroup> writeSet, Map<String,
            Configtx.ConfigGroup> sameSet) {
        boolean updatedMembers = false;

        for (Map.Entry<String, Configtx.ConfigGroup> i : original.entrySet()) {
            final String groupName = i.getKey();
            final Configtx.ConfigGroup originalGroup = i.getValue();

            if (!updated.containsKey(groupName) || null == updated.get(groupName)) {
                updatedMembers = true; //missing from updated ie deleted.

            } else {
                final Configtx.ConfigGroup updatedGroup = updated.get(groupName);

                Configtx.ConfigGroup.Builder readSetBuilder = Configtx.ConfigGroup.newBuilder();
                Configtx.ConfigGroup.Builder writeSetBuilder = Configtx.ConfigGroup.newBuilder();

                if (!computeGroupUpdate(originalGroup, updatedGroup, readSetBuilder, writeSetBuilder)) {
                    sameSet.put(groupName, readSetBuilder.build());

                } else {
                    readSet.put(groupName, readSetBuilder.build());
                    writeSet.put(groupName, writeSetBuilder.build());
                }

            }

        }

        for (Map.Entry<String, Configtx.ConfigGroup> i : updated.entrySet()) {
            final String groupName = i.getKey();
            final Configtx.ConfigGroup updatedConfigGroup = i.getValue();

            if (!original.containsKey(groupName) || null == original.get(groupName)) {
                updatedMembers = true;
                // final Configtx.ConfigGroup originalConfigGroup = original.get(groupName);
                Configtx.ConfigGroup.Builder readSetBuilder = Configtx.ConfigGroup.newBuilder();
                Configtx.ConfigGroup.Builder writeSetBuilder = Configtx.ConfigGroup.newBuilder();
                computeGroupUpdate(Configtx.ConfigGroup.newBuilder().build(), updatedConfigGroup, readSetBuilder, writeSetBuilder);
                writeSet.put(groupName, Configtx.ConfigGroup.newBuilder()
                        .setVersion(0)
                        .setModPolicy(updatedConfigGroup.getModPolicy())
                        .putAllPolicies(writeSetBuilder.getPoliciesMap())
                        .putAllValues(writeSetBuilder.getValuesMap())
                        .putAllGroups(writeSetBuilder.getGroupsMap())
                        .build()

                );

            }

        }

        return updatedMembers;
    }

    private static boolean computeValuesMapUpdate(Map<String, Configtx.ConfigValue> original, Map<String, Configtx.ConfigValue> updated,
                                                  Map<String, Configtx.ConfigValue> writeSet, Map<String, Configtx.ConfigValue> sameSet) {

        boolean updatedMembers = false;

        for (Map.Entry<String, Configtx.ConfigValue> i : original.entrySet()) {
            final String valueName = i.getKey();
            final Configtx.ConfigValue originalValue = i.getValue();
            if (!updated.containsKey(valueName) || null == updated.get(valueName)) {
                updatedMembers = true; //missing from updated ie deleted.

            } else { // is in both...

                final Configtx.ConfigValue updatedValue = updated.get(valueName);
                if (originalValue.getModPolicy().equals(updatedValue.getModPolicy()) &&
                        originalValue.getValue().equals(updatedValue.getValue())) { //same value

                    sameSet.put(valueName, Configtx.ConfigValue.newBuilder().setVersion(originalValue.getVersion()).build());

                } else { // new value put in writeset.

                    writeSet.put(valueName, Configtx.ConfigValue.newBuilder()
                            .setVersion(originalValue.getVersion() + 1)
                            .setModPolicy(updatedValue.getModPolicy())
                            .setValue(updatedValue.getValue())
                            .build());

                }

            }

        }

        for (Map.Entry<String, Configtx.ConfigValue> i : updated.entrySet()) {
            final String valueName = i.getKey();
            final Configtx.ConfigValue updatedValue = i.getValue();

            if (!original.containsKey(valueName) || null == original.get(valueName)) {

                updatedMembers = true;

                writeSet.put(valueName, Configtx.ConfigValue.newBuilder()
                        .setVersion(0)
                        .setModPolicy(updatedValue.getModPolicy())
                        .setValue(updatedValue.getValue())
                        .build());

            }
        }

        return updatedMembers;

    }

    private static boolean computePoliciesMapUpdate(Map<String, Configtx.ConfigPolicy> original, Map<String, Configtx.ConfigPolicy> updated,
                                                    Map<String, Configtx.ConfigPolicy> writeSet, Map<String, Configtx.ConfigPolicy> sameSet) {

        boolean updatedMembers = false;

        for (Map.Entry<String, Configtx.ConfigPolicy> i : original.entrySet()) {
            final String policyName = i.getKey();
            final Configtx.ConfigPolicy originalPolicy = i.getValue();
            if (!updated.containsKey(policyName) || null == updated.get(policyName)) {
                updatedMembers = true; //missing from updated ie deleted.

            } else { // is in both...

                final Configtx.ConfigPolicy updatedPolicy = updated.get(policyName);
                if (originalPolicy.getModPolicy().equals(updatedPolicy.getModPolicy()) &&
                        originalPolicy.toByteString().equals(updatedPolicy.toByteString())) { //same policy

                    sameSet.put(policyName, Configtx.ConfigPolicy.newBuilder().setVersion(originalPolicy.getVersion()).build());

                } else { // new policy put in writeset.

                    writeSet.put(policyName, Configtx.ConfigPolicy.newBuilder()
                            .setVersion(originalPolicy.getVersion() + 1)
                            .setModPolicy(updatedPolicy.getModPolicy())
                            .setPolicy(updatedPolicy.getPolicy().newBuilderForType().build())
                            .build());

                }

            }

        }

        for (Map.Entry<String, Configtx.ConfigPolicy> i : updated.entrySet()) {
            final String policyName = i.getKey();
            final Configtx.ConfigPolicy updatedPolicy = i.getValue();

            if (!original.containsKey(policyName) || null == original.get(policyName)) {

                updatedMembers = true;

                writeSet.put(policyName, Configtx.ConfigPolicy.newBuilder()
                        .setVersion(0)
                        .setModPolicy(updatedPolicy.getModPolicy())
                        .setPolicy(updatedPolicy.getPolicy().newBuilderForType().build())
                        .build());

            }
        }

        return updatedMembers;
    }

//     Keep for now as this can be handy in the future....
//    static void printConfigGroup(Configtx.Config configGroup) throws InvalidProtocolBufferException {
//        //     final JsonFormat.Parser parser = JsonFormat.parser();
//        final JsonFormat.Printer printer = JsonFormat.printer();
//        // Read the input stream and convert to JSON
//
//        JsonReader reader = Json.createReader(new StringReader(printer.print(configGroup)));
//        JsonObject jsonConfig = (JsonObject) reader.read();
//
//        //channelGroup
//        //   final Object read = JsonPath.parse(jsonConfig).read("$", Criteria.where("value").exists(true));
//        // final Object read = JsonPath.parse(jsonConfig).read("$.channelGroup[?(@.value)]");
//        //  final Object read = JsonPath.parse(jsonConfig).read("$.channelGroup..value");
//        // worked got strings  final Object read = JsonPath.parse(jsonConfig).read("$.channelGroup..value");
//        // final Object read = JsonPath.parse(jsonConfig).read("$.channelGroup..[?(@[?(@.value)])]");
//        final net.minidev.json.JSONArray read = JsonPath.parse(jsonConfig).read("$.channelGroup..[?(@.value)]");
//        final Object next = read.iterator().next();
//        out(read + "");
//
//        // out(printer.print(json));
//
//    }






































}
