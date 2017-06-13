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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.google.protobuf.ByteString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.HeaderType;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInput;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeInvocationSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeHeaderExtension;
import org.hyperledger.fabric.protos.peer.FabricProposal.ChaincodeProposalPayload;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.ProposalException;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.helper.Utils.logString;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createChannelHeader;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getSignatureHeaderAsByteString;

public class ProposalBuilder {

    private static final Log logger = LogFactory.getLog(ProposalBuilder.class);
    private static final boolean IS_DEBUG_LEVEL = logger.isDebugEnabled();

    private Chaincode.ChaincodeID chaincodeID;
    private List<ByteString> argList;
    protected TransactionContext context;
    protected TransactionRequest request;
    protected ChaincodeSpec.Type ccType = ChaincodeSpec.Type.GOLANG;
    protected Map<String, byte[]> transientMap = null;

    // The channel that is being targeted . note blank string means no specific channel
    private String channelID;

    protected ProposalBuilder() {
    }

    public static ProposalBuilder newBuilder() {
        return new ProposalBuilder();
    }

    public ProposalBuilder chaincodeID(Chaincode.ChaincodeID chaincodeID) {
        this.chaincodeID = chaincodeID;
        return this;
    }

    public ProposalBuilder args(List<ByteString> argList) {
        this.argList = argList;
        return this;
    }

    public ProposalBuilder context(TransactionContext context) {
        this.context = context;
        if (null == channelID) {
            channelID = context.getChannel().getName(); //Default to context channel.
        }
        return this;
    }

    public ProposalBuilder request(TransactionRequest request) {
        this.request = request;

        chaincodeID(request.getChaincodeID().getFabricChaincodeID());
        ccType(request.getChaincodeLanguage() == TransactionRequest.Type.JAVA ?
                Chaincode.ChaincodeSpec.Type.JAVA : Chaincode.ChaincodeSpec.Type.GOLANG);

        transientMap = request.getTransientMap();

        return this;
    }

    public FabricProposal.Proposal build() throws ProposalException {
        if (request != null && request.noChannelID()) {
            channelID = "";
        }
        return createFabricProposal(channelID, chaincodeID);
    }

    private FabricProposal.Proposal createFabricProposal(String channelID, Chaincode.ChaincodeID chaincodeID) {
        if (null == transientMap) {
            transientMap = Collections.emptyMap();
        }

        if (IS_DEBUG_LEVEL) {
            for (Entry<String, byte[]> tme : transientMap.entrySet()) {
                logger.debug(format("transientMap('%s', '%s'))", logString(tme.getKey()),
                        logString(new String(tme.getValue(), UTF_8))));
            }
        }
        ChaincodeHeaderExtension chaincodeHeaderExtension = ChaincodeHeaderExtension.newBuilder()
                .setChaincodeId(chaincodeID).build();

        Common.ChannelHeader chainHeader = createChannelHeader(HeaderType.ENDORSER_TRANSACTION,
                context.getTxID(), channelID, context.getEpoch(), context.getFabricTimestamp(), chaincodeHeaderExtension);

        ChaincodeInvocationSpec chaincodeInvocationSpec = createChaincodeInvocationSpec(
                chaincodeID,
                ccType);

        //Convert to bytestring map.
        Map<String, ByteString> bsm = new HashMap<>(transientMap.size());

        for (Entry<String, byte[]> tme : transientMap.entrySet()) {
            bsm.put(tme.getKey(), ByteString.copyFrom(tme.getValue()));

        }

        ChaincodeProposalPayload payload = ChaincodeProposalPayload.newBuilder()
                .setInput(chaincodeInvocationSpec.toByteString())
                .putAllTransientMap(bsm)
                .build();

        Common.Header header = Common.Header.newBuilder()
                .setSignatureHeader(getSignatureHeaderAsByteString(context))
                .setChannelHeader(chainHeader.toByteString())
                .build();

        return FabricProposal.Proposal.newBuilder()
                .setHeader(header.toByteString())
                .setPayload(payload.toByteString())
                .build();

    }

    private ChaincodeInvocationSpec createChaincodeInvocationSpec(Chaincode.ChaincodeID chaincodeID, ChaincodeSpec.Type langType) {

        List<ByteString> allArgs = new ArrayList<>();

        if (argList != null && argList.size() > 0) {
            // If we already have an argList then the Builder subclasses have already set the arguments
            // for chaincodeInput. Accept the list and pass it on to the chaincodeInput builder
            // TODO need to clean this logic up so that common protobuf struct builds are in one place
            allArgs = argList;
        } else if (request != null) {
            // if argList is empty and we have a Request, build the chaincodeInput args array from the Request args and argbytes lists
            allArgs.add(ByteString.copyFrom(request.getFcn(), UTF_8));
            List<String> args = request.getArgs();
            if (args != null && args.size() > 0) {
                for (String arg : args) {
                    allArgs.add(ByteString.copyFrom(arg.getBytes(UTF_8)));
                }
            }
            // TODO currently assume that chaincodeInput args are strings followed by byte[].
            // Either agree with Fabric folks that this will always be the case or modify all Builders to expect
            // a List of Objects and determine if each list item is a string or a byte array
            List<byte[]> argBytes = request.getArgBytes();
            if (argBytes != null && argBytes.size() > 0) {
                for (byte[] arg : argBytes) {
                    allArgs.add(ByteString.copyFrom(arg));
                }
            }

        }
        if (IS_DEBUG_LEVEL) {

            StringBuilder logout = new StringBuilder(1000);

            logout.append(format("ChaincodeInvocationSpec type: %s, chaincode name: %s, chaincode path: %s, chaincode version: %s",
                    langType.name(), chaincodeID.getName(), chaincodeID.getPath(), chaincodeID.getVersion()));

            String sep = "";
            logout.append(" args(");

            for (ByteString x : allArgs) {
                logout.append(sep).append("\"").append(logString(new String(x.toByteArray(), UTF_8))).append("\"");
                sep = ", ";

            }
            logout.append(")");

            logger.debug(logout.toString());

        }

        ChaincodeInput chaincodeInput = ChaincodeInput.newBuilder().addAllArgs(allArgs).build();

        ChaincodeSpec chaincodeSpec = ChaincodeSpec.newBuilder()
                .setType(langType)
                .setChaincodeId(chaincodeID)
                .setInput(chaincodeInput)
                .build();

        return ChaincodeInvocationSpec.newBuilder()
                .setChaincodeSpec(chaincodeSpec).build();

    }

    public ProposalBuilder ccType(ChaincodeSpec.Type ccType) {
        this.ccType = ccType;
        return this;
    }

}