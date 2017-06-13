/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.google.protobuf.ByteString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.sdk.ChaincodeEndorsementPolicy;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;

import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createDeploymentSpec;

public class InstantiateProposalBuilder extends LSCCProposalBuilder {

    private static final Log logger = LogFactory.getLog(InstantiateProposalBuilder.class);

    private String chaincodePath;

    private String chaincodeName;
    private List<String> argList;
    private String chaincodeVersion;

    private byte[] chaincodePolicy = null;
    protected String action = "deploy";

    public void setTransientMap(Map<String, byte[]> transientMap) throws InvalidArgumentException {
        if (null == transientMap) {

            throw new InvalidArgumentException("Transient map may not be null");

        }
        this.transientMap = transientMap;
    }

    protected InstantiateProposalBuilder() {
        super();
    }

    public static InstantiateProposalBuilder newBuilder() {
        return new InstantiateProposalBuilder();

    }

    public InstantiateProposalBuilder chaincodePath(String chaincodePath) {

        this.chaincodePath = chaincodePath;

        return this;

    }

    public InstantiateProposalBuilder chaincodeName(String chaincodeName) {

        this.chaincodeName = chaincodeName;

        return this;

    }

    public void chaincodEndorsementPolicy(ChaincodeEndorsementPolicy policy) {
        if (policy != null) {
            this.chaincodePolicy = policy.getChaincodeEndorsementPolicyAsBytes();
        }
    }

    public InstantiateProposalBuilder argss(List<String> argList) {
        this.argList = argList;
        return this;
    }

    @Override
    public FabricProposal.Proposal build() throws ProposalException {

        constructInstantiateProposal();
        return super.build();
    }

    private void constructInstantiateProposal() throws ProposalException {

        try {

            createNetModeTransaction();

        } catch (Exception exp) {
            logger.error(exp);
            throw new ProposalException("IO Error while creating install transaction", exp);
        }
    }

    private void createNetModeTransaction() {
        logger.debug("NetModeTransaction");

        List<String> modlist = new LinkedList<>();
        modlist.add("init");
        modlist.addAll(argList);

        ChaincodeDeploymentSpec depspec = createDeploymentSpec(ccType,
                chaincodeName, chaincodePath, chaincodeVersion, modlist, null);

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom(action, StandardCharsets.UTF_8));
        argList.add(ByteString.copyFrom(context.getChannelID(), StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());
        if (chaincodePolicy != null) {
            argList.add(ByteString.copyFrom(chaincodePolicy));
        }

        args(argList);

    }

    public void chaincodeVersion(String chaincodeVersion) {
        this.chaincodeVersion = chaincodeVersion;
    }
}