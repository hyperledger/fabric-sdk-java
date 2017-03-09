/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createDeploymentSpec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec.Type;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;

import com.google.protobuf.ByteString;

import io.netty.util.internal.StringUtil;


public class InstallProposalBuilder extends ProposalBuilder {


    private final static Log logger = LogFactory.getLog(InstallProposalBuilder.class);
    private static final ChaincodeID LIFECYCLE_CHAINCODE_ID = ChaincodeID.newBuilder().setName("lccc").build();
    private String chaincodePath;


    private String chaincodeSource;
    private String chaincodeName;
    private String chaincodeVersion;
    private TransactionRequest.Type chaincodeLanguage;


    private InstallProposalBuilder() {
        super();
    }

    public static InstallProposalBuilder newBuilder() {
        return new InstallProposalBuilder();


    }


    public InstallProposalBuilder chaincodePath(String chaincodePath) {

        this.chaincodePath = chaincodePath;

        return this;

    }

    public InstallProposalBuilder chaincodeName(String chaincodeName) {

        this.chaincodeName = chaincodeName;

        return this;

    }


    public InstallProposalBuilder setChaincodeSource(String chaincodeSource) {
        this.chaincodeSource = chaincodeSource;

        return this;
    }

    @Override
    public FabricProposal.Proposal build() throws Exception {

        constructInstallProposal();
        return super.build();
    }


    private void constructInstallProposal() throws ProposalException {


        try {

            if (context.isDevMode()) {
                createDevModeTransaction();
            } else {
                createNetModeTransaction();
            }

        } catch (Exception exp) {
            logger.error(exp);
            throw new ProposalException("IO Error while creating install proposal", exp);
        }
    }

    private void createNetModeTransaction() throws Exception {
        logger.debug("newNetModeTransaction");

        // Verify that chaincodePath is being passed
        if (StringUtil.isNullOrEmpty(chaincodePath)) {
            throw new IllegalArgumentException("[NetMode] Missing chaincodePath in DeployRequest");
        }

        final Type ccType;
        final Path projectSourceDir;
        final String targetPathPrefix;

        switch (chaincodeLanguage) {
        case GO_LANG:
            ccType = Type.GOLANG;
            if (chaincodeSource == null) {
                chaincodeSource = System.getenv("GOPATH");
                logger.info(String.format("Using GOPATH :%s", chaincodeSource));
            }
            if (StringUtil.isNullOrEmpty(chaincodeSource)) {
        	logger.error("[NetMode] Neither the golang chaincodeSource directory or the GOPATH environment variable set.");
                throw new IllegalArgumentException("[NetMode] Neither the golang chaincodeSource directory or the GOPATH environment variable set.");
            }
            logger.info(String.format("Looking for Golang chaincode in %s", chaincodeSource));
            projectSourceDir = Paths.get(chaincodeSource, "src", chaincodePath);
            targetPathPrefix = SDKUtil.combinePaths("src", chaincodePath);
            break;
        case JAVA:
            ccType = Type.JAVA;
            targetPathPrefix = "src";
            if(StringUtil.isNullOrEmpty(chaincodeSource)) {
                chaincodeSource = Paths.get("").toAbsolutePath().toString();
            }
            logger.info(String.format("Looking for Java chaincode in %s", chaincodeSource));
            projectSourceDir = Paths.get(chaincodeSource, chaincodePath);
        default:
            throw new IllegalArgumentException("Unexpected chaincode language: " + chaincodeLanguage);
        }

        if(!projectSourceDir.toFile().exists()) {
            final String message = "The project source directory does not exist: " + projectSourceDir.toAbsolutePath();
            logger.error(message);
            throw new IllegalArgumentException(message);
        }
        if(!projectSourceDir.toFile().isDirectory()) {
            final String message = "The project source directory is not a directory: " + projectSourceDir.toAbsolutePath();
            logger.error(message);
            throw new IllegalArgumentException(message);
        }
        logger.debug("Project source directory: " + projectSourceDir.toAbsolutePath());

        // generate chain code source tar
        final byte[] data = SDKUtil.generateTarGz(projectSourceDir, targetPathPrefix);
        
        final ChaincodeDeploymentSpec depspec = createDeploymentSpec(
        	ccType, this.chaincodeName, this.chaincodePath, this.chaincodeVersion, null, data);

        // set args
        final List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom("install", StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());
        args(argList);

        chaincodeID(LIFECYCLE_CHAINCODE_ID);
        ccType(ccType);
        chainID(""); //Installing chaincode is not targeted to a chain.

    }


    private void createDevModeTransaction() {
        logger.debug("newDevModeTransaction");


        ChaincodeDeploymentSpec depspec = createDeploymentSpec(Type.GOLANG,
                chaincodeName, null, null, null, null);

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom("install", StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());


        args(argList);
        chaincodeID(LIFECYCLE_CHAINCODE_ID);
    }

    public void setChaincodeLanguage(TransactionRequest.Type chaincodeLanguage) {
        this.chaincodeLanguage = chaincodeLanguage;
    }


    public void chaincodeVersion(String chaincodeVersion) {
        this.chaincodeVersion = chaincodeVersion;
    }
}