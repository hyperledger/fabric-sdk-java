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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeDeploymentSpec;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeSpec.Type;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createDeploymentSpec;


public class InstallProposalBuilder extends LCCCProposalBuilder {


    private final static Log logger = LogFactory.getLog(InstallProposalBuilder.class);

    private String chaincodePath;


    private File chaincodeSource;
    private String chaincodeName;
    private String chaincodeVersion;
    private TransactionRequest.Type chaincodeLanguage;
    protected String action = "install";


    protected InstallProposalBuilder() {
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


    public InstallProposalBuilder setChaincodeSource(File chaincodeSource) {
        this.chaincodeSource = chaincodeSource;

        return this;
    }

    @Override
    public FabricProposal.Proposal build() throws ProposalException {

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
            throw new IllegalArgumentException("Missing chaincodePath in InstallRequest");
        }
        if (null == chaincodeSource) {
            throw new IllegalArgumentException("Missing chaincodeSource in InstallRequest");
        }


        final Type ccType;
        final File projectSourceDir;
        final String targetPathPrefix;
        String dplang;

        switch (chaincodeLanguage) {
            case GO_LANG:
                dplang = "Go";
                ccType = Type.GOLANG;
                projectSourceDir = Paths.get(chaincodeSource.toString(), "src", chaincodePath).toFile();
                targetPathPrefix = Paths.get("src", chaincodePath).toString();
                break;

            case JAVA:
                dplang = "Java";
                ccType = Type.JAVA;
                targetPathPrefix = "src";
                projectSourceDir = Paths.get(chaincodeSource.toString(), chaincodePath).toFile();
                break;

            default:
                throw new IllegalArgumentException("Unexpected chaincode language: " + chaincodeLanguage);
        }

        if (!projectSourceDir.exists()) {
            final String message = "The project source directory does not exist: " + projectSourceDir.getAbsolutePath();
            logger.error(message);
            throw new IllegalArgumentException(message);
        }
        if (!projectSourceDir.isDirectory()) {
            final String message = "The project source directory is not a directory: " + projectSourceDir.getAbsolutePath();
            logger.error(message);
            throw new IllegalArgumentException(message);
        }

        String chaincodeID = chaincodeName + "::" + chaincodePath + "::" + chaincodeVersion;

        logger.info(format("Installing '%s'  %s chaincode from directory: '%s' with source location: '%s'. chaincodePath:'%s'",
                chaincodeID, dplang, projectSourceDir.getAbsolutePath(), targetPathPrefix, chaincodePath));

        // generate chain code source tar
        final byte[] data = SDKUtil.generateTarGz(projectSourceDir, targetPathPrefix);

        final ChaincodeDeploymentSpec depspec = createDeploymentSpec(
                ccType, this.chaincodeName, this.chaincodePath, this.chaincodeVersion, null, data);

        // set args
        final List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom(action, StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());
        args(argList);

    }


    private void createDevModeTransaction() {
        logger.debug("newDevModeTransaction");


        ChaincodeDeploymentSpec depspec = createDeploymentSpec(Type.GOLANG,
                chaincodeName, null, null, null, null);

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom("install", StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());


        args(argList);

    }

    public void setChaincodeLanguage(TransactionRequest.Type chaincodeLanguage) {
        this.chaincodeLanguage = chaincodeLanguage;
    }


    public void chaincodeVersion(String chaincodeVersion) {
        this.chaincodeVersion = chaincodeVersion;
    }
}