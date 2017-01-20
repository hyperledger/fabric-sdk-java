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

import com.google.common.io.Files;
import com.google.protobuf.ByteString;
import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;


public class DeploymentProposalBuilder extends ProposalBuilder {


    private Log logger = LogFactory.getLog(DeploymentProposalBuilder.class);
    private String chaincodePath;
    private String chaincodeName;
    private List<String> argList;
    private TransactionRequest.Type chaincodeLanguage;

    private DeploymentProposalBuilder() {
        super();
    }

    public static DeploymentProposalBuilder newBuilder() {
        return new DeploymentProposalBuilder();


    }


    public DeploymentProposalBuilder chaincodePath(String chaincodePath) {

        this.chaincodePath = chaincodePath;

        return this;

    }

    public DeploymentProposalBuilder chaincodeName(String chaincodeName) {

        this.chaincodeName = chaincodeName;

        return this;

    }

    public DeploymentProposalBuilder argss(List<String> argList) {
        this.argList = argList;
        return this;
    }

    @Override
    public FabricProposal.Proposal build() throws Exception {

        constructDeploymentProposal();
        return super.build();
    }

    private static String LCCC_CHAIN_NAME = "lccc";


    public void constructDeploymentProposal() {


        try {

            if (context.isDevMode()) {
                createDevModeTransaction();
            } else {
                createNetModeTransaction();
            }

        } catch (Exception exp) {
            logger.error(exp);
            throw new DeploymentException("IO Error while creating deploy transaction", exp);
        }
    }

    private void createNetModeTransaction() throws Exception {
        logger.debug("newNetModeTransaction");

        // Verify that chaincodePath is being passed
        if (StringUtil.isNullOrEmpty(chaincodePath)) {
            throw new IllegalArgumentException("[NetMode] Missing chaincodePath in DeployRequest");
        }

        String rootDir = "";
        String chaincodeDir = "";

        Chaincode.ChaincodeSpec.Type ccType = Chaincode.ChaincodeSpec.Type.GOLANG;

        if (chaincodeLanguage == TransactionRequest.Type.GO_LANG) {
            // Determine the user's $GOPATH
            String goPath = System.getenv("GOPATH");
            logger.info(String.format("Using GOPATH :%s", goPath));
            if (StringUtil.isNullOrEmpty(goPath)) {
                throw new IllegalArgumentException("[NetMode] Missing GOPATH environment variable");
            }

            logger.debug("$GOPATH: " + goPath);

            // Compose the path to the chaincode project directory
            rootDir = SDKUtil.combinePaths(goPath, "src");
            chaincodeDir = chaincodePath;

        } else {
            ccType = Chaincode.ChaincodeSpec.Type.JAVA;

            // Compose the path to the chaincode project directory
            File ccFile = new File(chaincodePath);
            rootDir = ccFile.getParent();
            chaincodeDir = ccFile.getName();
        }

        String projDir = SDKUtil.combinePaths(rootDir, chaincodeDir);
        logger.debug("projDir: " + projDir);

        String dockerFileContents = getDockerFileContents(chaincodeLanguage);

        // NO longer using hash .. keep same as Node SDK.
        // Compute the hash of the chaincode deployment parameters
        //    String hash = SDKUtil.generateParameterHash(chaincodeDir, request.getFcn(), request.getArgs());

        // Compute the hash of the project directory contents
//        hash = SDKUtil.generateDirectoryHash(rootDir, chaincodeDir, hash);
//        logger.debug("hash: " + hash);

        // Substitute the hashStrHash for the image name
        dockerFileContents = String.format(dockerFileContents, chaincodeName);

        // Create a Docker file with dockerFileContents
        String dockerFilePath = SDKUtil.combinePaths(projDir, "Dockerfile");
        Files.write(dockerFileContents.getBytes(), new java.io.File(dockerFilePath));

        logger.debug(String.format("Created Dockerfile at [%s]", dockerFilePath));

        // Create the .tar.gz file of the chaincode package
        String targzFilePath = SDKUtil.combinePaths(System.getProperty("java.io.tmpdir"), "deployment-package.tar.gz");
        // Create the compressed archive
        SDKUtil.generateTarGz(projDir, targzFilePath);
        byte[] data = SDKUtil.readFile(new File(targzFilePath));

        // Clean up temporary files
        SDKUtil.deleteFileOrDirectory(new File(targzFilePath));
        SDKUtil.deleteFileOrDirectory(new File(dockerFilePath));


        Chaincode.ChaincodeDeploymentSpec depspec = createDeploymentSpec(ccType,
                chaincodeName, argList, data, null);


        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom("deploy", StandardCharsets.UTF_8));
        argList.add(ByteString.copyFrom("default", StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());

        Chaincode.ChaincodeID lcccID = Chaincode.ChaincodeID.newBuilder().setName(LCCC_CHAIN_NAME).build();

        super.args(argList);
        super.chaincodeID(lcccID);
        super.ccType(ccType);

    }


    private void createDevModeTransaction() {
        logger.debug("newDevModeTransaction");


        Chaincode.ChaincodeDeploymentSpec depspec = createDeploymentSpec(Chaincode.ChaincodeSpec.Type.GOLANG,
                chaincodeName, argList, null, null);

        Chaincode.ChaincodeID lcccID = Chaincode.ChaincodeID.newBuilder().setName(LCCC_CHAIN_NAME).build();

        List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom("deploy", StandardCharsets.UTF_8));
        argList.add(ByteString.copyFrom("default", StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());


        super.args(argList);
        super.chaincodeID(lcccID);


    }


    private Chaincode.ChaincodeDeploymentSpec createDeploymentSpec(Chaincode.ChaincodeSpec.Type ccType,
                                                                   String name,
                                                                   List<String> args,
                                                                   byte[] codePackage,
                                                                   String chaincodePath) {
        logger.trace("Creating deployment Specification.");

        Chaincode.ChaincodeID.Builder chaincodeIDBuilder = Chaincode.ChaincodeID.newBuilder().setName(name);
        if (chaincodePath != null) {
            chaincodeIDBuilder = chaincodeIDBuilder.setPath(chaincodePath);
        }

        Chaincode.ChaincodeID chaincodeID = chaincodeIDBuilder.build();

        // build chaincodeInput
        List<ByteString> argList = new ArrayList<>(args.size());
        argList.add(ByteString.copyFrom("init", StandardCharsets.UTF_8));
        for (String arg : args) {
            argList.add(ByteString.copyFrom(arg.getBytes()));
        }
        Chaincode.ChaincodeInput chaincodeInput = Chaincode.ChaincodeInput.newBuilder().addAllArgs(argList).build();

        // Construct the ChaincodeSpec
        Chaincode.ChaincodeSpec chaincodeSpec = Chaincode.ChaincodeSpec.newBuilder().setType(ccType).setChaincodeID(chaincodeID)
                .setInput(chaincodeInput)
                .build();


        Chaincode.ChaincodeDeploymentSpec.Builder chaincodeDeploymentSpecBuilder = Chaincode.ChaincodeDeploymentSpec
                .newBuilder().setChaincodeSpec(chaincodeSpec).setEffectiveDate(context.getFabricTimestamp())
                .setExecEnv(Chaincode.ChaincodeDeploymentSpec.ExecutionEnvironment.DOCKER);
        chaincodeDeploymentSpecBuilder.setCodePackage(ByteString.copyFrom(codePackage));

        return chaincodeDeploymentSpecBuilder.build();

    }


    private String getDockerFileContents(TransactionRequest.Type lang) throws IOException {
        if (chaincodeLanguage == TransactionRequest.Type.GO_LANG) {
            return new String(SDKUtil.readFileFromClasspath("Go.Docker"));
        } else if (chaincodeLanguage == TransactionRequest.Type.JAVA) {
            return new String(SDKUtil.readFileFromClasspath("Java.Docker"));
        }

        throw new UnsupportedOperationException(String.format("Unknown chaincode language: %s", lang));
    }


    public void setChaincodeLanguage(TransactionRequest.Type chaincodeLanguage) {
        this.chaincodeLanguage = chaincodeLanguage;
    }
}