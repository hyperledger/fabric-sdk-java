/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;
import org.hyperledger.fabric.sdk.helper.Utils;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.createDeploymentSpec;

public class InstallProposalBuilder extends LSCCProposalBuilder {

    private static final Log logger = LogFactory.getLog(InstallProposalBuilder.class);
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final Config config = Config.getConfig();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;

    private String chaincodePath;

    private File chaincodeSource;
    private String chaincodeName;
    private String chaincodeVersion;
    private TransactionRequest.Type chaincodeLanguage;
    protected String action = "install";
    private InputStream chaincodeInputStream;
    private File chaincodeMetaInfLocation;

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

    public InstallProposalBuilder setChaincodeMetaInfLocation(File chaincodeMetaInfLocation) {

        this.chaincodeMetaInfLocation = chaincodeMetaInfLocation;
        return this;
    }

    @Override
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {

        constructInstallProposal();
        return super.build();
    }

    private void constructInstallProposal() throws ProposalException {

        try {

            createNetModeTransaction();

        } catch (IOException exp) {
            logger.error(exp);
            throw new ProposalException("IO Error while creating install proposal", exp);
        }
    }

    private void createNetModeTransaction() throws IOException {
        logger.debug("createNetModeTransaction");

        if (null == chaincodeSource && chaincodeInputStream == null) {
            throw new IllegalArgumentException("Missing chaincodeSource or chaincodeInputStream in InstallRequest");
        }

        if (null != chaincodeSource && chaincodeInputStream != null) {
            throw new IllegalArgumentException("Both chaincodeSource and chaincodeInputStream in InstallRequest were set. Specify one or the other");
        }

        final Chaincode.ChaincodeSpec.Type ccType;
        File projectSourceDir = null;
        String targetPathPrefix = null;
        String dplang;

        File metainf = null;
        if (null != chaincodeMetaInfLocation) {
            if (!chaincodeMetaInfLocation.exists()) {
                throw new IllegalArgumentException(format("Directory to find chaincode META-INF %s does not exist", chaincodeMetaInfLocation.getAbsolutePath()));
            }

            if (!chaincodeMetaInfLocation.isDirectory()) {
                throw new IllegalArgumentException(format("Directory to find chaincode META-INF %s is not a directory", chaincodeMetaInfLocation.getAbsolutePath()));
            }
            metainf = new File(chaincodeMetaInfLocation, "META-INF");
            logger.trace("META-INF directory is " + metainf.getAbsolutePath());
            if (!metainf.exists()) {

                throw new IllegalArgumentException(format("The META-INF directory does not exist in %s", chaincodeMetaInfLocation.getAbsolutePath()));
            }

            if (!metainf.isDirectory()) {
                throw new IllegalArgumentException(format("The META-INF in %s is not a directory.", chaincodeMetaInfLocation.getAbsolutePath()));
            }
            File[] files = metainf.listFiles();

            if (files == null) {
                throw new IllegalArgumentException("null for listFiles on: " + chaincodeMetaInfLocation.getAbsolutePath());
            }

            if (files.length < 1) {

                throw new IllegalArgumentException(format("The META-INF directory %s is empty.", metainf.getAbsolutePath()));
            }

            logger.trace(format("chaincode META-INF found %s", metainf.getAbsolutePath()));

        }

        switch (chaincodeLanguage) {
            case GO_LANG:

                // chaincodePath is mandatory
                // chaincodeSource may be a File or InputStream

                //   Verify that chaincodePath is being passed
                if (Utils.isNullOrEmpty(chaincodePath)) {
                    throw new IllegalArgumentException("Missing chaincodePath in InstallRequest");
                }

                dplang = "Go";
                ccType = Chaincode.ChaincodeSpec.Type.GOLANG;
                if (null != chaincodeSource) {

                    projectSourceDir = Paths.get(chaincodeSource.toString(), "src", chaincodePath).toFile();
                    targetPathPrefix = Paths.get("src", chaincodePath).toString();
                }
                break;

            case JAVA:

                // chaincodePath is not applicable and must be null
                // chaincodeSource may be a File or InputStream

                //   Verify that chaincodePath is null
                if (!Utils.isNullOrEmpty(chaincodePath)) {
                    throw new IllegalArgumentException("chaincodePath must be null for Java chaincode");
                }

                dplang = "Java";
                ccType = Chaincode.ChaincodeSpec.Type.JAVA;
                if (null != chaincodeSource) {
                    targetPathPrefix = "src";
                    projectSourceDir = Paths.get(chaincodeSource.toString()).toFile();
                }
                break;

            case NODE:

                // chaincodePath is not applicable and must be null
                // chaincodeSource may be a File or InputStream

                //   Verify that chaincodePath is null
                if (!Utils.isNullOrEmpty(chaincodePath)) {
                    throw new IllegalArgumentException("chaincodePath must be null for Node chaincode");
                }

                dplang = "Node";
                ccType = Chaincode.ChaincodeSpec.Type.NODE;
                if (null != chaincodeSource) {

                    projectSourceDir = Paths.get(chaincodeSource.toString()).toFile();
                    targetPathPrefix = "src"; //Paths.get("src", chaincodePath).toString();
                }
                break;
            default:
                throw new IllegalArgumentException("Unexpected chaincode language: " + chaincodeLanguage);
        }

        ccType(ccType);

        final byte[] data;
        String chaincodeID = chaincodeName + "::" + chaincodePath + "::" + chaincodeVersion;

        if (chaincodeSource != null) {
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

            logger.info(format("Installing '%s' language %s chaincode from directory: '%s' with source location: '%s'. chaincodePath:'%s'",
                    chaincodeID, dplang, projectSourceDir.getAbsolutePath(), targetPathPrefix, chaincodePath));

            // generate chaincode source tar
            data = Utils.generateTarGz(projectSourceDir, targetPathPrefix, metainf);

            if (null != diagnosticFileDumper) {

                logger.trace(format("Installing '%s' language %s chaincode from directory: '%s' with source location: '%s'. chaincodePath:'%s' tar file dump %s",
                        chaincodeID, dplang, projectSourceDir.getAbsolutePath(), targetPathPrefix,
                        chaincodePath, diagnosticFileDumper.createDiagnosticTarFile(data)));
            }

        } else {
            logger.info(format("Installing '%s'  %s chaincode chaincodePath:'%s' from input stream",
                    chaincodeID, dplang, chaincodePath));
            data = IOUtils.toByteArray(chaincodeInputStream);

            if (null != diagnosticFileDumper) {
                logger.trace(format("Installing '%s' language %s chaincode from input stream tar file dump %s",
                        chaincodeID, dplang, diagnosticFileDumper.createDiagnosticTarFile(data)));
            }

        }

        final Chaincode.ChaincodeDeploymentSpec depspec = createDeploymentSpec(
                ccType, this.chaincodeName, this.chaincodePath, this.chaincodeVersion, null, data);

        // set args
        final List<ByteString> argList = new ArrayList<>();
        argList.add(ByteString.copyFrom(action, StandardCharsets.UTF_8));
        argList.add(depspec.toByteString());
        args(argList);

    }

    public void setChaincodeLanguage(TransactionRequest.Type chaincodeLanguage) {
        this.chaincodeLanguage = chaincodeLanguage;
    }

    public void chaincodeVersion(String chaincodeVersion) {
        this.chaincodeVersion = chaincodeVersion;
    }

    public void setChaincodeInputStream(InputStream chaincodeInputStream) {
        this.chaincodeInputStream = chaincodeInputStream;

    }
}