/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdk.transaction;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.lifecycle.Lifecycle;
import org.hyperledger.fabric.sdk.TransactionRequest;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.DiagnosticFileDumper;

public class LifecycleInstallProposalBuilder extends LifecycleProposalBuilder {

    private static final Log logger = LogFactory.getLog(LifecycleInstallProposalBuilder.class);
    private static final boolean IS_TRACE_LEVEL = logger.isTraceEnabled();

    private static final Config config = Config.getConfig();
    private static final DiagnosticFileDumper diagnosticFileDumper = IS_TRACE_LEVEL
            ? config.getDiagnosticFileDumper() : null;

    private String chaincodePath;

    private File chaincodeSource;

    private TransactionRequest.Type chaincodeLanguage;
    protected String action = "InstallChaincode";
    private InputStream chaincodeInputStream;
    private File chaincodeMetaInfLocation;
    private byte[] chaincodeBytes;

    protected LifecycleInstallProposalBuilder() {
        super();
    }

    public static LifecycleInstallProposalBuilder newBuilder() {
        return new LifecycleInstallProposalBuilder();

    }

    public LifecycleInstallProposalBuilder chaincodePath(String chaincodePath) {

        this.chaincodePath = chaincodePath;

        return this;

    }

    public LifecycleInstallProposalBuilder setChaincodeSource(File chaincodeSource) {
        this.chaincodeSource = chaincodeSource;

        return this;
    }

    public LifecycleInstallProposalBuilder setChaincodeBytes(byte[] chaincodeBytes) {
        this.chaincodeBytes = chaincodeBytes;

        return this;
    }

    public LifecycleInstallProposalBuilder setChaincodeMetaInfLocation(File chaincodeMetaInfLocation) {

        this.chaincodeMetaInfLocation = chaincodeMetaInfLocation;
        return this;
    }

    @Override
    public ProposalPackage.Proposal build() throws ProposalException, InvalidArgumentException {

        constructInstallProposal();
        return super.build();
    }

    private void constructInstallProposal() throws ProposalException {
        createNetModeTransaction();
    }

    private void createNetModeTransaction() {
        logger.debug("createNetModeTransaction");

        final List<ByteString> argList = new ArrayList<>();

        Lifecycle.InstallChaincodeArgs installChaincodeArgs = Lifecycle.InstallChaincodeArgs.newBuilder()
                .setChaincodeInstallPackage(ByteString.copyFrom(chaincodeBytes)).build();
        argList.add(ByteString.copyFromUtf8(action));
        argList.add(ByteString.copyFrom(installChaincodeArgs.toByteArray()));
        args(argList);

    }

    public void setChaincodeLanguage(TransactionRequest.Type chaincodeLanguage) {
        this.chaincodeLanguage = chaincodeLanguage;
    }
}