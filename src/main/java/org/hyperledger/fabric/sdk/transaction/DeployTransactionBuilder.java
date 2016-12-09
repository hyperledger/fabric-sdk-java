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

import java.io.File;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.ChaincodeLanguage;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.protos.peer.Chaincode;

import com.google.common.io.Files;

import io.netty.util.internal.StringUtil;

public class DeployTransactionBuilder extends TransactionBuilder {

	private Log logger = LogFactory.getLog(TransactionBuilder.class);

	private DeployTransactionBuilder() {}

	public static DeployTransactionBuilder newBuilder() {
		return new DeployTransactionBuilder();
	}

	@Override
	public Transaction build() {
		if (chain == null || request == null) {
			throw new IllegalArgumentException("Must provide request and chain before attempting to call build()");
		}

		try {
			return chain.isDevMode()? createDevModeTransaction(): createNetModeTransaction();
		} catch(IOException exp) {
			throw new DeploymentException("IO Error while creating deploy transaction", exp);
		}
	}

	private Transaction createDevModeTransaction() {
		logger.debug("newDevModeTransaction");

		// Verify that chaincodeName is being passed
		if (StringUtil.isNullOrEmpty(request.getChaincodeName())) {
			throw new RuntimeException("[DevMode] Missing chaincodeName in DeployRequest");
		}

		//TODO  create transaction
//		Fabric.Proposal tx = createTransactionBuilder(
//				request.getChaincodeLanguage() == ChaincodeLanguage.GO_LANG ? Chaincode.ChaincodeSpec.Type.GOLANG
//						: Chaincode.ChaincodeSpec.Type.JAVA,
//				Fabric.Transaction.Type.CHAINCODE_DEPLOY, request.getChaincodeName(), request.getArgs(), null,
//				request.getChaincodeName(), request.getChaincodePath()).build();
//
//		return new Transaction(tx, request.getChaincodeName());
		return null; //TODO implement
	}

	private Transaction createNetModeTransaction() throws IOException {
		logger.debug("newNetModeTransaction");

		// Verify that chaincodePath is being passed
		if (StringUtil.isNullOrEmpty(request.getChaincodePath())) {
			throw new IllegalArgumentException("[NetMode] Missing chaincodePath in DeployRequest");
		}

		String rootDir = "";
		String chaincodeDir = "";

		Chaincode.ChaincodeSpec.Type ccType = Chaincode.ChaincodeSpec.Type.GOLANG;

		if (request.getChaincodeLanguage() == ChaincodeLanguage.GO_LANG) {
			// Determine the user's $GOPATH
			String goPath = System.getenv("GOPATH");
			logger.info(String.format("Using GOPATH :%s", goPath));
			if (StringUtil.isNullOrEmpty(goPath)) {
				throw new IllegalArgumentException("[NetMode] Missing GOPATH environment variable");
			}

			logger.debug("$GOPATH: " + goPath);

			// Compose the path to the chaincode project directory
			rootDir = SDKUtil.combinePaths(goPath,  "src");
			chaincodeDir = request.getChaincodePath();

		} else {
			ccType = Chaincode.ChaincodeSpec.Type.JAVA;

			// Compose the path to the chaincode project directory
			File ccFile = new File(request.getChaincodePath());
			rootDir = ccFile.getParent();
			chaincodeDir = ccFile.getName();
		}

		String projDir = SDKUtil.combinePaths(rootDir, chaincodeDir);
		logger.debug("projDir: " + projDir);

		String dockerFileContents = getDockerFileContents(request.getChaincodeLanguage());

		// Compute the hash of the chaincode deployment parameters
		String hash = SDKUtil.generateParameterHash(chaincodeDir, request.getFcn(), request.getArgs());

		// Compute the hash of the project directory contents
		hash = SDKUtil.generateDirectoryHash(rootDir, chaincodeDir, hash);
		logger.debug("hash: " + hash);

		// Substitute the hashStrHash for the image name
		dockerFileContents = String.format(dockerFileContents, hash);

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

		//TODO create transaction
//		Fabric.Transaction tx = createTransactionBuilder(ccType,
//				Fabric.Transaction.Type.CHAINCODE_DEPLOY, hash, request.getArgs(), data, SDKUtil.generateUUID(), null)
//				.build();
//
//		return new Transaction(tx, hash);
		return null; //TODO implement
	}

	private String getDockerFileContents(ChaincodeLanguage lang) throws IOException {
		if (request.getChaincodeLanguage() == ChaincodeLanguage.GO_LANG) {
			return new String(SDKUtil.readFileFromClasspath("Go.Docker"));
		} else if (request.getChaincodeLanguage() == ChaincodeLanguage.JAVA) {
			return new String(SDKUtil.readFileFromClasspath("Java.Docker"));
		}

		throw new UnsupportedOperationException(String.format("Unknown chaincode language: %s", lang));
	}
}
